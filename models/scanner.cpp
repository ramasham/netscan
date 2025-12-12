#include "scanner.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

//the kernel does the handshake, you just call connect()
//1. if the handshake is established:
//The socket state becomes ESTABLISHED
//connect() succeeds, SO_ERROR == 0
//2. if the port is closed:
//Target replies with RST instead of SYN+ACK
//Kernel sees this and sets ECONNREFUSED
//3. if the port if filtered (firewall):
//Maybe no reply at all (packet dropped)
//Kernel waits and then times out
//Your scanner sees no completion within timeoutMs or SO_ERROR == ETIMEDOUT

//convert enum to string
std::string port_state_to_string(PortState state) {
    switch (state) {
        case PortState::OPEN:
            return "OPEN";
        case PortState::CLOSED:
            return "CLOSED";
        case PortState::FILTERED:
            return "FILTERED";
        case PortState::ERROR_STATE:
            return "ERROR";
    }
    return "UNKNOWN";
}

void print_scan_results(const std::vector<Scanner> &scans,
                        int startPort,
                        int endPort)
{
    // ANSI color codes
    const char* RESET   = "\033[0m";
    const char* GREEN   = "\033[32m";
    const char* RED     = "\033[31m";
    const char* YELLOW  = "\033[33m";
    const char* MAGENTA = "\033[35m";

    std::cout << std::left
              << std::setw(8)  << "PORT"
              << std::setw(16) << "STATE"
              << "INFO\n";

    std::cout << "---------------------------------------------------------\n";

    for (const auto &Scanner : scans) {
        if (Scanner.port < startPort || Scanner.port > endPort)
            continue;

        // Pick color
        const char* color = RESET;
        switch (Scanner.state) {
            case PortState::OPEN:        color = GREEN;   break;
            case PortState::CLOSED:      color = RED;     break;
            case PortState::FILTERED:    color = YELLOW;  break;
            case PortState::ERROR_STATE: color = MAGENTA; break;
        }

        // Convert state to string
        std::string stateStr = port_state_to_string(Scanner.state);

        // Prepare INFO field
        std::string info = Scanner.msg;
        if (!Scanner.banner.empty())
            info += " banner: \"" + Scanner.banner + "\"";

        // Print aligned line
        std::cout << std::left
                  << std::setw(8)  << Scanner.port                      // no /tcp
                  << std::setw(16) << (std::string(color) + stateStr + RESET)
                  << info << "\n";
    }

    std::cout << "\n[*] Scan complete.\n";
}


// Small helper: sanitize banner to a single printable line
static std::string sanitize_banner(const char* buf, int len) {
    std::string out;
    out.reserve(len);

    for (int i = 0; i < len; ++i) {
        unsigned char c = static_cast<unsigned char>(buf[i]);
        if (c == '\r' || c == '\n')
            break;
        if (c >= 32 && c <= 126)
            out.push_back(static_cast<char>(c));
        else
            out.push_back('.');
    }
    return out;
}

void run_scanner(const std::string &targetIp, int startPort, int endPort, int timeoutMs) {
   //validate port range
   //why 1 -> 65535?
   //TCP port number is 16-bit unsigned int
   //2^16 = 65536
   //port zero is reserved 
    if (startPort < 1 || endPort > 65535 || startPort > endPort) {
        std::cerr << "\033[35mInvalid port range! \n";
        return;
    }

    std::cout << "\033[36mAsync TCP connect scanner\033[0m\n";
    std::cout << "\033[35mTarget: " << targetIp
              << " Ports: " << startPort << "-" << endPort
              << " Timeout: " << timeoutMs << " ms\033[0m\n\n";

    // Prepare target address (IP only, port set per socket)
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, targetIp.c_str(), &addr.sin_addr) <= 0) {
        std::cerr << "failed for IP " << targetIp << "\n";
        return;
    }

    // Create epoll instance
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        std::cerr << "failed: " << std::strerror(errno) << "\n";
        return;
    }

    std::vector<Scanner> scans;
    scans.reserve(endPort - startPort + 1);

    // Create one non-blocking socket per port and start connect()
    for (int port = startPort; port <= endPort; ++port) {
        int sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (sockfd < 0) {
            std::cerr << "failed for port " << port
                      << ": " << std::strerror(errno) << "\n";
            continue;
        }

        addr.sin_port = htons(static_cast<uint16_t>(port));

        int res = connect(sockfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        if (res < 0 && errno != EINPROGRESS) {
            // Immediate failure
            Scanner Scanner{};
            Scanner.sockfd = sockfd;
            Scanner.port = port;
            Scanner.completed = true;
            Scanner.state = (errno == ECONNREFUSED) ? PortState::CLOSED
                                                : PortState::ERROR_STATE;
            Scanner.msg = std::string("failed: ") + std::strerror(errno);
            close(sockfd);
            scans.push_back(Scanner);
            continue;
        }

        // Register socket with epoll to wait for connection result
        epoll_event ev{};
        ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
        ev.data.fd = sockfd;

        if (epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev) < 0) {
            std::cerr << "failed for port " << port
                      << ": " << std::strerror(errno) << "\n";
            close(sockfd);
            continue;
        }

        Scanner Scanner{};
        Scanner.sockfd = sockfd;
        Scanner.port = port;
        Scanner.completed = false;
        Scanner.state = PortState::ERROR_STATE;
        scans.push_back(Scanner);
    }

    int remaining = 0;
    for (const auto &s : scans)
        if (!s.completed) remaining++;

    const int MAX_EVENTS = 256;
    std::vector<epoll_event> events(MAX_EVENTS);

    // Main epoll loop
    while (remaining > 0) {
        int n = epoll_wait(epfd, events.data(), MAX_EVENTS, timeoutMs);
        if (n < 0) {
            std::cerr << "failed: " << std::strerror(errno) << "\n";
            break;
        }

        if (n == 0) {
            // Global timeout: mark all still-pending as FILTERED
            for (auto &Scanner : scans) {
                if (!Scanner.completed) {
                    Scanner.completed = true;
                    Scanner.state = PortState::FILTERED;
                    Scanner.msg = "timeout (no response)";
                    close(Scanner.sockfd);
                    remaining--;
                }
            }
            break;
        }

        for (int i = 0; i < n; ++i) {
            int sockfd = events[i].data.fd;

            // Find corresponding Scanner
            Scanner *ScannerPtr = nullptr;
            for (auto &s : scans) {
                if (s.sockfd == sockfd) {
                    ScannerPtr = &s;
                    break;
                }
            }
            if (!ScannerPtr || ScannerPtr->completed)
                continue;

            Scanner &Scanner = *ScannerPtr;

            int err = 0;
            socklen_t len = sizeof(err);
            if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
                Scanner.state = PortState::ERROR_STATE;
                Scanner.msg = std::string("failed: ") + std::strerror(errno);
            } else if (err == 0) {
                // Connection successful -> OPEN
                Scanner.state = PortState::OPEN;
                Scanner.msg = "connection succeeded";

                // Try to grab a small banner (non-blocking recv)
                char buf[256];
                int nbytes = recv(sockfd, buf, sizeof(buf) - 1, MSG_DONTWAIT);
                if (nbytes > 0) {
                    buf[nbytes] = '\0';
                    Scanner.banner = sanitize_banner(buf, nbytes);
                }
            } else if (err == ECONNREFUSED) {
                Scanner.state = PortState::CLOSED;
                Scanner.msg = "connection refused";
            } else if (err == ETIMEDOUT) {
                Scanner.state = PortState::FILTERED;
                Scanner.msg = "connection timed out";
            } else {
                Scanner.state = PortState::FILTERED;
                Scanner.msg = std::string("error: ") + std::strerror(err);
            }

            Scanner.completed = true;
            remaining--;
            close(sockfd);
        }
    }
    close(epfd);
    print_scan_results(scans, startPort, endPort);

}