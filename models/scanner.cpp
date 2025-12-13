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
#include <netdb.h> 

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

// Get service name using system database (/etc/services)
std::string port_to_service(int port) {
    servent *s = getservbyport(htons(port), "tcp");
    if (s && s->s_name)
        return s->s_name;
    return "UNKNOWN";
}

void print_scan_results(const std::vector<Scanner> &scans,
                        int startPort, int endPort)
{
    const char* RESET   = "\033[0m";
    const char* GREEN   = "\033[32m";
    const char* RED     = "\033[31m";
    const char* YELLOW  = "\033[33m";
    const char* MAGENTA = "\033[35m";

    std::cout << std::left
              << std::setw(8)  << "PORT"
              << std::setw(11) << "STATE"
              << std::setw(15) << "SERVICE"
              << "INFO\n";

    std::cout << "---------------------------------------------------------------\n";

    for (const auto &Scanner : scans) {
        if (Scanner.port < startPort || Scanner.port > endPort)
            continue;

        // STATE color
        const char* stateColor = RESET;
        const char* infoColor  = RESET;

        if (Scanner.state == PortState::OPEN) {
            stateColor = GREEN;
            infoColor  = GREEN;
        }
        else if (Scanner.state == PortState::CLOSED) {
            stateColor = MAGENTA;
            infoColor  = MAGENTA;
        }
        else if (Scanner.state == PortState::FILTERED) {
            stateColor = YELLOW;
            infoColor  = YELLOW;
        }
        else if (Scanner.state == PortState::ERROR_STATE) {
            stateColor = RED;
            infoColor  = RED;
        }

        std::string stateStr = port_state_to_string(Scanner.state);
        std::string service  = port_to_service(Scanner.port);

        std::cout << std::left
                  << std::setw(8)  << Scanner.port
                  << std::setw(21) << (std::string(stateColor) + stateStr + RESET)
                  << std::setw(15) << service
                  << infoColor << Scanner.msg << RESET
                  << "\n";
    }

    std::cout << "\n\033[36mScan complete ✔️\033[0m\n";
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
    std::cout << "\033[36mTarget: " << targetIp
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

    //Create the list of scan entries
    //hold one Scanner struct per port.
    std::vector<Scanner> scans;
    //Pre-allocates memory for the expected number of ports.
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

        //starts TCP handshake to that IP + Port
        int res = connect(sockfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        //res < 0 → connect didn’t finish instantly
        //errno != EINPROGRESS → and it’s NOT the “still connecting” case
        //So the connection failed right away (final failure).
        if (res < 0 && errno != EINPROGRESS) {
            Scanner Scanner{};
            Scanner.sockfd = sockfd;
            Scanner.port = port;
            Scanner.completed = true;
            //ECONNREFUSED means target actively rejected it (RST) → CLOSED
            if (errno == ECONNREFUSED)
                Scanner.state = PortState::CLOSED;
            else
                Scanner.state = PortState::ERROR_STATE;
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
        Scanner.sockfd = sockfd; //Store which socket belongs to this scan record.
        Scanner.port = port; //Store which port we are scanning.
        Scanner.completed = false; //Temporary default state
        Scanner.state = PortState::ERROR_STATE;
        scans.push_back(Scanner);
    }

    int remaining = 0;
    for (const auto &s : scans)
        if (!s.completed) remaining++;

    //Maximum number of events you want epoll to return per call.
    const int MAX_EVENTS = 256;
    //Allocate an array (vector) where epoll_wait will write event results.
    std::vector<epoll_event> events(MAX_EVENTS);

    while (remaining > 0) {
        //“Sleep until any of these events happens on any of those sockets, then give me the list.”
        //Each events[i] describes one socket that became ready
        int n = epoll_wait(epfd, events.data(), MAX_EVENTS, timeoutMs);
        if (n < 0) {
            std::cerr << "failed: " << std::strerror(errno) << "\n";
            break;
        }
        //If epoll timed out: mark remaining as FILTERED
        if (n == 0) {
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

        //Process each ready socket event
        //“Get the socket file descriptor that became ready.”
        for (int i = 0; i < n; ++i) {
            int sockfd = events[i].data.fd;

            //“Find the scan record (Scanner) that belongs to this socket.”
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
            //Linux stores the final result of a non-blocking
            //connect in a special socket option called SO_ERROR
            if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
                Scanner.state = PortState::ERROR_STATE;
                Scanner.msg = std::string("failed: ") + std::strerror(errno);
            //The socket is now ESTABLISHED
            }
            else if (err == 0) {
                Scanner.state = PortState::OPEN;
                Scanner.msg = "connection succeeded";
            }
            //You sent SYN
            //Target replied with RST
            else if (err == ECONNREFUSED) {
                Scanner.state = PortState::CLOSED;
                Scanner.msg = "connection refused";
            }
            //You sent SYN
            //No SYN-ACK
            //No RST
            //Kernel waited and gave up
            //"Firewall dropped packets"
            else if (err == ETIMEDOUT) {
                Scanner.state = PortState::FILTERED;
                Scanner.msg = "connection timed out";
            }
            //any other error → FILTERED
            else {
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