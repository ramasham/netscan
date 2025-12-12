#include <string>
#include <vector>

enum class PortState {
    OPEN,
    CLOSED,
    FILTERED,
    ERROR_STATE
};

struct ScanResult {
    int port;
    PortState state;
    std::string msg;
    std::string banner;
};

struct Scanner {
    int sockfd;
    int port;
    bool completed;
    PortState state;
    std::string msg;
    std::string banner;
};


// Runs a simple blocking scanner from startPort to endPort
void run_scanner(const std::string &targetIp, int startPort, int endport, int timeoutMs);

// Converts PortState → readable text
std::string port_state_to_string(PortState state);
void print_scan_results(const std::vector<Scanner> &scans, int startPort, int endPort);