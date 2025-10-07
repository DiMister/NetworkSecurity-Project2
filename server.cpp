// Simple TCP server in C++
// Listens on all interfaces and accepts a single client.
// It echoes back exactly the bytes it receives so the existing
// `client.cpp` will print the server reply as: "Server Replies: <message>".

#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <sstream>
#include <random>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "DiffeHellman.h"
#include "net_utils.h"
using namespace std;

// send_all, recv_line and recv_one are provided by net_utils.cpp

int main(int argc, char* argv[]) {
    uint16_t port = 8421;
    if (argc >= 2) port = static_cast<uint16_t>(std::stoi(argv[1]));

    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == -1) {
        std::perror("socket");
        return 1;
    }

    int opt = 1;
    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::perror("setsockopt");
        close(listen_sock);
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(listen_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::perror("bind");
        close(listen_sock);
        return 1;
    }

    if (listen(listen_sock, 1) < 0) {
        std::perror("listen");
        close(listen_sock);
        return 1;
    }

    std::cout << "Server listening on port " << port << " (accepting 1 client)\n";

    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int client_sock = accept(listen_sock, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
    if (client_sock < 0) {
        std::perror("accept");
        close(listen_sock);
        return 1;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    std::cout << "Accepted connection from " << client_ip << ":" << ntohs(client_addr.sin_port) << "\n";

    // New protocol:
    // Client -> "PARAM p g\n"
    // Server -> "ACK\n"
    // Client -> "PUB A\n"
    // Server -> "PUB B\n"
    // Client -> "SHARED s\n" (client's computed shared secret)
    // Server -> "OK\n" (if matches)

    std::string line = recv_line(client_sock);
    if (line.rfind("PARAM ", 0) != 0) {
    std::cout << "Server: expected PARAM, got '" << line << "'\n";
        close(client_sock);
        close(listen_sock);
        return 1;
    }

    // parse p and g
    int p = -1, g = -1;
    try {
        std::istringstream iss(line.substr(6));
        iss >> p >> g;
    } catch (...) {}
    DiffeHellman dh(p, g);
    

    // send ACK
    if (!send_all(client_sock, std::string("ACK\n"))) {
        std::perror("send");
        close(client_sock);
        close(listen_sock);
        return 1;
    }

    // receive PUB A
    line = recv_line(client_sock);
    if (line.rfind("PUB ", 0) != 0) {
        std::cout << "Server: expected PUB, got '" << line << "'\n";
        close(client_sock);
        close(listen_sock);
        return 1;
    }
    int A = std::stoi(line.substr(4));

    // compute B
    vector<int> primes = dh.loadPrimes("./primes.csv");
    int b = dh.pickRandomFrom(primes);
    int B = dh.calculatePublicKey(b);

    // send PUB B
    if (!send_all(client_sock, std::string("PUB ") + std::to_string(B) + "\n") ) {
        std::perror("send");
        close(client_sock);
        close(listen_sock);
        return 1;
    }

    // receive SHARED s
    line = recv_line(client_sock);
    if (line.rfind("SHARED ", 0) != 0) {
        std::cout << "Server: expected SHARED, got '" << line << "'\n";
        close(client_sock);
        close(listen_sock);
        return 1;
    }
    int s_client = std::stoi(line.substr(7));

    int s_server = dh.calculateSharedSecret(A, b);
    if (s_server == s_client) {
        send_all(client_sock, std::string("OK\n"));
        std::cout << "Server: shared secret verified\n";
    } else {
        send_all(client_sock, std::string("ERR\n"));
        std::cout << "Server: shared secret mismatch (client=" << s_client << " server=" << s_server << ")\n";
    }

    // Cleanup
    close(client_sock);
    close(listen_sock);
    return 0;
}
