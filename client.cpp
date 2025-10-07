// Simple TCP client rewritten in C++
// Connects to a server (default localhost:8421), sends user input lines, and prints responses.

#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    std::string server_ip = "127.0.0.1";
    uint16_t port = 8421;
    if (argc >= 2) server_ip = argv[1];
    if (argc >= 3) port = static_cast<uint16_t>(std::stoi(argv[2]));

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        std::perror("socket");
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address: " << server_ip << "\n";
        return 1;
    }

    if (connect(sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        std::perror("connect");
        close(sock);
        return 1;
    }

    std::cout << "Connected to " << server_ip << ":" << port << "\n";

    const int BUF_SIZE = 1024;
    char buf[BUF_SIZE];

    auto send_all = [&](const std::string &msg) -> bool {
        ssize_t tosend = static_cast<ssize_t>(msg.size());
        ssize_t sent = 0;
        while (sent < tosend) {
            ssize_t s = send(sock, msg.data() + sent, tosend - sent, 0);
            if (s <= 0) return false;
            sent += s;
        }
        return true;
    };

    auto recv_one = [&]() -> std::string {
        ssize_t r = recv(sock, buf, BUF_SIZE, 0);
        if (r <= 0) return std::string();
        return std::string(buf, buf + r);
    };

    // Simple handshake: client -> "hi", server -> "hi", client -> "bye", server -> "bye"
    std::string msg = "hi";
    std::cout << "Client: sending '" << msg << "'\n";
    if (!send_all(msg)) {
        std::perror("send");
        close(sock);
        return 1;
    }

    std::string reply = recv_one();
    if (reply.empty()) {
        std::cout << "Client: no reply from server\n";
        close(sock);
        return 1;
    }
    std::cout << "Client: received '" << reply << "'\n";

    msg = "bye";
    std::cout << "Client: sending '" << msg << "'\n";
    if (!send_all(msg)) {
        std::perror("send");
        close(sock);
        return 1;
    }

    reply = recv_one();
    if (!reply.empty()) {
        std::cout << "Client: received '" << reply << "'\n";
    }

    close(sock);
    return 0;
}
