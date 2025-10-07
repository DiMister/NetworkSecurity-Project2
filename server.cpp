// Simple TCP server in C++
// Listens on all interfaces and accepts a single client.
// It echoes back exactly the bytes it receives so the existing
// `client.cpp` will print the server reply as: "Server Replies: <message>".

#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

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

    const int BUF_SIZE = 1024;
    char buf[BUF_SIZE];

    auto recv_one = [&]() -> std::string {
        ssize_t r = recv(client_sock, buf, BUF_SIZE, 0);
        if (r <= 0) return std::string();
        return std::string(buf, buf + r);
    };

    auto send_all = [&](const std::string &msg) -> bool {
        ssize_t tosend = static_cast<ssize_t>(msg.size());
        ssize_t sent = 0;
        while (sent < tosend) {
            ssize_t s = send(client_sock, msg.data() + sent, tosend - sent, 0);
            if (s <= 0) return false;
            sent += s;
        }
        return true;
    };

    // Handshake: expect "hi", reply "hi", then expect "bye", reply "bye"
    std::string req = recv_one();
    if (req.empty()) {
        std::cout << "Server: no data from client\n";
        close(client_sock);
        close(listen_sock);
        return 1;
    }
    std::cout << "Server: received '" << req << "'\n";

    if (!send_all(std::string("hi"))) {
        std::perror("send");
        close(client_sock);
        close(listen_sock);
        return 1;
    }
    std::cout << "Server: sent 'hi'\n";

    req = recv_one();
    if (req.empty()) {
        std::cout << "Server: no second message from client\n";
        close(client_sock);
        close(listen_sock);
        return 1;
    }
    std::cout << "Server: received '" << req << "'\n";

    if (!send_all(std::string("bye"))) {
        std::perror("send");
    } else {
        std::cout << "Server: sent 'bye'\n";
    }

    close(client_sock);
    close(listen_sock);
    return 0;
}