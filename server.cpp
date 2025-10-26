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
#include "./Helpers/DiffeHellman.h"
#include "./Helpers/net_utils.h"
#include "./Helpers/SDESModes.h"
#include <thread>
#include <sstream>
#include <iomanip>
#include <atomic>

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

    if (::bind(listen_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
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
    std::cout << "Server: received parameters p=" << p << " g=" << g << "\n";
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
    std::cout << "Server: received public A=" << A << "\n";

    // compute B
    MathUtils mathUtils;
    std::vector<int> primes = mathUtils.loadPrimes("./primes.csv");
    int b = mathUtils.pickRandomFrom(primes);
    std::cout << "Server: generated private b=" << b << "\n";
    int B = dh.calculatePublicKey(b);
    std::cout << "Server: computed public B=" << B << "\n";

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
        std::cout << "Server: shared secret verified (s=" << s_server << ")\n";
    } else {
        send_all(client_sock, std::string("ERR\n"));
        std::cout << "Server: shared secret mismatch (client=" << s_client << " server=" << s_server << ")\n";
    }

    // Receive IV
    line = recv_line(client_sock);
    if (line.rfind("IV ", 0) != 0) {
        std::cout << "Server: expected IV, got '" << line << "'\n";
        close(client_sock);
        close(listen_sock);
        return 1;
    }
    std::bitset<8> cbc_iv(static_cast<uint8_t>(std::stoi(line.substr(3))));
    std::cout << "Received 8-bit IV for CBC: " << cbc_iv << "\n";

    // Derive SDES 10-bit key from shared secret
    int s = s_server;
    uint16_t key10 = static_cast<uint16_t>(s % 1024);
    std::bitset<10> sdes_key(key10);
    SDESModes sdes(sdes_key);

    auto hex_to_bytes = [](const std::string &hex) {
        std::vector<unsigned char> out;
        if (hex.size() % 2 != 0) return out;
        for (size_t i = 0; i < hex.size(); i += 2) {
            std::string byteStr = hex.substr(i, 2);
            unsigned int byte;
            std::stringstream ss;
            ss << std::hex << byteStr;
            ss >> byte;
            out.push_back(static_cast<unsigned char>(byte));
        }
        return out;
    };

    auto bytes_to_hex = [](const std::vector<unsigned char>& bytes) {
        std::ostringstream oss;
        for (unsigned char b : bytes) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        return oss.str();
    };

    // Receive loop: decrypt incoming MSG <hex> lines and print
    while (true) {
        std::string line = recv_line(client_sock);
        if (line.empty()) break;
        if (line.rfind("MSG ", 0) == 0) {
            std::string hex = line.substr(4);
            // Log the encrypted message received (hex)
            std::cout << "Encrypted (hex) received: " << hex << std::endl;

            auto bytes = hex_to_bytes(hex);

            auto plain_bytes =sdes.decrypt(bytes, EncryptionMode::CBC, cbc_iv);
            std::string plain;
            plain.reserve(bytes.size());
            for (unsigned char b : plain_bytes) {
                std::bitset<8> pt(b);
                plain.push_back(static_cast<char>(pt.to_ulong()));
            }
            // Log the decrypted keyboard input
            std::cout << "Decrypted keyboard input: '" << plain << "'" << std::endl;
        } else if (line == "BYE") {
            std::cout << "Client closed connection" << std::endl;
            break;
        }
    }

    // Cleanup
    close(client_sock);
    close(listen_sock);
    return 0;
}
