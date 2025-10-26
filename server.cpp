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
#include "./Helpers/net_utils.h"
#include "./Helpers/FastModExp.h"
#include "./Helpers/MathUtils.h"
#include "./Helpers/SDESModes.h"
#include <thread>
#include <sstream>
#include <iomanip>

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

    // Expect client's RSA public key: "RSA_PUB <n> <e>\n"
    std::string line = recv_line(client_sock);
    if (line.rfind("RSA_PUB ", 0) != 0) {
        std::cerr << "Server: expected RSA_PUB, got '" << line << "'\n";
        close(client_sock);
        close(listen_sock);
        return 1;
    }

    unsigned long long client_n_tmp = 0ull;
    uuint32_t client_e = 0u;
    {
        std::istringstream iss(line.substr(8));
        iss >> client_n_tmp >> client_e;
    }
    uint32_t client_n = static_cast<uint32_t>(client_n_tmp);
    std::cout << "Server: received client RSA public n=" << client_n << " e=" << client_e << "\n";

    if (client_n == 0u) {
        std::cerr << "Server: invalid client modulus\n";
        close(client_sock);
        close(listen_sock);
        return 1;
    }

    // Generate a small random shared secret using MathUtils (demo only)
    MathUtils mathUtils;
    std::vector<int> primes = mathUtils.loadPrimes("./primes.csv");
    uint32_t shared = 0u;
    int picked = mathUtils.pickRandomFrom(primes);
    if (picked < 0) picked = 1;
    // Ensure shared is in range [1, client_n-1]
    if (client_n > 1u) {
        shared = static_cast<uint32_t>(picked) % (client_n - 1u) + 1u;
    } else {
        shared = static_cast<uint32_t>(picked);
    }
    std::cout << "Server: generated shared secret from primes (picked=" << picked << ") -> plain=" << shared << "\n";
    
    // Encrypt shared with client's RSA pub: c = shared^e mod n
    uint32_t m = shared % client_n;
    uint32_t ciph = FastModExp::powmod(m, client_e, client_n);
    std::string enc_line = "ENC_SHARE " + std::to_string(ciph) + "\n";
    if (!send_all(client_sock, enc_line)) {
        std::perror("send");
        close(client_sock);
        close(listen_sock);
        return 1;
    }
    std::cout << "Server: sent ENC_SHARE " << ciph << "\n";

    // Derive a 10-bit SDES key from the shared secret 
    int s = static_cast<int>(shared);
    uint16_t key10 = static_cast<uint16_t>(s % 1024);
    std::bitset<10> sdes_key(key10);
    SDESModes sdes(sdes_key);

    // Helper: hex -> bytes (same format used by client)
    auto hex_to_bytes = [](const std::string &hex) {
        std::vector<unsigned char> out;
        if (hex.size() % 2 != 0) return out;
        for (size_t i = 0; i < hex.size(); i += 2) {
            std::string byteStr = hex.substr(i, 2);
            uint32_t byte;
            std::stringstream ss;
            ss << std::hex << byteStr;
            ss >> byte;
            out.push_back(static_cast<unsigned char>(byte));
        }
        return out;
    };

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

    // Wait for BYE or EOF, then cleanup
    while (true) {
        std::string line = recv_line(client_sock);
        if (line.empty()) break;
        if (line.rfind("MSG ", 0) == 0) {
            std::string hex = line.substr(4);
            // Log the encrypted message received (hex)
            std::cout << "Encrypted (hex) received: " << hex << std::endl;

            auto bytes = hex_to_bytes(hex);

            // Convert bytes -> vector<bitset<8>> expected by SDESModes
            std::vector<std::bitset<8>> cipher_bits;
            for (unsigned char b : bytes) cipher_bits.emplace_back(static_cast<unsigned long>(b));

            auto plain_bits = sdes.decrypt(cipher_bits, EncryptionMode::CBC, cbc_iv);
            std::string plain;
            for (const auto &pt : plain_bits) {
                plain.push_back(static_cast<char>(pt.to_ulong()));
            }
            // Log the decrypted keyboard input
            std::cout << "Decrypted keyboard input: '" << plain << "'" << std::endl;
        } else if (line == "BYE") {
            std::cout << "Client closed connection" << std::endl;
            break;
        }
    }

    close(client_sock);
    close(listen_sock);
    return 0;

    
}
