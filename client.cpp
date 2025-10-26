#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <random>
#include "./Helpers/net_utils.h"
#include "./Helpers/SDES.h"
#include <sstream>
#include <iomanip>
#include <cstdint>

int main(int argc, char* argv[]) {
    std::string server_ip = "127.0.0.1";
    uint16_t port = 8421;
    if (argc >= 2) server_ip = argv[1];
    if (argc >= 3) port = static_cast<uint16_t>(std::stoi(argv[2]));

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("socket");
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address: " << server_ip << "\n";
        close(sock);
        return 1;
    }

    if (connect(sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }

    std::cout << "Connected to " << server_ip << ":" << port << "\n";

    MathUtils mathUtils;
    std::vector<int> primes = mathUtils.loadPrimes("./primes.csv");

    if (primes.size() < 2) {
        std::cerr << "Not enough primes in primes.csv\n";
        close(sock);
        return 1;
    }

    // Generate RSA keypair for client (small primes from CSV)
    unsigned int p_rsa = static_cast<unsigned int>(mathUtils.pickRandomFrom(primes));
    unsigned int q_rsa = static_cast<unsigned int>(mathUtils.pickRandomFrom(primes));
    while (q_rsa == p_rsa) q_rsa = static_cast<unsigned int>(mathUtils.pickRandomFrom(primes));

    unsigned long long n_tmp = static_cast<unsigned long long>(p_rsa) * static_cast<unsigned long long>(q_rsa);
    unsigned int n = static_cast<unsigned int>(n_tmp);
    unsigned int totient = (p_rsa - 1u) * (q_rsa - 1u);

    unsigned int e = mathUtils.findPublicExponent(totient);
    if (e == 0u) {
        e = 65537u;
        if (mathUtils.findGCD(e, totient) != 1u) {
            std::cerr << "Failed to find suitable public exponent\n";
            close(sock);
            return 1;
        }
    }

    unsigned int d = mathUtils.extendedEuclidean(e, totient);

    // Send our public key to server: RSA_PUB <n> <e>\n
    std::string publine = "RSA_PUB " + std::to_string(n) + " " + std::to_string(e) + "\n";
    if (!send_all(sock, publine)) { perror("send"); close(sock); return 1; }

    std::string ok = recv_line(sock);
    if (ok == "OK") std::cout << "Client: server acknowledged shared secret\n";

    // Derive 10-bit SDES key from shared secret (simple: take s mod 1024)
    int s = s_client;
    uint16_t key10 = static_cast<uint16_t>(s % 1024);
    std::bitset<10> sdes_key(key10);
    SDES sdes(sdes_key);

    // Helper lambdas for hex encoding/decoding
    auto bytes_to_hex = [](const std::vector<unsigned char>& bytes) {
        std::ostringstream oss;
        for (unsigned char b : bytes) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        return oss.str();
    };

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

    // Sender loop: read stdin lines, encrypt and send as MSG <hex>\n
    std::string input;
    while (std::getline(std::cin, input)) {
        if (input == "/quit") {
            send_all(sock, std::string("BYE\n"));
            break;
        }
        std::vector<unsigned char> cipher_bytes;
        cipher_bytes.reserve(input.size());
        // Log the keyboard input we're about to send
        std::cout << "Keyboard input: '" << input << "'\n";

        for (char c : input) {
            std::bitset<8> pt = sdes.charToBinary(c);
            std::bitset<8> ct = sdes.encrypt(pt);
            cipher_bytes.push_back(static_cast<unsigned char>(ct.to_ulong()));
        }
        std::string hex = bytes_to_hex(cipher_bytes);
        // Log the encrypted message we're sending (hex)
        std::cout << "Encrypted (hex) sent: " << hex << std::endl;

        std::string out = std::string("MSG ") + hex + "\n";
        if (!send_all(sock, out)) break;
    }

    // Close and exit
    close(sock);
    return 0;
}
