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
#include "./Helpers/MathUtils.h"
#include "./Helpers/FastModExp.h"
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

    // Receive encrypted shared secret from server: "ENC_SHARE <c>\n"
    std::string enc_line = recv_line(sock);
    if (enc_line.rfind("ENC_SHARE ", 0) != 0) {
        std::cerr << "Expected ENC_SHARE from server, got '" << enc_line << "'\n";
        close(sock);
        return 1;
    }
    unsigned long long c_tmp = 0ull;
    {
        std::istringstream iss(enc_line.substr(10));
        iss >> c_tmp;
    }
    unsigned int ciph = static_cast<unsigned int>(c_tmp);

    // Decrypt with client's private exponent d: shared = c^d mod n
    unsigned int shared = FastModExp::powmod(ciph, d, n);
    std::cout << "Client: decrypted shared secret = " << shared << std::endl;

    // Tell server we're done and close
    send_all(sock, std::string("BYE\n"));
    close(sock);
    return 0;
}
