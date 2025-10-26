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
#include "./Helpers/SDESModes.h"
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
    // Parse the numeric ciphertext after the prefix "ENC_SHARE ".
    // Use std::stoul to convert directly from substring to unsigned long, then cast.
    unsigned int ciph = 0u;
    try {
        ciph = static_cast<unsigned int>(std::stoul(enc_line.substr(10)));
    } catch (const std::exception &e) {
        std::cerr << "Failed to parse ENC_SHARE value: " << e.what() << "\n";
        close(sock);
        return 1;
    }

    // Decrypt with client's private exponent d: shared = c^d mod n
    unsigned int shared = FastModExp::powmod(ciph, d, n);
    std::cout << "Client: decrypted shared secret = " << shared << std::endl;

    // Generate a random 8-bit IV for CBC mode
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    uint8_t iv = static_cast<uint8_t>(dist(gen));
    std::bitset<8> cbc_iv(iv);
    std::cout << "Generated 8-bit IV for CBC: " << cbc_iv << "\n";

    if (!send_all(sock, std::string("IV ") + std::to_string(cbc_iv.to_ulong()) + "\n")) {
        perror("send");
        close(sock);
        return 1;
    }

    // Derive 10-bit SDES key from shared secret (simple: take s mod 1024)
    int s = static_cast<int>(shared);
    uint16_t key10 = static_cast<uint16_t>(s % 1024);
    std::bitset<10> sdes_key(key10);
    SDESModes sdes(sdes_key);

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
        // Log the keyboard input we're about to send
        std::cout << "Keyboard input: '" << input << "'\n";

        std::vector<std::bitset<8>> plaintext_bits;
        for (char c : input) {
            std::bitset<8> pt(static_cast<unsigned char>(c));
            plaintext_bits.push_back(pt);
        }
        auto cipher_bits = sdes.encrypt(plaintext_bits, EncryptionMode::CBC, cbc_iv);
        // convert bitsets to bytes
        std::vector<unsigned char> cipher_bytes;
        cipher_bytes.reserve(cipher_bits.size());
        for (const auto &b : cipher_bits) cipher_bytes.push_back(static_cast<unsigned char>(b.to_ulong()));
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
