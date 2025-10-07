// Diffie-Hellman client

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
#include "DiffeHellman.h"
#include "net_utils.h"

using namespace std;

// using send_all and recv_line from net_utils.h

int main(int argc, char* argv[]) {
    string server_ip = "127.0.0.1";
    uint16_t port = 8421;
    if (argc >= 2) server_ip = argv[1];
    if (argc >= 3) port = static_cast<uint16_t>(stoi(argv[2]));

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("socket");
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        cerr << "Invalid address: " << server_ip << "\n";
        close(sock);
        return 1;
    }

    if (connect(sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }

    cout << "Connected to " << server_ip << ":" << port << "\n";

    // Use small demo params; you can change or load from file
    int p = 23;
    int g = 5;
    DiffeHellman dh(p, g);

    // Send parameters to server
    string params = "PARAM " + to_string(p) + " " + to_string(g) + "\n";
    if (!send_all(sock, params)) { perror("send"); close(sock); return 1; }

    string reply = recv_line(sock);
    if (reply != "ACK") { cerr << "Expected ACK, got '" << reply << "'\n"; close(sock); return 1; }

    // Generate client's private and public
    vector<int> primes = dh.loadPrimes("./primes.csv");
    int a = dh.pickRandomFrom(primes);
    int A = dh.calculatePublicKey(a);

    // Send public A
    string msg = "PUB " + to_string(A) + "\n";
    if (!send_all(sock, msg)) { perror("send"); close(sock); return 1; }

    // Receive server public B
    string line = recv_line(sock);
    if (line.rfind("PUB ", 0) != 0) { cerr << "Expected PUB from server, got '" << line << "'\n"; close(sock); return 1; }
    int B = stoi(line.substr(4));

    int s_client = dh.calculateSharedSecret(B, a);
    cout << "Client: computed shared secret = " << s_client << "\n";

    // Send shared secret for verification (not secure, demo only)
    string shared_msg = "SHARED " + to_string(s_client) + "\n";
    if (!send_all(sock, shared_msg)) { perror("send"); close(sock); return 1; }

    string ok = recv_line(sock);
    if (ok == "OK") cout << "Client: server acknowledged shared secret\n";

    // Cleanup
    close(sock);
    return 0;
}
