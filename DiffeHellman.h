#pragma once

#include <vector>
#include <string>

class DiffeHellman {
public:
    // constructor sets modulus (p) and generator (g)
    DiffeHellman(int modulus = 23, int generator = 5);

    // Load primes from a CSV file that has one prime per line (optional header)
    std::vector<int> loadPrimes(const std::string &path) const;

    // Pick a random element from a vector; returns -1 if empty
    int pickRandomFrom(const std::vector<int>& v) const;

    // Compute public key from private key: g^private mod p
    int calculatePublicKey(int privateKey) const;

    // Compute shared secret: otherPublic^private mod p
    int calculateSharedSecret(int otherPublicKey, int privateKey) const;

    int getModulus() const;
    int getGenerator() const;

private:
    int p;
    int g;
};
