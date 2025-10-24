#pragma once

#include <vector>
#include <string>

class MathUtils {
public:
    // Load primes from a CSV file that has one prime per line (optional header)
    std::vector<int> loadPrimes(const std::string &path) const;

    // Pick a random element from a vector; returns -1 if empty
    int pickRandomFrom(const std::vector<int>& v) const;

    // Find a generator for modulus p
    int findGenerator(int p) const;

private:
    // Check if g is a valid generator for modulus p
    bool isGenerator(int g, int p) const;
};