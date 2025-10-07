
#include "DiffeHellman.h"
#include "FastModExp.h"
#include <fstream>
#include <string>
#include <cctype>
#include <random>
using namespace std;

// Implementation of DiffeHellman
DiffeHellman::DiffeHellman(int modulus, int generator)
    : p(modulus), g(generator) {}

vector<int> DiffeHellman::loadPrimes(const string &path) const {
    vector<int> primes;
    ifstream in(path);
    if (!in) return primes;
    string line;
    while (getline(in, line)) {
        if (line.empty()) continue;
        if (line == "prime" || line == "Prime") continue;
        size_t a = line.find_first_not_of(" \t\r\n");
        size_t b = line.find_last_not_of(" \t\r\n");
        if (a == string::npos) continue;
        string token = line.substr(a, b - a + 1);
        try {
            int v = stoi(token);
            primes.push_back(v);
        } catch (...) {
            // skip invalid lines
        }
    }
    return primes;
}

int DiffeHellman::pickRandomFrom(const vector<int>& v) const {
    if (v.empty()) return -1;
    static random_device rd;
    static mt19937 gen(rd());
    uniform_int_distribution<size_t> dist(0, v.size() - 1);
    return v[dist(gen)];
}

int DiffeHellman::calculatePublicKey(int privateKey) const {
    return FastModExp::powmod(g, privateKey, p);
}

int DiffeHellman::calculateSharedSecret(int otherPublicKey, int privateKey) const {
    return FastModExp::powmod(otherPublicKey, privateKey, p);
}

int DiffeHellman::getModulus() const { return p; }
int DiffeHellman::getGenerator() const { return g; }