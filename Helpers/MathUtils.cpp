#include "MathUtils.h"
#include <fstream>
#include <string>
#include <cctype>
#include <random>
#include <set>
using namespace std;

vector<int> MathUtils::loadPrimes(const string &path) const {
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

int MathUtils::pickRandomFrom(const vector<int>& v) const {
    if (v.empty()) return -1;
    static random_device rd;
    static mt19937 gen(rd());
    uniform_int_distribution<size_t> dist(0, v.size() - 1);
    return v[dist(gen)];
}

int MathUtils::findGenerator(int p) const {
    for (int candidate = 2; candidate < p; candidate++) {
        if (isGenerator(candidate, p)) {
            return candidate;
        }
    }
    return -1; // No generator found
}

bool MathUtils::isGenerator(int g, int p) const {
    set<int> seen;
    int current = 1;
    for (int i = 1; i < p; i++) {
        current = (current * g) % p;
        if (seen.count(current)) return false;  // Early cycle
        seen.insert(current);
    }
    return seen.size() == p - 1;
}