
#include <iostream>
#include <random>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <cstdint>
#include "FastModExp.h"
using namespace std;

int p = 23;   // prime modulus
int g = 5;    // generator

// Load primes from a CSV file that has one prime per line (optional header)
static vector<int> load_primes(const string &path) {
    vector<int> primes;
    ifstream in(path);
    if (!in) return primes;
    string line;
    while (getline(in, line)) {
        if (line.empty()) continue;
        // Skip header
        if (line == "prime" || line == "Prime") continue;
        // Trim whitespace
        size_t a = line.find_first_not_of(" \t\r\n");
        size_t b = line.find_last_not_of(" \t\r\n");
        if (a == string::npos) continue;
        string token = line.substr(a, b - a + 1);
        try {
            int v = stoi(token); // convert string to int
            primes.push_back(v);
        } catch (...) {
            // skip invalid lines
        }
    }
    return primes;
}

static int pick_random_from(const std::vector<int>& v) {
    if (v.empty()) return -1;
    return v[std::rand() % v.size()];
}

int main() {
    // seed random number generator
    srand(static_cast<unsigned>(time(nullptr)));

    cout << "Diffie-Hellman demo (single client)\n";
    cout << "Using prime p=" << p << " and generator g=" << g << "\n";

    // Try to load primes from file and pick one to use as a private prime (demo)
    auto primes = load_primes("primes.csv");
    int a = pick_random_from(primes);

    // Compute Alice's public value
    int A = FastModExp::powmod(g, a, p); // public value A = g^a mod p

    // Simulate Bob (other party) private key b and public value B
    int b = pick_random_from(primes);
    int B = FastModExp::powmod(g, b, p);

    cout << "Alice private a=" << a << " public A=" << A << "\n";
    cout << "Bob   private b=" << b << " public B=" << B << "\n";

    // Each computes shared secret
    int s_alice = FastModExp::powmod(B, a, p);
    int s_bob = FastModExp::powmod(A, b, p);

    cout << "Alice computes shared secret s = B^a mod p = " << s_alice << "\n";
    cout << "Bob   computes shared secret s = A^b mod p = " << s_bob << "\n";

    if (s_alice == s_bob) {
        cout << "Success: shared secrets match.\n";
    } else {
        cout << "Error: shared secrets differ!\n";
    }

    return 0;
}