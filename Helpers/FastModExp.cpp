#include "FastModExp.h"
#include <stdexcept>

// Use wider intermediate when available; for "int" fallback uses safe algorithm
int FastModExp::mul_mod(int a, int b, int mod) {
    return (a*b) % mod;
}

int FastModExp::powmod(int base, int exp, int mod) {
    if (mod == 0) throw std::invalid_argument("mod must be > 0");
    if (exp < 0) throw std::invalid_argument("exp must be >= 0");

    base %= mod;
    int result = 1;

    // Find the most-significant-bit mask for exp
    int mask = 1;
    int e = exp;
    while (e >>= 1) mask <<= 1;

    // Process bits from MSB to LSB: for each bit do
    //   result = result^2 mod
    //   if bit == 1 -> result = result * base mod
    for (; mask; mask >>= 1) {
        // square
        result = mul_mod(result, result, mod);
        // if current MSB is 1, multiply by base
        if (exp & mask) {
            result = mul_mod(result, base, mod);
        }
    }

    return result;
}
