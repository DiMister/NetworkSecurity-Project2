#include "FastModExp.h"
#include <stdexcept>

// Use wider intermediate when available; unsigned version
unsigned int FastModExp::mul_mod(unsigned int a, unsigned int b, unsigned int mod) {
    // Use 64-bit intermediate to reduce overflow risk
    unsigned long long res = static_cast<unsigned long long>(a) * static_cast<unsigned long long>(b);
    return static_cast<unsigned int>(res % mod);
}

unsigned int FastModExp::powmod(unsigned int base, unsigned int exp, unsigned int mod) {
    if (mod == 0) throw std::invalid_argument("mod must be > 0");

    base %= mod;
    unsigned int result = 1u;

    // Find the most-significant-bit mask for exp
    unsigned int mask = 1u;
    unsigned int e = exp;
    while (e >>= 1) mask <<= 1;

    // Process bits from MSB to LSB
    for (; mask; mask >>= 1) {
        result = mul_mod(result, result, mod);
        if (exp & mask) {
            result = mul_mod(result, base, mod);
        }
    }

    return result;
}
