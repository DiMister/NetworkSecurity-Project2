#pragma once

class FastModExp {
public:
    // Multiply a * b mod m safely (avoids overflow when possible)
    static unsigned int mul_mod(unsigned int a, unsigned int b, unsigned int mod);

    // Compute base^exp mod mod using fast binary exponentiation
    static unsigned int powmod(unsigned int base, unsigned int exp, unsigned int mod);
};
