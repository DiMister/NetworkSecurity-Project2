#pragma once

class FastModExp {
public:
    // Multiply a * b mod m safely (avoids overflow when possible)
    static int mul_mod(int a, int b, int mod);

    // Compute base^exp mod mod using fast binary exponentiation
    static int powmod(int base, int exp, int mod);
};
