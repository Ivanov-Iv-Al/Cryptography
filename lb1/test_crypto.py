import math
import random
import pytest

from crypto_lib import (
    mod_pow,
    is_prime_fermat,
    extended_gcd,
    generate_prime,
    generate_coprime_pair,
)


class TestModPow:
    def test_example_from_manual(self):
        assert mod_pow(3, 100, 7) == 4

    def test_simple_cases(self):
        assert mod_pow(2, 10, 1000) == 24
        assert mod_pow(5, 0, 7) == 1
        assert mod_pow(0, 5, 7) == 0
        assert mod_pow(1, 999, 7) == 1

    def test_compare_with_builtin(self):
        for _ in range(50):
            a = random.randint(0, 10**6)
            x = random.randint(0, 10**4)
            p = random.randint(1, 10**6)
            assert mod_pow(a, x, p) == pow(a, x, p)

    def test_negative_exponent(self):
        with pytest.raises(ValueError):
            mod_pow(2, -1, 7)

    def test_zero_modulus(self):
        with pytest.raises(ValueError):
            mod_pow(2, 5, 0)


class TestFermat:
    def test_small_primes(self):
        for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 97, 101]:
            assert is_prime_fermat(p, iterations=50) is True

    def test_small_composites(self):
        for n in [4, 6, 8, 9, 10, 12, 15, 21, 100, 1000]:
            assert is_prime_fermat(n, iterations=50) is False

    def test_edge_cases(self):
        assert is_prime_fermat(0) is False
        assert is_prime_fermat(1) is False
        assert is_prime_fermat(-7) is False

    def test_large_prime(self):
        assert is_prime_fermat(2**31 - 1, iterations=50) is True


class TestExtendedGCD:
    def test_manual_examples(self):
        g, x, y = extended_gcd(28, 19)
        assert g == 1
        assert 28 * x + 19 * y == g

        g, x, y = extended_gcd(28, 8)
        assert g == 4
        assert 28 * x + 8 * y == g

    def test_known_values(self):
        for a, b in [(240, 46), (7, 11), (100, 75), (17, 5), (1, 1)]:
            g, x, y = extended_gcd(a, b)
            assert g == math.gcd(a, b)
            assert a * x + b * y == g

    def test_zero_cases(self):
        g, _, _ = extended_gcd(0, 5)
        assert g == 5
        g, _, _ = extended_gcd(5, 0)
        assert g == 5


class TestGeneration:
    def test_generate_prime_is_prime(self):
        for _ in range(5):
            p = generate_prime(16)
            assert is_prime_fermat(p, iterations=50) is True
            assert p > 0
            assert p % 2 == 1

    def test_generate_coprime_pair(self):
        for _ in range(10):
            a, b = generate_coprime_pair(16)
            assert math.gcd(a, b) == 1


class TestModularInverse:
    def test_inverse_via_extended_gcd(self):
        for c, m in [(3, 11), (7, 11), (5, 13), (17, 3120)]:
            g, x, y = extended_gcd(c, m)
            if g == 1:
                d = x % m
                assert (c * d) % m == 1

    def test_inverse_from_manual(self):
        g, x, y = extended_gcd(7, 11)
        d = x % 11
        assert d == 8
        assert (7 * 8) % 11 == 1