import random
import math


def mod_pow(a: int, x: int, p: int) -> int:
    if p <= 0:
        raise ValueError("Модуль p должен быть положительным")
    if x < 0:
        raise ValueError("Показатель x должен быть неотрицательным")

    y = 1
    a = a % p
    while x > 0:
        if x & 1:
            y = (y * a) % p
        a = (a * a) % p
        x >>= 1
    return y


def is_prime_fermat(n: int, iterations: int = 100) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    for _ in range(iterations):
        a = random.randint(2, n - 2)
        if math.gcd(a, n) != 1:
            return False
        if mod_pow(a, n - 1, n) != 1:
            return False
    return True


def extended_gcd(a: int, b: int):
    U = (abs(a), 1, 0)
    V = (abs(b), 0, 1)

    while V[0] != 0:
        q = U[0] // V[0]
        T = (U[0] % V[0],
             U[1] - q * V[1],
             U[2] - q * V[2])
        U = V
        V = T

    gcd_val, x, y = U
    if a < 0:
        x = -x
    if b < 0:
        y = -y
    return gcd_val, x, y


def generate_prime(bits: int = 16) -> int:
    while True:
        candidate = random.getrandbits(bits) | 1
        if candidate < 3:
            continue
        if is_prime_fermat(candidate, iterations=50):
            return candidate


def generate_coprime_pair(bits: int = 16):
    while True:
        a = random.getrandbits(bits) | 1
        b = random.getrandbits(bits) | 1
        if math.gcd(a, b) == 1:
            return a, b


def main():
    print("=" * 60)
    print("КРИПТОГРАФИЧЕСКАЯ БИБЛИОТЕКА — Лабораторная работа №1")
    print("=" * 60)

    print("\n[1] Быстрое возведение в степень по модулю")
    print("Пример: 3^100 mod 7")
    print(f"Результат: {mod_pow(3, 100, 7)}")

    print("\n[2] Тест простоты Ферма")
    for num in [7, 13, 561, 1105, 100, 97]:
        res = is_prime_fermat(num, iterations=100)
        print(f"  {num}: {'простое' if res else 'составное'}")

    print("\n[3] Обобщённый алгоритм Евклида")
    for a, b in [(28, 19), (28, 8), (7, 11), (240, 46)]:
        g, x, y = extended_gcd(a, b)
        print(f"  a={a}, b={b}: gcd={g}, x={x}, y={y}, "
              f"проверка: {a}*{x} + {b}*{y} = {a*x + b*y}")

    print("\n[4] Генерация простого числа")
    p = generate_prime(16)
    print(f"  p = {p}")

    print("\n[5] Обратный элемент по модулю")
    c, m = 7, 11
    g, x, y = extended_gcd(c, m)
    if g == 1:
        d = x % m
        print(f"  {c}^(-1) mod {m} = {d}, проверка: {(c*d) % m}")


if __name__ == "__main__":
    main()