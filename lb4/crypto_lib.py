import random
import math
import os
from typing import Optional


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


def mod_inverse(a: int, m: int) -> int:
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"Обратный элемент не существует: gcd({a}, {m}) = {g}")
    return x % m


def generate_prime(bits: int = 16) -> int:
    while True:
        candidate = random.getrandbits(bits) | 1
        if candidate < 3:
            continue
        if is_prime_fermat(candidate, iterations=50):
            return candidate


def is_primitive_root(g: int, p: int) -> bool:
    if math.gcd(g, p) != 1:
        return False
    if p == 2:
        return g % 2 == 1
    n = p - 1
    factors = set()
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.add(d)
            n //= d
        d += 1
    if n > 1:
        factors.add(n)
    for q in factors:
        if mod_pow(g, (p - 1) // q, p) == 1:
            return False
    return True


def generate_primitive_root(p: int) -> int:
    if p <= 2:
        return 1
    while True:
        g = random.randint(2, p - 2)
        if is_primitive_root(g, p):
            return g


def generate_shamir_keys(p: Optional[int] = None, bits: int = 16):
    if p is None:
        p = generate_prime(bits)
    while True:
        CA = random.randint(2, p - 2)
        if math.gcd(CA, p - 1) == 1:
            break
    DA = mod_inverse(CA, p - 1)
    while True:
        CB = random.randint(2, p - 2)
        if math.gcd(CB, p - 1) == 1:
            break
    DB = mod_inverse(CB, p - 1)
    return p, CA, DA, CB, DB


def shamir_encrypt_decrypt_file(input_path: str,
                                output_path: str,
                                mode: str,
                                p: int,
                                C1: Optional[int] = None,
                                D1: Optional[int] = None,
                                C2: Optional[int] = None,
                                D2: Optional[int] = None):
    with open(input_path, "rb") as f:
        data = f.read()

    if mode == "encrypt":
        if C1 is None or C2 is None:
            raise ValueError("Для шифрования нужны C1 (CA) и C2 (CB)")
        # y1 = x^CA mod p
        # y2 = y1^CB mod p
        out = bytes(mod_pow(b, C1, p) for b in data)
        out = bytes(mod_pow(b, C2, p) for b in out)
    elif mode == "decrypt":
        if D1 is None or D2 is None:
            raise ValueError("Для расшифровки нужны D1 (DA) и D2 (DB)")
        # x1 = y2^DA mod p
        # x2 = x1^DB mod p
        out = bytes(mod_pow(b, D1, p) for b in data)
        out = bytes(mod_pow(b, D2, p) for b in out)
    else:
        raise ValueError("mode должен быть 'encrypt' или 'decrypt'")

    with open(output_path, "wb") as f:
        f.write(out)
    return len(data), len(out)


def generate_elgamal_keys(p: Optional[int] = None,
                          g: Optional[int] = None,
                          bits: int = 16,
                          x: Optional[int] = None):
    if p is None:
        p = generate_prime(bits)
    if not is_prime_fermat(p, iterations=50):
        raise ValueError(f"p = {p} не является простым")
    if g is None:
        g = generate_primitive_root(p)
    if x is None:
        x = random.randint(2, p - 2)
    if not (1 < x < p - 1):
        raise ValueError("x должно быть в диапазоне 1 < x < p-1")
    # y = g^x mod p
    y = mod_pow(g, x, p)
    return p, g, x, y


def elgamal_encrypt_file(input_path: str,
                         output_path: str,
                         p: int,
                         g: int,
                         y: int,
                         k: Optional[int] = None):
    with open(input_path, "rb") as f:
        data = f.read()

    # a = g^k mod p
    # b = m * y^k mod p
    result = bytearray()
    for m in data:
        if k is None:
            kk = random.randint(2, p - 2)
        else:
            kk = k
        a = mod_pow(g, kk, p)
        b = (m * mod_pow(y, kk, p)) % p

        # упаковка пары (a, b) в 4 байта: 2 байта на a, 2 байта на b
        result.extend(a.to_bytes(2, "big"))
        result.extend(b.to_bytes(2, "big"))

    with open(output_path, "wb") as f:
        f.write(bytes(result))
    return len(data), len(result)


def elgamal_decrypt_file(input_path: str,
                         output_path: str,
                         p: int,
                         x: int):
    with open(input_path, "rb") as f:
        data = f.read()

    if len(data) % 4 != 0:
        raise ValueError("Некорректная длина шифртекста: должна быть кратна 4")

    # m = b * (a^x)^(-1) mod p
    result = bytearray()
    for i in range(0, len(data), 4):
        a = int.from_bytes(data[i:i + 2], "big")
        b = int.from_bytes(data[i + 2:i + 4], "big")
        s = mod_pow(a, x, p)
        s_inv = mod_inverse(s, p)
        m = (b * s_inv) % p
        if not (0 <= m <= 255):
            raise ValueError(f"Восстановленный байт вне диапазона: {m}")
        result.append(m)

    with open(output_path, "wb") as f:
        f.write(bytes(result))
    return len(data), len(result)


def lab3_menu():
    from crypto_lib import diffie_hellman
    print("\n" + "=" * 60)
    print("ЛАБОРАТОРНАЯ РАБОТА №3 — ДИФФИ-ХЕЛЛМАН")
    print("=" * 60)
    print("  1 — ввести p, g, xA, xB вручную")
    print("  2 — сгенерировать всё автоматически")
    print("  0 — назад")
    choice = input("  Ваш выбор: ").strip()
    if choice == "1":
        try:
            p = int(input("  p = "))
            g = int(input("  g = "))
            xA = int(input("  xA = "))
            xB = int(input("  xB = "))
            diffie_hellman(p=p, g=g, xA=xA, xB=xB)
        except ValueError as e:
            print(f"  Ошибка: {e}")
    elif choice == "2":
        bits = int(input("  Размер p в битах (по умолчанию 16): ") or "16")
        diffie_hellman(bits=bits)


def lab4_menu():
    print("\n" + "=" * 60)
    print("ЛАБОРАТОРНАЯ РАБОТА №4 — ШИФР ШАМИРА")
    print("=" * 60)
    print("  1 — ввести p, C1, C2, D1, D2 вручную")
    print("  2 — сгенерировать p, C1, C2, D1, D2 автоматически")
    print("  0 — назад")
    choice = input("  Ваш выбор: ").strip()
    if choice == "1":
        try:
            p = int(input("  p  = "))
            C1 = int(input("  C1 (CA) = "))
            D1 = int(input("  D1 (DA) = "))
            C2 = int(input("  C2 (CB) = "))
            D2 = int(input("  D2 (DB) = "))
        except ValueError as e:
            print(f"  Ошибка: {e}")
            return
    elif choice == "2":
        bits = int(input("  Размер p в битах (по умолчанию 16): ") or "16")
        p, C1, D1, C2, D2 = generate_shamir_keys(bits=bits)
        print(f"  Сгенерировано: p={p}, C1={C1}, D1={D1}, C2={C2}, D2={D2}")
        print(f"  Проверка: C1*D1 mod (p-1) = {(C1 * D1) % (p - 1)}")
        print(f"             C2*D2 mod (p-1) = {(C2 * D2) % (p - 1)}")
    else:
        return
    src = input("  Исходный файл: ").strip()
    enc = input("  Файл для шифртекста: ").strip()
    dec = input("  Файл для расшифровки: ").strip()
    try:
        n1, n2 = shamir_encrypt_decrypt_file(src, enc, "encrypt", p, C1, C2)
        print(f"  Зашифровано {n1} байт -> {n2} байт")
        n3, n4 = shamir_encrypt_decrypt_file(enc, dec, "decrypt", p, D1, D2)
        print(f"  Расшифровано {n3} байт -> {n4} байт")
        with open(src, "rb") as f1, open(dec, "rb") as f2:
            same = f1.read() == f2.read()
        print(f"  Файлы совпадают: {same}")
    except Exception as e:
        print(f"  Ошибка: {e}")


def lab5_menu():
    print("\n" + "=" * 60)
    print("ЛАБОРАТОРНАЯ РАБОТА №5 — ШИФР ЭЛЬ-ГАМАЛЯ")
    print("=" * 60)
    print("  1 — ввести p, g, x вручную")
    print("  2 — сгенерировать p, g, x автоматически")
    print("  0 — назад")
    choice = input("  Ваш выбор: ").strip()

    if choice == "1":
        try:
            p = int(input("  p = "))
            g = int(input("  g = "))
            x = int(input("  x = "))
            if not (1 < x < p - 1):
                raise ValueError("x должно быть в диапазоне 1 < x < p-1")
            y = mod_pow(g, x, p)
            print(f"  Открытый ключ: y = g^x mod p = {y}")
        except ValueError as e:
            print(f"  Ошибка: {e}")
            return
    elif choice == "2":
        bits = int(input("  Размер p в битах (по умолчанию 16): ") or "16")
        p, g, x, y = generate_elgamal_keys(bits=bits)
        print(f"  Сгенерировано: p={p}, g={g}, x={x}, y={y}")
    else:
        return

    src = input("  Исходный файл: ").strip()
    enc = input("  Файл для шифртекста: ").strip()
    dec = input("  Файл для расшифровки: ").strip()

    try:
        n1, n2 = elgamal_encrypt_file(src, enc, p, g, y)
        print(f"  Зашифровано {n1} байт -> {n2} байт")
        n3, n4 = elgamal_decrypt_file(enc, dec, p, x)
        print(f"  Расшифровано {n3} байт -> {n4} байт")
        with open(src, "rb") as f1, open(dec, "rb") as f2:
            same = f1.read() == f2.read()
        print(f"  Файлы совпадают: {same}")
    except Exception as e:
        print(f"  Ошибка: {e}")


def main():
    print("=" * 60)
    print("КРИПТОГРАФИЧЕСКАЯ БИБЛИОТЕКА — Лабораторные работы №3–5")
    print("=" * 60)

    while True:
        print("\n" + "=" * 60)
        print("ГЛАВНОЕ МЕНЮ")
        print("=" * 60)
        print("  1 — Лабораторная работа №3 (Диффи-Хеллман)")
        print("  2 — Лабораторная работа №4 (Шифр Шамира)")
        print("  3 — Лабораторная работа №5 (Шифр Эль-Гамаля)")
        print("  0 — выход")
        c = input("  Ваш выбор: ").strip()
        if c == "1":
            lab3_menu()
        elif c == "2":
            lab4_menu()
        elif c == "3":
            lab5_menu()
        elif c == "0":
            break


if __name__ == "__main__":
    main()
