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


def generate_rsa_keys(p: Optional[int] = None,
                      q: Optional[int] = None,
                      D: Optional[int] = None,
                      bits: int = 16):
    if p is None:
        p = generate_prime(bits)
    if q is None:
        q = generate_prime(bits)
        while q == p:
            q = generate_prime(bits)
    if not is_prime_fermat(p, iterations=50):
        raise ValueError(f"p = {p} не является простым")
    if not is_prime_fermat(q, iterations=50):
        raise ValueError(f"q = {q} не является простым")
    #Выбираем простые числа p и q и выполняем их умножение
    n = p * q
    #Вычисляется значение функции Эйлера от числа n 
    phi = (p - 1) * (q - 1)
    if D is None:
        while True:
            D = random.randint(2, phi - 1)
            if math.gcd(D, phi) == 1:
                break
    else:
        if math.gcd(D, phi) != 1:
            raise ValueError(f"D = {D} не взаимно просто с phi = {phi}")
    C = mod_inverse(D, phi)
    return p, q, n, phi, D, C


def rsa_encrypt_file(input_path: str,
                     output_path: str,
                     n: int,
                     D: int):
    with open(input_path, "rb") as f:
        data = f.read()

    if n <= 255:
        raise ValueError("n должно быть больше 255 для шифрования байтов")

    result = bytearray()
    for m in data:
        c = mod_pow(m, D, n)
        result.extend(c.to_bytes(4, "big"))

    with open(output_path, "wb") as f:
        f.write(bytes(result))
    return len(data), len(result)


def rsa_decrypt_file(input_path: str,
                     output_path: str,
                     n: int,
                     C: int):
    with open(input_path, "rb") as f:
        data = f.read()

    if len(data) % 4 != 0:
        raise ValueError("Некорректная длина шифртекста: должна быть кратна 4")

    result = bytearray()
    for i in range(0, len(data), 4):
        c = int.from_bytes(data[i:i + 4], "big")
        m = mod_pow(c, C, n)
        if not (0 <= m <= 255):
            raise ValueError(f"Восстановленный байт вне диапазона: {m}")
        result.append(m)

    with open(output_path, "wb") as f:
        f.write(bytes(result))
    return len(data), len(result)


def rsa_menu():
    print("Шифр RSA")
    print("  1 — ввести p, q, D вручную")
    print("  2 — сгенерировать p, q, D автоматически")
    print("  0 — назад")
    choice = input("  Ваш выбор: ").strip()

    if choice == "1":
        try:
            p = int(input("  p = "))
            q = int(input("  q = "))
            D = int(input("  D = "))
            p, q, n, phi, D, C = generate_rsa_keys(p=p, q=q, D=D)
            print(f"  n = p*q = {n}")
            print(f"  phi = (p-1)*(q-1) = {phi}")
            print(f"  Открытый ключ: (n={n}, D={D})")
            print(f"  Закрытый ключ: (n={n}, C={C})")
            print(f"  Проверка: D*C mod phi = {(D * C) % phi}")
        except ValueError as e:
            print(f"  Ошибка: {e}")
            return
    elif choice == "2":
        bits = int(input("  Размер p и q в битах (по умолчанию 16): ") or "16")
        p, q, n, phi, D, C = generate_rsa_keys(bits=bits)
        print(f"  Сгенерировано: p={p}, q={q}")
        print(f"  n = p*q = {n}")
        print(f"  phi = (p-1)*(q-1) = {phi}")
        print(f"  Открытый ключ: (n={n}, D={D})")
        print(f"  Закрытый ключ: (n={n}, C={C})")
        print(f"  Проверка: D*C mod phi = {(D * C) % phi}")
    else:
        return

    src = input("  Исходный файл: ").strip()
    enc = input("  Файл для шифртекста: ").strip()
    dec = input("  Файл для расшифровки: ").strip()

    try:
        n1, n2 = rsa_encrypt_file(src, enc, n, D)
        print(f"  Зашифровано {n1} байт -> {n2} байт")
        n3, n4 = rsa_decrypt_file(enc, dec, n, C)
        print(f"  Расшифровано {n3} байт -> {n4} байт")
        with open(src, "rb") as f1, open(dec, "rb") as f2:
            same = f1.read() == f2.read()
        print(f"  Файлы совпадают: {same}")
    except Exception as e:
        print(f"  Ошибка: {e}")


def main():
            rsa_menu()

main()