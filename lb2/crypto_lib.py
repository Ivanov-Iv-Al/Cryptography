import random
import math
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


def generate_coprime_pair(bits: int = 16):
    while True:
        a = random.getrandbits(bits) | 1
        b = random.getrandbits(bits) | 1
        if math.gcd(a, b) == 1:
            return a, b


def discrete_log_bsgs(a: int, y: int, p: int) -> Optional[int]:  
    if p <= 1:  
        raise ValueError("Модуль p должен быть > 1")  
    if a <= 0:  
        raise ValueError("Основание a должно быть положительным")  

    a = a % p  
    y = y % p  

    if y == 1:  
        return 0  
    if a == 0:  
        return 1 if y == 0 else None  

    m = math.isqrt(p) + 1  
    k = m  

    baby_steps = {}  
    cur = y  
    for j in range(m):  
        if cur not in baby_steps:  
            baby_steps[cur] = j  
        cur = (cur * a) % p  

    a_m = mod_pow(a, m, p)  
    cur = 1  

    for i in range(1, k + 1):  
        cur = (cur * a_m) % p  
        if cur in baby_steps:  
            j = baby_steps[cur]  
            x = i * m - j  
            if mod_pow(a, x, p) == y:  
                return x  

    return None  


def discrete_log_bruteforce(a: int, y: int, p: int) -> Optional[int]:  
    a = a % p  
    y = y % p  
    cur = 1  
    for x in range(p):  
        if cur == y:  
            return x  
        cur = (cur * a) % p  
    return None  


def generate_dlog_task(bits: int = 16, p: Optional[int] = None):  
    if p is None:  
        p = generate_prime(bits)  

    a = random.randint(2, p - 2)  
    x_true = random.randint(1, p - 2)  
    y = mod_pow(a, x_true, p)  
    return a, y, p, x_true  


def main():

    print("\nБыстрое возведение в степень по модулю")
    print("Пример: 3^100 mod 7")
    print(f"Результат: {mod_pow(3, 100, 7)}")

    print("\nТест простоты Ферма")
    for num in [7, 13, 561, 1105, 100, 97]:
        res = is_prime_fermat(num, iterations=100)
        print(f"  {num}: {'простое' if res else 'составное'}")

    print("\nОбобщённый алгоритм Евклида")
    for a, b in [(28, 19), (28, 8), (7, 11), (240, 46)]:
        g, x, y = extended_gcd(a, b)
        print(f"  a={a}, b={b}: gcd={g}, x={x}, y={y}, "
              f"проверка: {a}*{x} + {b}*{y} = {a*x + b*y}")

    print("\nГенерация простого числа")
    p = generate_prime(16)
    print(f"  p = {p}")

    print("\nОбратный элемент по модулю")
    c, m = 7, 11
    g, x, y = extended_gcd(c, m)
    if g == 1:
        d = x % m
        print(f"  {c}^(-1) mod {m} = {d}, проверка: {(c*d) % m}")

    print("\nДискретный логарифм (BSGS)")
    print("[Пример из учебника] 2^x mod 23 = 9")  
    x = discrete_log_bsgs(2, 9, 23)  
    print(f"  x = {x}")  
    print(f"  Проверка: 2^{x} mod 23 = {mod_pow(2, x, 23)}")  

    print("\nПроверка BSGS на случайных задачах")
    random.seed(42)  
    for i in range(5):  
        a, y, p, x_true = generate_dlog_task(bits=12)  
        x_found = discrete_log_bsgs(a, y, p)  
        print(f"  Задача {i+1}: a={a}, y={y}, p={p}")  
        print(f"    x_true={x_true}, x_found={x_found}, "  
              f"проверка: {mod_pow(a, x_found, p) == y}")  

    print("\nСравнение с прямым перебором на малых p")
    for p in [11, 23, 101]:  
        a = 2  
        x_true = random.randint(1, p - 2)  
        y = mod_pow(a, x_true, p)  
        x_bsgs = discrete_log_bsgs(a, y, p)  
        x_bf = discrete_log_bruteforce(a, y, p)  
        print(f"  p={p}, a={a}, y={y}: BSGS={x_bsgs}, перебор={x_bf}, "  
              f"совпадают: {x_bsgs == x_bf}")  

    print("  1 — ввести a, y, p вручную")  
    print("  2 — сгенерировать задачу автоматически")  
    print("  0 — выход")  
    choice = input("  Ваш выбор: ").strip()  

    if choice == "1":  
        try:  
            a = int(input("  a = "))  
            y = int(input("  y = "))  
            p = int(input("  p = "))  
            x = discrete_log_bsgs(a, y, p)  
            if x is None:  
                print("  Решение не найдено.")  
            else:  
                print(f"  x = {x}")  
                print(f"  Проверка: {a}^{x} mod {p} = {mod_pow(a, x, p)}")  
        except ValueError as e:  
            print(f"  Ошибка: {e}")  
    elif choice == "2":  
        a, y, p, x_true = generate_dlog_task(bits=16)  
        print(f"  Сгенерировано: a={a}, y={y}, p={p}")  
        x = discrete_log_bsgs(a, y, p)  
        print(f"  x = {x} (истинное x = {x_true})")  
        print(f"  Проверка: {mod_pow(a, x, p) == y}")  

main()