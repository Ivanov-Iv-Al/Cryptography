import os
import sys
import json
import hashlib
import secrets

#Лаба 7

def mod_pow(base, exp, mod):
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result

def is_probable_prime(n, rounds=40):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n == p:
            return True
        if n % p == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = mod_pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_safe_prime(bits=64):
    # Генерируем "безопасное простое" p = 2q + 1, где q тоже простое.
    # Такое p удобно для поиска первообразного корня и защищает DH от
    # атак по малым подгруппам.
    while True:
        q = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if not is_probable_prime(q):
            continue
        p = 2 * q + 1
        if is_probable_prime(p):
            return p, q

def find_primitive_root(p, q):
    # Ищем первообразный корень g по модулю p.
    # Для безопасного p=2q+1 достаточно проверить, что g^2 != 1 и g^q != 1 (mod p).
    while True:
        g = secrets.randbelow(p - 3) + 2
        if mod_pow(g, 2, p) != 1 and mod_pow(g, q, p) != 1:
            return g

def dh_establish_shared_secret(bits=64):
    # Диффи-Хеллман:
    #   A = g^a mod p,  B = g^b mod p
    #   S = B^a mod p = A^b mod p = g^(ab) mod p
    # Из S получаем seed = SHA-256(S) — из него потом раздувается ключевой поток Вернама.
    p, q = gen_safe_prime(bits)
    g = find_primitive_root(p, q)
    a = secrets.randbelow(p - 3) + 2
    b = secrets.randbelow(p - 3) + 2
    A = mod_pow(g, a, p)
    B = mod_pow(g, b, p)
    S_a = mod_pow(B, a, p)
    S_b = mod_pow(A, b, p)
    assert S_a == S_b
    seed = hashlib.sha256(S_a.to_bytes((S_a.bit_length() + 7) // 8, 'big')).digest()
    print("=== Диффи-Хеллман ===")
    print(f"p = {p}, g = {g}")
    print(f"a = {a}, A = {A}")
    print(f"b = {b}, B = {B}")
    print(f"S = {S_a}")
    print(f"SHA-256(S) = {seed.hex()}\n")
    return seed

def vernam_keystream(seed, length):
    # Ключевой поток для шифра Вернама:
    #   keystream = SHA-256(seed || 0) || SHA-256(seed || 1) || ... (обрезаем до length)
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(seed + counter.to_bytes(8, 'big')).digest())
        counter += 1
    return bytes(out[:length])

def vernam_xor(data, keystream):
    # Шифр Вернама: C = P XOR K, расшифрование: P = C XOR K (XOR обратим)
    if len(data) != len(keystream):
        raise ValueError("Длина ключевого потока != длине данных")
    return bytes(d ^ k for d, k in zip(data, keystream))

def lab7_encrypt_file(in_path, out_path, seed):
    with open(in_path, 'rb') as f:
        data = f.read()
    enc = vernam_xor(data, vernam_keystream(seed, len(data)))
    with open(out_path, 'wb') as f:
        f.write(enc)
    print(f"[Лаба 7] Зашифровано {in_path} -> {out_path} ({len(data)} байт)")

def lab7_decrypt_file(in_path, out_path, seed):
    with open(in_path, 'rb') as f:
        data = f.read()
    dec = vernam_xor(data, vernam_keystream(seed, len(data)))
    with open(out_path, 'wb') as f:
        f.write(dec)
    print(f"[Лаба 7] Расшифровано {in_path} -> {out_path} ({len(data)} байт)")


#Лаба 8

def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def mod_inverse(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Инверсии нет")
    return x % m

def gen_prime(bits):
    while True:
        n = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(n):
            return n

def rsa_generate_keys(bits=1024):
    # RSA:
    #   n = p*q, phi = (p-1)(q-1)
    #   e = 65537, d = e^{-1} mod phi
    #   Открытый ключ: (n, e), закрытый: (n, d)
    e = 65537
    while True:
        p = gen_prime(bits // 2)
        q = gen_prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if egcd(e, phi)[0] == 1:
            break
    n = p * q
    d = mod_inverse(e, phi)
    return dict(n=n, e=e, d=d, p=p, q=q, phi=phi)

def rsa_sign_byte(byte_val, key):
    # Подпись "байта" (на самом деле — значение < n) закрытым ключом:
    #   s = m^d mod n
    return mod_pow(byte_val, key['d'], key['n'])

def rsa_verify_byte(sig, byte_val, key):
    # Проверка: m == s^e mod n
    return mod_pow(sig, key['e'], key['n']) == byte_val

def rsa_sign_file(in_path, key):
    # Подписываем хеш файла (SHA-256 = 32 байта), каждый байт отдельно:
    #   s_i = h_i^d mod n
    # Результат пишется по byte_len байт на каждый подписанный байт.
    with open(in_path, 'rb') as f:
        h = hashlib.sha256(f.read()).digest()
    byte_len = (key['n'].bit_length() + 7) // 8
    out = bytearray()
    for b in h:
        out.extend(rsa_sign_byte(b, key).to_bytes(byte_len, 'big'))
    return bytes(out)

def rsa_verify_file(in_path, sig, key):
    # Для каждого байта хеша проверяем: h_i == s_i^e mod n
    with open(in_path, 'rb') as f:
        h = hashlib.sha256(f.read()).digest()
    byte_len = (key['n'].bit_length() + 7) // 8
    if len(sig) != byte_len * len(h):
        return False
    for i, b in enumerate(h):
        s = int.from_bytes(sig[i * byte_len:(i + 1) * byte_len], 'big')
        if not rsa_verify_byte(s, b, key):
            return False
    return True


#Лаба 9

def egcd_full(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd_full(b, a % b)
    return g, y1, x1 - (a // b) * y1

def elgamal_generate_keys(bits=256):
    # Эль-Гамаль:
    #   Параметры: простое p, первообразный корень g
    #   Закрытый ключ x, открытый y = g^x mod p
    while True:
        p, q = gen_safe_prime(bits)
        if p.bit_length() >= bits:
            break
    g = find_primitive_root(p, q)
    x = secrets.randbelow(p - 3) + 2
    y = mod_pow(g, x, p)
    return dict(p=p, g=g, y=y, x=x)

def elgamal_sign_file(in_path, key):
    # Подпись Эль-Гамаля:
    #   m = H(file) mod p
    #   выбираем одноразовое k, gcd(k, p-1) = 1
    #   r = g^k mod p
    #   s = (m - x*r) * k^{-1} mod (p-1)
    # Подпись — пара (r, s).
    # ВАЖНО: k нельзя использовать дважды, иначе раскрывается x.
    with open(in_path, 'rb') as f:
        h = hashlib.sha256(f.read()).digest()
    m = int.from_bytes(h, 'big') % key['p']
    p, g, x = key['p'], key['g'], key['x']
    while True:
        k = secrets.randbelow(p - 2) + 1
        if egcd_full(k, p - 1)[0] != 1:
            continue
        r = mod_pow(g, k, p)
        if r == 0:
            continue
        k_inv = mod_inverse(k, p - 1)
        s = (k_inv * (m - x * r)) % (p - 1)
        if s != 0:
            break
    byte_len = (p.bit_length() + 7) // 8
    return r.to_bytes(byte_len, 'big') + s.to_bytes(byte_len, 'big')

def elgamal_verify_file(in_path, sig, key):
    # Проверка подписи Эль-Гамаля:
    #   должно выполняться  g^m ≡ y^r * r^s (mod p)
    # В коде левая часть переписана как g^m * (y^r)^{-1} mod p,
    # правая — r^s mod p. Сравниваем.
    with open(in_path, 'rb') as f:
        h = hashlib.sha256(f.read()).digest()
    m = int.from_bytes(h, 'big') % key['p']
    p, g, y = key['p'], key['g'], key['y']
    byte_len = (p.bit_length() + 7) // 8
    if len(sig) != 2 * byte_len:
        return False
    r = int.from_bytes(sig[:byte_len], 'big')
    s = int.from_bytes(sig[byte_len:], 'big')
    if not (0 < r < p) or not (0 < s < p - 1):
        return False
    y_r = mod_pow(y, r, p)
    if y_r == 0:
        return False
    left = (mod_pow(g, m, p) * mod_pow(y_r, p - 2, p)) % p
    right = mod_pow(r, s, p)
    return left == right


#Лаба 10

def gost94_generate_keys(bits=256):
    # ГОСТ Р 34.10-94:
    #   p — простое, q — простое, q | p-1, g — элемент порядка q по модулю p
    #   Закрытый x ∈ [1, q-1], открытый y = g^x mod p
    # (здесь g — первообразный корень по модулю p из безопасного простого)
    while True:
        p, q = gen_safe_prime(bits)
        if p.bit_length() >= bits:
            break
    g = find_primitive_root(p, q)
    x = secrets.randbelow(q - 2) + 1
    y = mod_pow(g, x, p)
    return dict(p=p, q=q, g=g, y=y, x=x)

def gost94_sign_file(in_path, key):
    # Подпись ГОСТ 94:
    #   m = H(file) mod q  (если 0, берём 1)
    #   выбираем одноразовое k ∈ [1, q-1]
    #   r = (g^k mod p) mod q
    #   s = (k*m + x*r) mod q
    # Если r = 0 или s = 0 — новый k. Подпись — (r, s), оба < q.
    with open(in_path, 'rb') as f:
        h = hashlib.sha256(f.read()).digest()
    p, q, g, x = key['p'], key['q'], key['g'], key['x']
    m = int.from_bytes(h, 'big') % q
    if m == 0:
        m = 1
    while True:
        k = secrets.randbelow(q - 2) + 1
        r = mod_pow(g, k, p) % q
        if r == 0:
            continue
        s = (k * m + x * r) % q
        if s != 0:
            break
    byte_len = (p.bit_length() + 7) // 8
    return r.to_bytes(byte_len, 'big') + s.to_bytes(byte_len, 'big')

def gost94_verify_file(in_path, sig, key):
    # Проверка ГОСТ 94:
    #   v  = m^{-1} mod q
    #   z1 = s*v mod q
    #   z2 = (q - r)*v mod q
    #   u  = (g^z1 * y^z2 mod p) mod q
    # Подпись верна, если u == r.
    with open(in_path, 'rb') as f:
        h = hashlib.sha256(f.read()).digest()
    p, q, g, y = key['p'], key['q'], key['g'], key['y']
    m = int.from_bytes(h, 'big') % q
    if m == 0:
        m = 1
    byte_len = (p.bit_length() + 7) // 8
    if len(sig) != 2 * byte_len:
        return False
    r = int.from_bytes(sig[:byte_len], 'big')
    s = int.from_bytes(sig[byte_len:], 'big')
    if not (0 < r < q) or not (0 < s < q):
        return False
    v = mod_inverse(m, q)
    z1 = (s * v) % q
    z2 = ((q - r) * v) % q
    u = (mod_pow(g, z1, p) * mod_pow(y, z2, p)) % p % q
    return u == r


def run_all_on_file(in_path):
    print(f"\n===== Прогон всех лаб на файле: {in_path} =====\n")

    #Лаба 7
    # DH -> общий секрет S -> seed -> ключевой поток -> XOR с файлом.
    # Проверяем, что после расшифрования получили исходный файл.
    seed = dh_establish_shared_secret(bits=64)
    enc_path = in_path + '.lab7.enc'
    dec_path = in_path + '.lab7.dec'
    lab7_encrypt_file(in_path, enc_path, seed)
    lab7_decrypt_file(enc_path, dec_path, seed)
    with open(in_path, 'rb') as f:
        orig = f.read()
    with open(dec_path, 'rb') as f:
        back = f.read()
    print(f"[Лаба 7] Расшифровка совпала с оригиналом: {orig == back}\n")

    #Лаба 8
    # RSA-подпись: s_i = h_i^d mod n, проверка h_i == s_i^e mod n.
    key8 = rsa_generate_keys(1024)
    sig8 = rsa_sign_file(in_path, key8)
    sig8_path = in_path + '.lab8.sig'
    with open(sig8_path, 'wb') as f:
        f.write(sig8)
    ok8 = rsa_verify_file(in_path, sig8, key8)
    print(f"[Лаба 8] Подпись сохранена: {sig8_path} ({len(sig8)} байт), проверка: {'ВЕРНА' if ok8 else 'НЕВЕРНА'}\n")

    #Лаба 9
    # Эль-Гамаль: r = g^k, s = (m - x*r)*k^{-1} mod (p-1),
    # проверка g^m == y^r * r^s (mod p).
    key9 = elgamal_generate_keys(256)
    sig9 = elgamal_sign_file(in_path, key9)
    sig9_path = in_path + '.lab9.sig'
    with open(sig9_path, 'wb') as f:
        f.write(sig9)
    ok9 = elgamal_verify_file(in_path, sig9, key9)
    print(f"[Лаба 9] Подпись сохранена: {sig9_path} ({len(sig9)} байт), проверка: {'ВЕРНА' if ok9 else 'НЕВЕРНА'}\n")

    #Лаба 10
    # ГОСТ 94: r = (g^k mod p) mod q, s = (k*m + x*r) mod q,
    # проверка u == r, где u = (g^z1 * y^z2 mod p) mod q,
    # z1 = s*v mod q, z2 = (q-r)*v mod q, v = m^{-1} mod q.
    key10 = gost94_generate_keys(256)
    sig10 = gost94_sign_file(in_path, key10)
    sig10_path = in_path + '.lab10.sig'
    with open(sig10_path, 'wb') as f:
        f.write(sig10)
    ok10 = gost94_verify_file(in_path, sig10, key10)
    print(f"[Лаба 10] Подпись сохранена: {sig10_path} ({len(sig10)} байт), проверка: {'ВЕРНА' if ok10 else 'НЕВЕРНА'}\n")

    print("===== Готово =====")


if __name__ == '__main__':
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        path = input("Путь к файлу для прогона всех лаб: ").strip().strip('"').strip("'")
    run_all_on_file(path)
