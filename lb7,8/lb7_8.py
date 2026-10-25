import os
import sys
import json
import hashlib
import secrets
import argparse

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
    while True:
        q = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if not is_probable_prime(q):
            continue
        p = 2 * q + 1
        if is_probable_prime(p):
            return p, q

def find_primitive_root(p, q):
    while True:
        g = secrets.randbelow(p - 3) + 2
        if mod_pow(g, 2, p) != 1 and mod_pow(g, q, p) != 1:
            return g

def dh_establish_shared_secret(bits=64):
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
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(seed + counter.to_bytes(8, 'big')).digest())
        counter += 1
    return bytes(out[:length])

def vernam_xor(data, keystream):
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
    return mod_pow(byte_val, key['d'], key['n'])

def rsa_verify_byte(sig, byte_val, key):
    return mod_pow(sig, key['e'], key['n']) == byte_val

def rsa_sign_file(in_path, key):
    with open(in_path, 'rb') as f:
        h = hashlib.sha256(f.read()).digest()
    byte_len = (key['n'].bit_length() + 7) // 8
    out = bytearray()
    for b in h:
        out.extend(rsa_sign_byte(b, key).to_bytes(byte_len, 'big'))
    return bytes(out)

def rsa_verify_file(in_path, sig, key):
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

def ask_file(prompt, must_exist=True):

    while True:
        path = input(prompt).strip().strip('"').strip("'")
        if not path:
            print("  Путь не введён, попробуй снова.")
            continue
        if must_exist and not os.path.isfile(path):
            print(f"  Файл не найден: {path}")
            continue
        return path

def ask_out_file(prompt, default=None):

    raw = input(prompt).strip().strip('"').strip("'")
    if not raw:
        if default is None:
            return None
        raw = default
    return raw

def interactive_lab7():
    print("\n Шифр Вернама")
    print("1 — зашифровать файл")
    print("2 — расшифровать файл")
    choice = input("Выбор: ").strip()
    if choice not in ('1', '2'):
        print("Неверный выбор.")
        return

    inp = ask_file("Путь к входному файлу: ")
    if choice == '1':
        default_out = inp + '.enc'
        out = ask_out_file(f"Куда сохранить (Enter = {default_out}): ", default_out)
        seed = dh_establish_shared_secret(bits=64)
        lab7_encrypt_file(inp, out, seed)
    else:
        default_out = inp[:-4] if inp.endswith('.enc') else inp + '.dec'
        out = ask_out_file(f"Куда сохранить (Enter = {default_out}): ", default_out)
        seed = dh_establish_shared_secret(bits=64)
        lab7_decrypt_file(inp, out, seed)

def interactive_lab8():
    print("\n Электронная подпись RSA")
    print("1 — сгенерировать ключи")
    print("2 — подписать файл")
    print("3 — проверить подпись")
    choice = input("Выбор: ").strip()
    KEYFILE = 'rsa_private_key.json'

    if choice == '1':
        key = rsa_generate_keys(1024)
        with open(KEYFILE, 'w') as f:
            json.dump(key, f)
        print(f"[Лаба 8] Ключи сохранены в {KEYFILE}")
        return

    if not os.path.isfile(KEYFILE):
        print(f"  Нет файла ключей {KEYFILE}. Сначала сгенерируй ключи (пункт 1).")
        return
    with open(KEYFILE) as f:
        key = {k: int(v) for k, v in json.load(f).items()}

    if choice == '2':
        inp = ask_file("Путь к файлу для подписи: ")
        sig = rsa_sign_file(inp, key)
        sig_path = inp + '.sig'
        with open(sig_path, 'wb') as f:
            f.write(sig)
        print(f"[Лаба 8] Подпись сохранена: {sig_path} ({len(sig)} байт)")
    elif choice == '3':
        inp = ask_file("Путь к проверяемому файлу: ")
        sig_path = ask_file("Путь к файлу подписи (.sig): ")
        with open(sig_path, 'rb') as f:
            sig = f.read()
        ok = rsa_verify_file(inp, sig, key)
        print(f"[Лаба 8] Подпись {'ВЕРНА' if ok else 'НЕВЕРНА'}")
    else:
        print("Неверный выбор.")

def main():
    ap = argparse.ArgumentParser(add_help=True)
    sub = ap.add_subparsers(dest='cmd')

    a7 = sub.add_parser('lab7')
    a7.add_argument('mode', nargs='?', choices=['enc', 'dec'])
    a7.add_argument('inp', nargs='?')
    a7.add_argument('out', nargs='?')

    a8 = sub.add_parser('lab8')
    a8.add_argument('mode', nargs='?', choices=['keygen', 'sign', 'verify'])
    a8.add_argument('inp', nargs='?')
    a8.add_argument('sig', nargs='?')

    args = ap.parse_args()

    if args.cmd is None:
        print("Выбери лабораторную:")
        print("7 — Шифр Вернама + Диффи-Хеллман")
        print("8 — Электронная подпись RSA")
        lab = input("Ввод: ").strip()
        if lab == '7':
            interactive_lab7()
        elif lab == '8':
            interactive_lab8()
        else:
            print("Неверный выбор.")
        return

    #ЛАБА 7 
    if args.cmd == 'lab7':
        if not args.mode:
            interactive_lab7()
            return
        seed = dh_establish_shared_secret(bits=64)
        if args.mode == 'enc':
            lab7_encrypt_file(args.inp, args.out, seed)
        else:
            lab7_decrypt_file(args.inp, args.out, seed)
        return

    #ЛАБА 8 
    if args.cmd == 'lab8':
        KEYFILE = 'rsa_private_key.json'
        if not args.mode:
            interactive_lab8()
            return
        if args.mode == 'keygen':
            key = rsa_generate_keys(1024)
            with open(KEYFILE, 'w') as f:
                json.dump(key, f)
            print(f"[Лаба 8] Ключи сохранены в {KEYFILE}")
            return
        with open(KEYFILE) as f:
            key = {k: int(v) for k, v in json.load(f).items()}
        if args.mode == 'sign':
            sig = rsa_sign_file(args.inp, key)
            with open(args.inp + '.sig', 'wb') as f:
                f.write(sig)
            print(f"[Лаба 8] Подпись: {args.inp}.sig ({len(sig)} байт)")
            return
        if args.mode == 'verify':
            with open(args.sig, 'rb') as f:
                sig = f.read()
            print(f"[Лаба 8] Подпись {'ВЕРНА' if rsa_verify_file(args.inp, sig, key) else 'НЕВЕРНА'}")

main()