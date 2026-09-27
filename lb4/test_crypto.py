import os
import math
import random
from crypto_lib import (
    mod_pow,
    is_prime_fermat,
    mod_inverse,
    is_primitive_root,
    generate_primitive_root,
    diffie_hellman,
    generate_shamir_keys,
    shamir_encrypt_decrypt_file,
)


def run_tests_lab3():
    print("=" * 60)
    print("ТЕСТЫ ДЛЯ ЛАБОРАТОРНОЙ РАБОТЫ №3 (ДИФФИ-ХЕЛЛМАН)")
    print("=" * 60)
    passed = 0
    failed = 0

    def check(name, condition):
        nonlocal passed, failed
        if condition:
            print(f"  [OK]   {name}")
            passed += 1
        else:
            print(f"  [FAIL] {name}")
            failed += 1

    r1 = diffie_hellman(bits=16, verbose=False)
    check("Автогенерация: KA == KB", r1['KA'] == r1['KB'])
    check("Автогенерация: p простое", is_prime_fermat(r1['p'], 50))
    check("Автогенерация: yA == g^xA mod p",
          r1['yA'] == mod_pow(r1['g'], r1['xA'], r1['p']))
    check("Автогенерация: yB == g^xB mod p",
          r1['yB'] == mod_pow(r1['g'], r1['xB'], r1['p']))

    r2 = diffie_hellman(p=23, g=5, xA=6, xB=15, verbose=False)
    check("Ручной ввод: KA == KB", r2['KA'] == r2['KB'])
    check("Ручной ввод: yA = 8", r2['yA'] == 8)
    check("Ручной ввод: yB = 19", r2['yB'] == 19)
    check("Ручной ввод: KA = 2", r2['KA'] == 2)

    r3 = diffie_hellman(p=101, g=2, xA=10, xB=20, verbose=False)
    check("p=101: KA == KB", r3['KA'] == r3['KB'])
    check("p=101: KA == g^(xA*xB) mod p", r3['KA'] == mod_pow(2, 200, 101))

    for _ in range(10):
        r = diffie_hellman(bits=12, verbose=False)
        if r['KA'] != r['KB']:
            check("10 случайных запусков: все KA == KB", False)
            break
    else:
        check("10 случайных запусков: все KA == KB", True)

    check("is_primitive_root(2, 11)", is_primitive_root(2, 11))
    check("is_primitive_root(3, 11) == False", not is_primitive_root(3, 11))
    check("is_primitive_root(2, 13)", is_primitive_root(2, 13))
    check("is_primitive_root(6, 13) == False", not is_primitive_root(6, 13))
    check("generate_primitive_root(11) — корень",
          is_primitive_root(generate_primitive_root(11), 11))

    print(f"\n  Итого: пройдено {passed}, провалено {failed}")
    return failed == 0


def run_tests_lab4():
    print("=" * 60)
    print("ТЕСТЫ ДЛЯ ЛАБОРАТОРНОЙ РАБОТЫ №4 (ШИФР ШАМИРА)")
    print("=" * 60)
    passed = 0
    failed = 0

    def check(name, condition):
        nonlocal passed, failed
        if condition:
            print(f"  [OK]   {name}")
            passed += 1
        else:
            print(f"  [FAIL] {name}")
            failed += 1

    p, CA, DA, CB, DB = generate_shamir_keys(bits=16)
    check("Генерация: p простое", is_prime_fermat(p, 50))
    check("Генерация: CA*DA mod (p-1) == 1", (CA * DA) % (p - 1) == 1)
    check("Генерация: CB*DB mod (p-1) == 1", (CB * DB) % (p - 1) == 1)
    check("Генерация: p > 255", p > 255)
    check("Генерация: gcd(CA, p-1) == 1", math.gcd(CA, p - 1) == 1)
    check("Генерация: gcd(CB, p-1) == 1", math.gcd(CB, p - 1) == 1)

    p, CA, DA, CB, DB = generate_shamir_keys(bits=16)
    test_data = bytes(range(256)) * 4
    with open("test_src.bin", "wb") as f:
        f.write(test_data)

    shamir_encrypt_decrypt_file("test_src.bin", "test_enc.bin",
                                "encrypt", p, CA, CB)
    shamir_encrypt_decrypt_file("test_enc.bin", "test_dec.bin",
                                "decrypt", p, DA, DB)

    with open("test_dec.bin", "rb") as f:
        decrypted = f.read()
    check("Байты 0..255 (x4): шифрование/расшифровка", decrypted == test_data)

    with open("test_enc.bin", "rb") as f:
        enc_data = f.read()
    check("Шифртекст отличается от исходных данных", enc_data != test_data)
    check("Длина шифртекста == длина исходных данных",
          len(enc_data) == len(test_data))

    text = "Привет, мир! Hello, World! 12345".encode("utf-8")
    with open("test_text.txt", "wb") as f:
        f.write(text)
    p2, CA2, DA2, CB2, DB2 = generate_shamir_keys(bits=16)
    shamir_encrypt_decrypt_file("test_text.txt", "test_text_enc.bin",
                                "encrypt", p2, CA2, CB2)
    shamir_encrypt_decrypt_file("test_text_enc.bin", "test_text_dec.txt",
                                "decrypt", p2, DA2, DB2)
    with open("test_text_dec.txt", "rb") as f:
        dec_text = f.read()
    check("Текстовый файл: шифрование/расшифровка", dec_text == text)

    with open("test_empty.bin", "wb") as f:
        f.write(b"")
    p3, CA3, DA3, CB3, DB3 = generate_shamir_keys(bits=16)
    shamir_encrypt_decrypt_file("test_empty.bin", "test_empty_enc.bin",
                                "encrypt", p3, CA3, CB3)
    shamir_encrypt_decrypt_file("test_empty_enc.bin", "test_empty_dec.bin",
                                "decrypt", p3, DA3, DB3)
    with open("test_empty_dec.bin", "rb") as f:
        dec_empty = f.read()
    check("Пустой файл: шифрование/расшифровка", dec_empty == b"")

    with open("test_one.bin", "wb") as f:
        f.write(b"\x41")
    p4, CA4, DA4, CB4, DB4 = generate_shamir_keys(bits=16)
    shamir_encrypt_decrypt_file("test_one.bin", "test_one_enc.bin",
                                "encrypt", p4, CA4, CB4)
    shamir_encrypt_decrypt_file("test_one_enc.bin", "test_one_dec.bin",
                                "decrypt", p4, DA4, DB4)
    with open("test_one_dec.bin", "rb") as f:
        dec_one = f.read()
    check("Файл из 1 байта: шифрование/расшифровка", dec_one == b"\x41")

    p_manual = 101
    CA_m = 3
    DA_m = mod_inverse(CA_m, p_manual - 1)
    CB_m = 7
    DB_m = mod_inverse(CB_m, p_manual - 1)
    check("Ручной ввод: CA*DA mod (p-1) == 1",
          (CA_m * DA_m) % (p_manual - 1) == 1)
    check("Ручной ввод: CB*DB mod (p-1) == 1",
          (CB_m * DB_m) % (p_manual - 1) == 1)

    data_manual = bytes([65, 66, 67])
    with open("test_manual.bin", "wb") as f:
        f.write(data_manual)
    shamir_encrypt_decrypt_file("test_manual.bin", "test_manual_enc.bin",
                                "encrypt", p_manual, CA_m, CB_m)
    shamir_encrypt_decrypt_file("test_manual_enc.bin", "test_manual_dec.bin",
                                "decrypt", p_manual, DA_m, DB_m)
    with open("test_manual_dec.bin", "rb") as f:
        dec_manual = f.read()
    check("Ручные ключи: шифрование/расшифровка", dec_manual == data_manual)

    p5, CA5, DA5, CB5, DB5 = generate_shamir_keys(bits=16)
    big_data = bytes(random.randint(0, 255) for _ in range(1000))
    with open("test_big.bin", "wb") as f:
        f.write(big_data)
    shamir_encrypt_decrypt_file("test_big.bin", "test_big_enc.bin",
                                "encrypt", p5, CA5, CB5)
    shamir_encrypt_decrypt_file("test_big_enc.bin", "test_big_dec.bin",
                                "decrypt", p5, DA5, DB5)
    with open("test_big_dec.bin", "rb") as f:
        dec_big = f.read()
    check("1000 случайных байт: шифрование/расшифровка", dec_big == big_data)

    for fname in ["test_src.bin", "test_enc.bin", "test_dec.bin",
                  "test_text.txt", "test_text_enc.bin", "test_text_dec.txt",
                  "test_empty.bin", "test_empty_enc.bin", "test_empty_dec.bin",
                  "test_one.bin", "test_one_enc.bin", "test_one_dec.bin",
                  "test_manual.bin", "test_manual_enc.bin",
                  "test_manual_dec.bin", "test_big.bin", "test_big_enc.bin",
                  "test_big_dec.bin"]:
        if os.path.exists(fname):
            os.remove(fname)

    print(f"\n  Итого: пройдено {passed}, провалено {failed}")
    return failed == 0


def main():
    ok3 = run_tests_lab3()
    print()
    ok4 = run_tests_lab4()
    print()
    if ok3 and ok4:
        print("ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО")
    else:
        print("ЕСТЬ ПРОВАЛЕННЫЕ ТЕСТЫ")

main()