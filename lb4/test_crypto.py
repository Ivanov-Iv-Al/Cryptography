import os
import random
from crypto_lib import (
    mod_pow,
    is_prime_fermat,
    generate_elgamal_keys,
    elgamal_encrypt_file,
    elgamal_decrypt_file,
)


def run_tests_lab5():
    print("=" * 60)
    print("ТЕСТЫ ДЛЯ ЛАБОРАТОРНОЙ РАБОТЫ №5 (ШИФР ЭЛЬ-ГАМАЛЯ)")
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

    p, g, x, y = generate_elgamal_keys(bits=17)
    check("Генерация: p простое", is_prime_fermat(p, 50))
    check("Генерация: p > 65535", p > 65535)
    check("Генерация: 1 < x < p-1", 1 < x < p - 1)
    check("Генерация: y == g^x mod p", y == mod_pow(g, x, p))

    with open("test_src.bin", "wb") as f:
        f.write(bytes(range(256)) * 4)

    elgamal_encrypt_file("test_src.bin", "test_enc.bin", p, g, y)
    elgamal_decrypt_file("test_enc.bin", "test_dec.bin", p, x)

    with open("test_src.bin", "rb") as f:
        src_data = f.read()
    with open("test_dec.bin", "rb") as f:
        dec_data = f.read()
    check("Байты 0..255 (x4): шифрование/расшифровка", src_data == dec_data)

    with open("test_enc.bin", "rb") as f:
        enc_data = f.read()
    check("Шифртекст отличается от исходных данных", enc_data != src_data)
    check("Длина шифртекста = 4 * длина исходных данных",
          len(enc_data) == 4 * len(src_data))

    text = "Привет, мир! Hello, World! 12345".encode("utf-8")
    with open("test_text.txt", "wb") as f:
        f.write(text)
    p2, g2, x2, y2 = generate_elgamal_keys(bits=17)
    elgamal_encrypt_file("test_text.txt", "test_text_enc.bin", p2, g2, y2)
    elgamal_decrypt_file("test_text_enc.bin", "test_text_dec.txt", p2, x2)
    with open("test_text_dec.txt", "rb") as f:
        dec_text = f.read()
    check("Текстовый файл: шифрование/расшифровка", dec_text == text)

    with open("test_empty.bin", "wb") as f:
        f.write(b"")
    p3, g3, x3, y3 = generate_elgamal_keys(bits=17)
    elgamal_encrypt_file("test_empty.bin", "test_empty_enc.bin", p3, g3, y3)
    elgamal_decrypt_file("test_empty_enc.bin", "test_empty_dec.bin", p3, x3)
    with open("test_empty_dec.bin", "rb") as f:
        dec_empty = f.read()
    check("Пустой файл: шифрование/расшифровка", dec_empty == b"")

    with open("test_one.bin", "wb") as f:
        f.write(b"\x41")
    p4, g4, x4, y4 = generate_elgamal_keys(bits=17)
    elgamal_encrypt_file("test_one.bin", "test_one_enc.bin", p4, g4, y4)
    elgamal_decrypt_file("test_one_enc.bin", "test_one_dec.bin", p4, x4)
    with open("test_one_dec.bin", "rb") as f:
        dec_one = f.read()
    check("Файл из 1 байта: шифрование/расшифровка", dec_one == b"\x41")

    p_m = 65537
    g_m = 3
    x_m = 12345
    y_m = mod_pow(g_m, x_m, p_m)
    check("Ручной ввод: y == g^x mod p", y_m == mod_pow(g_m, x_m, p_m))

    data_manual = bytes([65, 66, 67])
    with open("test_manual.bin", "wb") as f:
        f.write(data_manual)
    elgamal_encrypt_file("test_manual.bin", "test_manual_enc.bin",
                         p_m, g_m, y_m)
    elgamal_decrypt_file("test_manual_enc.bin", "test_manual_dec.bin",
                         p_m, x_m)
    with open("test_manual_dec.bin", "rb") as f:
        dec_manual = f.read()
    check("Ручные ключи: шифрование/расшифровка", dec_manual == data_manual)

    p5, g5, x5, y5 = generate_elgamal_keys(bits=17)
    big_data = bytes(random.randint(0, 255) for _ in range(1000))
    with open("test_big.bin", "wb") as f:
        f.write(big_data)
    elgamal_encrypt_file("test_big.bin", "test_big_enc.bin", p5, g5, y5)
    elgamal_decrypt_file("test_big_enc.bin", "test_big_dec.bin", p5, x5)
    with open("test_big_dec.bin", "rb") as f:
        dec_big = f.read()
    check("1000 случайных байт: шифрование/расшифровка", dec_big == big_data)

    p6, g6, x6, y6 = generate_elgamal_keys(bits=17)
    data_k = b"ABCD"
    with open("test_k.bin", "wb") as f:
        f.write(data_k)
    elgamal_encrypt_file("test_k.bin", "test_k1_enc.bin", p6, g6, y6, k=42)
    elgamal_encrypt_file("test_k.bin", "test_k2_enc.bin", p6, g6, y6, k=42)
    with open("test_k1_enc.bin", "rb") as f1, \
         open("test_k2_enc.bin", "rb") as f2:
        same_k = f1.read() == f2.read()
    check("Фиксированный k: одинаковый шифртекст", same_k)

    elgamal_encrypt_file("test_k.bin", "test_k3_enc.bin", p6, g6, y6, k=43)
    with open("test_k1_enc.bin", "rb") as f1, \
         open("test_k3_enc.bin", "rb") as f2:
        diff_k = f1.read() != f2.read()
    check("Разный k: разный шифртекст", diff_k)

    with open("test_k1_enc.bin", "rb") as f:
        a1 = int.from_bytes(f.read()[:2], "big")
    with open("test_k3_enc.bin", "rb") as f:
        a3 = int.from_bytes(f.read()[:2], "big")
    check("Фиксированный k: a == g^k mod p", a1 == mod_pow(g6, 42, p6))
    check("Разный k: a != предыдущего", a3 != a1)

    with open("test_k1_enc.bin", "rb") as f:
        data_full = f.read()
    a1 = int.from_bytes(data_full[0:2], "big")
    b1 = int.from_bytes(data_full[2:4], "big")
    check("Формула шифрования: b = m * y^k mod p",
          b1 == (ord("A") * mod_pow(y6, 42, p6)) % p6)

    bad_data = b"\x00" * 5
    with open("test_bad.bin", "wb") as f:
        f.write(bad_data)
    try:
        elgamal_decrypt_file("test_bad.bin", "test_bad_dec.bin", p6, x6)
        check("Некорректная длина шифртекста вызывает ошибку", False)
    except ValueError:
        check("Некорректная длина шифртекста вызывает ошибку", True)

    for fname in ["test_src.bin", "test_enc.bin", "test_dec.bin",
                  "test_text.txt", "test_text_enc.bin", "test_text_dec.txt",
                  "test_empty.bin", "test_empty_enc.bin",
                  "test_empty_dec.bin", "test_one.bin", "test_one_enc.bin",
                  "test_one_dec.bin", "test_manual.bin",
                  "test_manual_enc.bin", "test_manual_dec.bin",
                  "test_big.bin", "test_big_enc.bin", "test_big_dec.bin",
                  "test_k.bin", "test_k1_enc.bin", "test_k2_enc.bin",
                  "test_k3_enc.bin", "test_bad.bin", "test_bad_dec.bin"]:
        if os.path.exists(fname):
            os.remove(fname)

    print(f"\n  Итого: пройдено {passed}, провалено {failed}")
    return failed == 0


def main():
    ok = run_tests_lab5()
    print()
    print("=" * 60)
    if ok:
        print("ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО")
    else:
        print("ЕСТЬ ПРОВАЛЕННЫЕ ТЕСТЫ")
    print("=" * 60)


if __name__ == "__main__":
    main()
