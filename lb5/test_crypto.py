import os
import random
from crypto_lib import (
    mod_pow,
    is_prime_fermat,
    generate_rsa_keys,
    rsa_encrypt_file,
    rsa_decrypt_file,
)


def run_tests_rsa():
    print("=" * 60)
    print("ТЕСТЫ ДЛЯ ШИФРА RSA")
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

    # Тест 1: генерация ключей — проверка простоты p и q
    p, q, n, phi, D, C = generate_rsa_keys(bits=16)
    check("Генерация: p простое", is_prime_fermat(p, 50))
    check("Генерация: q простое", is_prime_fermat(q, 50))
    check("Генерация: p != q", p != q)

    # Тест 2: проверка модуля n
    check("Генерация: n == p*q", n == p * q)

    # Тест 3: проверка функции Эйлера
    check("Генерация: phi == (p-1)*(q-1)", phi == (p - 1) * (q - 1))

    # Тест 4: проверка взаимной простоты D и phi
    check("Генерация: gcd(D, phi) == 1", math.gcd(D, phi) == 1)

    # Тест 5: проверка корректности закрытого ключа C
    check("Генерация: D*C mod phi == 1", (D * C) % phi == 1)

    # Тест 6: шифрование и расшифровка всех байтов 0..255 (повтор 4 раза)
    with open("test_src.bin", "wb") as f:
        f.write(bytes(range(256)) * 4)

    rsa_encrypt_file("test_src.bin", "test_enc.bin", n, D)
    rsa_decrypt_file("test_enc.bin", "test_dec.bin", n, C)

    with open("test_src.bin", "rb") as f:
        src_data = f.read()
    with open("test_dec.bin", "rb") as f:
        dec_data = f.read()
    check("Байты 0..255 (x4): шифрование/расшифровка", src_data == dec_data)

    # Тест 7: шифртекст отличается от исходных данных
    with open("test_enc.bin", "rb") as f:
        enc_data = f.read()
    check("Шифртекст отличается от исходных данных", enc_data != src_data)

    # Тест 8: длина шифртекста = 4 * длина исходных данных
    check("Длина шифртекста = 4 * длина исходных данных",
          len(enc_data) == 4 * len(src_data))

    # Тест 9: шифрование и расшифровка текстового файла UTF-8
    text = "Привет, мир! Hello, World! 12345".encode("utf-8")
    with open("test_text.txt", "wb") as f:
        f.write(text)
    p2, q2, n2, phi2, D2, C2 = generate_rsa_keys(bits=16)
    rsa_encrypt_file("test_text.txt", "test_text_enc.bin", n2, D2)
    rsa_decrypt_file("test_text_enc.bin", "test_text_dec.txt", n2, C2)
    with open("test_text_dec.txt", "rb") as f:
        dec_text = f.read()
    check("Текстовый файл: шифрование/расшифровка", dec_text == text)

    # Тест 10: шифрование и расшифровка пустого файла
    with open("test_empty.bin", "wb") as f:
        f.write(b"")
    p3, q3, n3, phi3, D3, C3 = generate_rsa_keys(bits=16)
    rsa_encrypt_file("test_empty.bin", "test_empty_enc.bin", n3, D3)
    rsa_decrypt_file("test_empty_enc.bin", "test_empty_dec.bin", n3, C3)
    with open("test_empty_dec.bin", "rb") as f:
        dec_empty = f.read()
    check("Пустой файл: шифрование/расшифровка", dec_empty == b"")

    # Тест 11: шифрование и расшифровка файла из 1 байта
    with open("test_one.bin", "wb") as f:
        f.write(b"\x41")
    p4, q4, n4, phi4, D4, C4 = generate_rsa_keys(bits=16)
    rsa_encrypt_file("test_one.bin", "test_one_enc.bin", n4, D4)
    rsa_decrypt_file("test_one_enc.bin", "test_one_dec.bin", n4, C4)
    with open("test_one_dec.bin", "rb") as f:
        dec_one = f.read()
    check("Файл из 1 байта: шифрование/расшифровка", dec_one == b"\x41")

    # Тест 12: ручной ввод p, q, D и проверка ключей
    p_m = 65537
    q_m = 65539
    D_m = 12345
    p_m, q_m, n_m, phi_m, D_m, C_m = generate_rsa_keys(p=p_m, q=q_m, D=D_m)
    check("Ручной ввод: n == p*q", n_m == p_m * q_m)
    check("Ручной ввод: D*C mod phi == 1", (D_m * C_m) % phi_m == 1)

    # Тест 13: шифрование и расшифровка с ручными ключами
    data_manual = bytes([65, 66, 67])
    with open("test_manual.bin", "wb") as f:
        f.write(data_manual)
    rsa_encrypt_file("test_manual.bin", "test_manual_enc.bin", n_m, D_m)
    rsa_decrypt_file("test_manual_enc.bin", "test_manual_dec.bin", n_m, C_m)
    with open("test_manual_dec.bin", "rb") as f:
        dec_manual = f.read()
    check("Ручные ключи: шифрование/расшифровка", dec_manual == data_manual)

    # Тест 14: шифрование и расшифровка 1000 случайных байт
    p5, q5, n5, phi5, D5, C5 = generate_rsa_keys(bits=16)
    big_data = bytes(random.randint(0, 255) for _ in range(1000))
    with open("test_big.bin", "wb") as f:
        f.write(big_data)
    rsa_encrypt_file("test_big.bin", "test_big_enc.bin", n5, D5)
    rsa_decrypt_file("test_big_enc.bin", "test_big_dec.bin", n5, C5)
    with open("test_big_dec.bin", "rb") as f:
        dec_big = f.read()
    check("1000 случайных байт: шифрование/расшифровка", dec_big == big_data)

    # Тест 15: проверка формулы шифрования c = m^D mod n
    p6, q6, n6, phi6, D6, C6 = generate_rsa_keys(bits=16)
    data_k = b"ABCD"
    with open("test_k.bin", "wb") as f:
        f.write(data_k)
    rsa_encrypt_file("test_k.bin", "test_k_enc.bin", n6, D6)
    with open("test_k_enc.bin", "rb") as f:
        data_full = f.read()
    c1 = int.from_bytes(data_full[0:4], "big")
    check("Формула шифрования: c = m^D mod n",
          c1 == mod_pow(ord("A"), D6, n6))

    # Тест 16: проверка формулы расшифровки m = c^C mod n
    rsa_decrypt_file("test_k_enc.bin", "test_k_dec.bin", n6, C6)
    with open("test_k_dec.bin", "rb") as f:
        dec_k = f.read()
    check("Формула расшифровки: m = c^C mod n", dec_k == data_k)

    # Тест 17: некорректная длина шифртекста вызывает ошибку
    bad_data = b"\x00" * 5
    with open("test_bad.bin", "wb") as f:
        f.write(bad_data)
    try:
        rsa_decrypt_file("test_bad.bin", "test_bad_dec.bin", n6, C6)
        check("Некорректная длина шифртекста вызывает ошибку", False)
    except ValueError:
        check("Некорректная длина шифртекста вызывает ошибку", True)

    # Тест 18: D не взаимно прост с phi — должна быть ошибка
    try:
        generate_rsa_keys(p=65537, q=65539, D=2)
        check("D не взаимно прост с phi — ошибка", False)
    except ValueError:
        check("D не взаимно прост с phi — ошибка", True)

    # Удаление временных файлов
    for fname in ["test_src.bin", "test_enc.bin", "test_dec.bin",
                  "test_text.txt", "test_text_enc.bin", "test_text_dec.txt",
                  "test_empty.bin", "test_empty_enc.bin",
                  "test_empty_dec.bin", "test_one.bin", "test_one_enc.bin",
                  "test_one_dec.bin", "test_manual.bin",
                  "test_manual_enc.bin", "test_manual_dec.bin",
                  "test_big.bin", "test_big_enc.bin", "test_big_dec.bin",
                  "test_k.bin", "test_k_enc.bin", "test_k_dec.bin",
                  "test_bad.bin", "test_bad_dec.bin"]:
        if os.path.exists(fname):
            os.remove(fname)

    print(f"\n  Итого: пройдено {passed}, провалено {failed}")
    return failed == 0


def main():
    ok = run_tests_rsa()
    print()
    print("=" * 60)
    if ok:
        print("ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО")
    else:
        print("ЕСТЬ ПРОВАЛЕННЫЕ ТЕСТЫ")
    print("=" * 60)


if __name__ == "__main__":
    main()