import random
from encryption_lib import (generate_key_pair, encrypt_step, decrypt_step, generate_key, vernam_encrypt, vernam_decrypt,
                           elgamal_generate_keys, elgamal_encrypt, elgamal_decrypt,
                           rsa_generate_keys, rsa_encrypt, rsa_decrypt)
from utils import test_ferma

# Тестирование шифра Шамира с генерацией большого простого p
def test_shamir_cipher():
    # Генерация большого простого числа p с помощью теста Ферма
    top = 10**6
    p = random.randint(2, top - 1)
    while not test_ferma(p):
        p = random.randint(2, top - 1)

    print(f"Сгенерированное простое число p: {p}")
    p_minus_1 = p - 1

    # Генерация ключей Алисы
    C_A, D_A = generate_key_pair(p_minus_1)
    print(f"Ключи Алисы: C_A={C_A}, D_A={D_A}")

    # Генерация ключей Боба
    C_B, D_B = generate_key_pair(p_minus_1)
    print(f"Ключи Боба: C_B={C_B}, D_B={D_B}")

    # Случайное сообщение m
    m = random.randint(1, p - 1)
    print(f"Сообщение m={m}")

    # Шаг 1: Алиса вычисляет x1 = m^C_A mod p и отправляет его Бобу
    x1 = encrypt_step(m, C_A, p)
    print(f"Шаг 1: x1 = {x1}")

    # Шаг 2: Боб вычисляет x2 = x1^C_B mod p и отправляет его Алисе
    x2 = encrypt_step(x1, C_B, p)
    print(f"Шаг 2: x2 = {x2}")

    # Шаг 3: Алиса вычисляет x3 = x2^D_A mod p и отправляет его Бобу
    x3 = decrypt_step(x2, D_A, p)
    print(f"Шаг 3: x3 = {x3}")

    # Шаг 4: Боб вычисляет x4 = x3^D_B mod p, получая исходное сообщение m
    x4 = decrypt_step(x3, D_B, p)
    print(f"Шаг 4: x4 = {x4}")

    # Проверка
    assert x4 == m, "Ошибка: исходное сообщение не совпадает!"
    print(f"Расшифрованное сообщение: {x4}")

# Тестирование шифра Вернама с генерацией случайных входных данных
def test_vernam_cipher():
    # Генерация случайного сообщения
    message_length = random.randint(10, 50)  # Длина сообщения от 10 до 50 байт
    message = [random.randint(0, 255) for _ in range(message_length)]
    print(f"Сгенерированное сообщение: {message}")

    # Генерация случайного ключа той же длины
    key = generate_key(message_length)
    print(f"Сгенерированный ключ: {key}")

    # Шифрование сообщения
    encrypted_message = vernam_encrypt(message, key)
    print(f"Зашифрованное сообщение: {encrypted_message}")

    # Расшифрование сообщения
    decrypted_message = vernam_decrypt(encrypted_message, key)
    print(f"Расшифрованное сообщение: {decrypted_message}")

    # Проверка
    assert message == decrypted_message, "Ошибка: исходное сообщение и расшифрованное сообщение не совпадают!"
    print("Сообщение успешно расшифровано, шифр Вернама работает корректно.")


# Тестирование шифра Эль-Гамаля с генерацией случайных данных
def test_elgamal_cipher():
    # Генерация большого простого числа p с помощью теста Ферма
    top = 10 ** 6
    p = random.randint(2, top - 1)
    while not test_ferma(p):
        p = random.randint(2, top - 1)

    print(f"Сгенерированное простое число p: {p}")

    # Выбор генератора g
    g = random.randint(2, p - 1)
    print(f"Выбранный генератор g: {g}")

    # Генерация ключей Алисы
    x, y = elgamal_generate_keys(p, g)
    print(f"Ключи Алисы: секретный ключ x={x}, открытый ключ y={y}")

    # Случайное сообщение m
    m = random.randint(1, p - 1)
    print(f"Сообщение m={m}")

    # Шифрование сообщения
    a, b = elgamal_encrypt(p, g, y, m)
    print(f"Зашифрованное сообщение: a={a}, b={b}")

    # Расшифрование сообщения
    decrypted_message = elgamal_decrypt(p, a, b, x)
    print(f"Расшифрованное сообщение: {decrypted_message}")

    # Проверка
    assert m == decrypted_message, "Ошибка: исходное сообщение и расшифрованное сообщение не совпадают!"
    print("Сообщение успешно расшифровано, шифр Эль-Гамаля работает корректно.")

    # Тестирование шифра RSA с генерацией случайных данных
def test_rsa_cipher():
        # Генерация двух больших простых чисел P и Q
        top = 1000
        P = random.randint(2, top)
        Q = random.randint(2, top)
        while not test_ferma(P):
            P = random.randint(2, top)
        while not test_ferma(Q) or Q == P:
            Q = random.randint(2, top)

        print(f"Сгенерированные простые числа P={P}, Q={Q}")

        # Генерация ключей для шифра RSA
        public_key, private_key = rsa_generate_keys(P, Q)
        print(f"Публичный ключ: {public_key}")
        print(f"Приватный ключ: {private_key}")

        # Случайное сообщение m
        m = random.randint(1, public_key[1] - 1)
        print(f"Сообщение m={m}")

        # Шифрование сообщения
        encrypted_message = rsa_encrypt(public_key, m)
        print(f"Зашифрованное сообщение: {encrypted_message}")

        # Расшифрование сообщения
        decrypted_message = rsa_decrypt(private_key, encrypted_message)
        print(f"Расшифрованное сообщение: {decrypted_message}")

        # Проверка
        assert m == decrypted_message, "Ошибка: исходное сообщение и расшифрованное сообщение не совпадают!"
        print("Сообщение успешно расшифровано, шифр RSA работает корректно.")


# Запуск теста
if __name__ == "__main__":
    # print("Тестирование шифра Шамира с большим простым числом p:")
    # test_shamir_cipher()
    # print("Тестирование шифра Вернама с генерацией случайных данных:")
    # test_vernam_cipher()
    # print("Тестирование шифра Эль-Гамаля с генерацией случайных данных:")
    # test_elgamal_cipher()
    print("Тестирование шифра RSA с генерацией случайных данных:")
    test_rsa_cipher()
