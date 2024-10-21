import random
from utils import mod_exp, extended_gcd

# Генерация пары ключей (C, D) так, чтобы C * D ≡ 1 (mod p-1)
def generate_key_pair(p_minus_1):
    while True:
        C = random.randint(2, p_minus_1 - 1)
        gcd, D, _ = extended_gcd(C, p_minus_1)
        if gcd == 1:
            D = D % p_minus_1
            if D < 0:
                D += p_minus_1
            return C, D

# Функция шифрования: x = m^C mod p
def encrypt_step(message, C, p):
    return mod_exp(message, C, p)

# Функция расшифрования: x = x^D mod p
def decrypt_step(encrypted_message, D, p):
    return mod_exp(encrypted_message, D, p)

# Функция для генерации случайного ключа той же длины, что и сообщение
def generate_key(length):
    return [random.randint(0, 255) for _ in range(length)]

# Шифрование сообщения с использованием шифра Вернама
def vernam_encrypt(message, key):
    encrypted_message = []
    for m, k in zip(message, key):
        encrypted_message.append(m ^ k)  # XOR
    return encrypted_message

# Расшифрование сообщения с использованием шифра Вернама
def vernam_decrypt(encrypted_message, key):
    decrypted_message = []
    for e, k in zip(encrypted_message, key):
        decrypted_message.append(e ^ k)  # XOR
    return decrypted_message

# Генерация ключей для шифра Эль-Гамаля
def elgamal_generate_keys(p, g):
    
    x = random.randint(1, p - 1)  # Секретный ключ Алисы
    y = mod_exp(g, x, p)  # Открытый ключ Алисы
    return x, y  # Возвращаем секретный и открытый ключ

# Шифрование сообщения m с использованием шифра Эль-Гамаля
def elgamal_encrypt(p, g, y, m):
    k = random.randint(1, p - 1)  # Секретный сессионный ключ
    a = mod_exp(g, k, p)  # a = g^k mod p
    b = (m * mod_exp(y, k, p)) % p  # b = m * y^k mod p
    return a, b  # Возвращаем пару (a, b)

# Расшифрование сообщения с использованием шифра Эль-Гамаля
def elgamal_decrypt(p, a, b, x):
    # m' = b * a^(p-1-x) mod p
    s = mod_exp(a, p - 1 - x, p)  # Вычисление обратного элемента
    m = (b * s) % p  # Восстановление исходного сообщения
    return m

# Генерация ключей для шифра RSA
def rsa_generate_keys(P, Q):
    N = P * Q  # Вычисление N
    phi = (P - 1) * (Q - 1)  # Вычисление функции Эйлера

    # Выбираем число e, взаимно простое с phi
    while True:
        e = random.randint(2, phi - 1)
        gcd, d, _ = extended_gcd(e, phi)
        if gcd == 1:
            d = d % phi
            if d < 0:
                d += phi
            return (e, N), (d, N)  # Возвращаем публичный и приватный ключи

# Шифрование сообщения m с использованием публичного ключа
def rsa_encrypt(public_key, m):
    e, N = public_key
    return mod_exp(m, e, N)

# Расшифрование сообщения с использованием приватного ключа
def rsa_decrypt(private_key, encrypted_message):
    d, N = private_key
    return mod_exp(encrypted_message, d, N)