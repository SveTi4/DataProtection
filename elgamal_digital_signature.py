import hashlib
import random
import json
from utils import mod_exp, extended_gcd, generate_large_prime, is_prime


def elgamal_generate_keys(bits=512) -> tuple:
    """
    Генерация ключей Эль-Гамаля. Возвращает публичный и приватный ключи.
    """
    # Генерация q и p, где p = 2q + 1
    q = generate_large_prime(bits)
    p = 2 * q + 1
    while not is_prime(p):
        q = generate_large_prime(bits)
        p = 2 * q + 1

    g = find_primitive_root(p, q)
    x = random.randint(2, p - 2)
    y = mod_exp(g, x, p)
    
    public_key = {'p': p, 'g': g, 'y': y}
    private_key = {'x': x}

    return public_key, private_key

def save_elgamal_keys(public_key, private_key):
    """
    Сохраняет публичный и приватный ключи Эль-Гамаля в файлы.
    """
    with open("elgamal_public_key.json", "w") as pub_file:
        json.dump(public_key, pub_file)
    with open("elgamal_private_key.json", "w") as priv_file:
        json.dump(private_key, priv_file)

def load_elgamal_public_key():
    """
    Загружает публичный ключ Эль-Гамаля из файла.
    """
    with open("elgamal_public_key.json", "r") as pub_file:
        return json.load(pub_file)

def load_elgamal_private_key():
    """
    Загружает приватный ключ Эль-Гамаля из файла.
    """
    with open("elgamal_private_key.json", "r") as priv_file:
        return json.load(priv_file)

def elgamal_sign_document(document_data: bytes, private_key, public_key) -> list:
    """
    Подписывает сообщение с помощью Эль-Гамаля. Возвращает подпись.
    """
    p = public_key['p']
    g = public_key['g']
    x = private_key['x']
    
    k = generate_coprime(p - 1)
    r = mod_exp(g, k, p)
    
    h = hashlib.md5(document_data).hexdigest()
    
    u_values = [(int(i, 16) - x * r) % (p - 1) for i in h]
    s_values = [(extended_gcd(k, p - 1)[1] * u) % (p - 1) for u in u_values]
    
    return {'r': r, 's': s_values}

def elgamal_verify_signature(document_data: bytes, signature: dict, public_key) -> bool:
    """
    Проверяет подлинность подписи для сообщения.
    """
    p = public_key["p"]
    y = public_key["y"]
    g = public_key["g"]
    r = signature["r"]
    s_values = signature["s"]
    
    h = hashlib.md5(document_data).hexdigest()
    hash_representation = ''.join(str(mod_exp(g, int(i, 16), p)) for i in h)
    verification_result = ''.join(str(mod_exp(y, r, p) * mod_exp(r, s, p) % p) for s in s_values)
    
    return verification_result == hash_representation

def find_primitive_root(p: int, q: int) -> int:
    for candidate in range(2, p):
        if mod_exp(candidate, q, p) != 1:
            return candidate
    return -1

def generate_coprime(phi: int) -> int:
    while True:
        k = random.randint(2, phi - 1)
        if extended_gcd(k, phi)[0] == 1:
            return k
