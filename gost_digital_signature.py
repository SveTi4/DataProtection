import hashlib
import random
from utils import mod_exp, extended_gcd, generate_large_prime, is_prime

def gost_generate_keys(bits_q=256, bits_p=1024):
    """
    Генерация ключей ГОСТ. Возвращает публичный и приватный ключи как словари.
    """
    q = generate_large_prime(bits_q)
    while True:
        b = random.randint(2, (1 << (bits_p - bits_q - 1)) - 1)
        p = b * q + 1
        if is_prime(p):
            break

    while True:
        g = random.randint(2, p - 2)
        a = mod_exp(g, b, p)
        if a > 1:
            break

    x = random.randint(1, q - 1)
    y = mod_exp(a, x, p)

    # Возвращаем ключи как словари
    public_key = {'p': p, 'q': q, 'a': a, 'y': y}
    private_key = {'x': x}
    print("Generated Public Key:", public_key)  # Отладочная печать
    print("Generated Private Key:", private_key)  # Отладочная печать
    return public_key, private_key


def gost_sign_document(document_data: bytes, private_key, public_key):
    """
    Создание подписи ГОСТ для документа. Возвращает r и s.
    """
    p, q, a, y = public_key['p'], public_key['q'], public_key['a'], public_key['y']
    x = private_key['x']
    h = int(hashlib.sha256(document_data).hexdigest(), 16) % q  # Хешируем документ и берем модуль q
    
    while True:
        k = random.randint(1, q - 1)
        r = mod_exp(a, k, p) % q
        if r == 0:
            continue
        s = (k * h + x * r) % q
        if s == 0:
            continue
        break

    return {'r': r, 's': s}

def gost_verify_signature(document_data: bytes, signature, public_key):
    """
    Проверка подписи ГОСТ. Возвращает True, если подпись верна, иначе False.
    """
    p, q, a, y = public_key['p'], public_key['q'], public_key['a'], public_key['y']
    r, s = signature['r'], signature['s']
    h = int(hashlib.sha256(document_data).hexdigest(), 16) % q  # Хешируем документ и берем модуль q
    
    if not (0 < r < q and 0 < s < q):
        return False

    h_inv = extended_gcd(h, q)[1] % q
    u1 = (s * h_inv) % q
    u2 = (-r * h_inv) % q
    v = ((mod_exp(a, u1, p) * mod_exp(y, u2, p)) % p) % q
    return v == r
