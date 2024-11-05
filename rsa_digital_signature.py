import hashlib
import random
from utils import mod_exp, extended_gcd

def rsa_generate_keys(P, Q):
    N = P * Q
    phi = (P - 1) * (Q - 1)

    # Выбор e, взаимно простого с phi
    while True:
        e = random.randint(2, phi - 1)
        gcd, _, _ = extended_gcd(e, phi)
        if gcd == 1:
            break

    _, d, _ = extended_gcd(e, phi)
    d = d % phi
    if d < 0:
        d += phi

    print(f"Public key (e, N): ({e}, {N}), Private key (d, N): ({d}, {N})")
    return (e, N), (d, N)

def hash_document(document_path, N):
    hasher = hashlib.sha256()
    with open(document_path, 'rb') as file:
        while chunk := file.read(4096):
            hasher.update(chunk)
    h = int(hasher.hexdigest(), 16)
    
    # Обеспечим, что хеш меньше модуля N
    if h >= N:
        h %= N
    return h

def sign_document(document_path, private_key):
    d, N = private_key
    h = hash_document(document_path, N)
    s = mod_exp(h, d, N)
    print(f"Document hash (h): {h}, Signature (s): {s}")
    return s

def verify_signature(document_path, signature, public_key):
    e, N = public_key
    h = hash_document(document_path, N)
    h_from_signature = mod_exp(signature, e, N)
    print(f"h_from_signature: {h_from_signature}, h: {h}")
    return h == h_from_signature
