import os
from utils import generate_large_prime
from elgamal_digital_signature import (
    elgamal_generate_keys, 
    elgamal_sign_document, 
    elgamal_verify_signature, 
    save_elgamal_keys, 
    load_elgamal_public_key, 
    load_elgamal_private_key
)
from rsa_digital_signature import (
    rsa_generate_keys,
    sign_document as rsa_sign_document,
    verify_signature as rsa_verify_signature
)
import json

def save_key(key, file_name):
    with open(file_name, 'w') as key_file:
        json.dump(key, key_file)

def load_key(file_name):
    with open(file_name, 'r') as key_file:
        return tuple(json.load(key_file))

def save_signature(signature, file_name):
    with open(file_name, 'w') as sig_file:
        json.dump(signature, sig_file)

def load_signature(file_name):
    with open(file_name, 'r') as sig_file:
        return json.load(sig_file)

# Функции для RSA
def rsa_sign_file(document_path):
    """
    Подписывает файл с помощью RSA и сохраняет подпись и ключи.
    """
    # Генерация случайных простых чисел P и Q длиной 512 бит каждый
    P = generate_large_prime(512)
    Q = generate_large_prime(512)
    while Q == P:
        Q = generate_large_prime(512)

    public_key, private_key = rsa_generate_keys(P, Q)

    # Подписываем документ
    signature = rsa_sign_document(document_path, private_key)
    save_signature(signature, document_path + '.sig')
    save_key(public_key, 'rsa_public_key.json')

    print(f"Документ подписан, подпись сохранена в {document_path}.sig")
    print("Публичный ключ сохранен в rsa_public_key.json")
    print("Приватный ключ сохранен в rsa_private_key.json")

def rsa_verify_file(document_path):
    public_key = load_key('rsa_public_key.json')
    signature = load_signature(document_path + '.sig')
    is_valid = rsa_verify_signature(document_path, signature, public_key)
    print("Подпись верна." if is_valid else "Подпись неверна.")

# Функции для Эль-Гамаля
def elgamal_sign_file(document_path):
    with open(document_path, 'rb') as file:
        document_data = file.read()

    public_key, private_key = elgamal_generate_keys()
    save_elgamal_keys(public_key, private_key)  # Сохранение ключей

    signature = elgamal_sign_document(document_data, private_key, public_key)
    
    with open(document_path + '.sig', 'w') as sig_file:
        json.dump(signature, sig_file)
    print(f"Документ подписан, подпись сохранена в {document_path}.sig")

def elgamal_verify_file(document_path):
    with open(document_path, 'rb') as file:
        document_data = file.read()
    
    with open(document_path + '.sig', 'r') as sig_file:
        signature = json.load(sig_file)
    
    public_key = load_elgamal_public_key()
    is_valid = elgamal_verify_signature(document_data, signature, public_key)
    print("Подпись верна." if is_valid else "Подпись неверна.")

# Основной код для запуска программы
if __name__ == "__main__":
    print("Выберите алгоритм: RSA (1) или Эль-Гамаля (2): ")
    algorithm = input().strip()

    if algorithm == '1':
        print("Выберите операцию: подписать файл (1) или проверить подпись (2): ")
        operation = input().strip()
        if operation == '1':
            document_path = input("Введите путь к файлу: ").strip()
            rsa_sign_file(document_path)
        elif operation == '2':
            document_path = input("Введите путь к файлу: ").strip()
            rsa_verify_file(document_path)
        else:
            print("Неверный выбор операции.")

    elif algorithm == '2':
        print("Выберите операцию: подписать файл (1) или проверить подпись (2): ")
        operation = input().strip()
        if operation == '1':
            document_path = input("Введите путь к файлу: ").strip()
            elgamal_sign_file(document_path)
        elif operation == '2':
            document_path = input("Введите путь к файлу: ").strip()
            elgamal_verify_file(document_path)
        else:
            print("Неверный выбор операции.")
    else:
        print("Неверный выбор алгоритма.")
