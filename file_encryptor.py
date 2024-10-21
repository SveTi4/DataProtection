import os
import random
from encryption_lib import rsa_generate_keys, rsa_encrypt, rsa_decrypt
from encryption_lib import elgamal_generate_keys, elgamal_encrypt, elgamal_decrypt
from encryption_lib import generate_key, vernam_encrypt, vernam_decrypt
from encryption_lib import generate_key_pair, encrypt_step, decrypt_step
from utils import test_ferma


# Функция для чтения бинарных данных из файла
def read_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()


# Функция для записи бинарных данных в файл
def write_file(file_path, data):
    with open(file_path, 'wb') as file:
        file.write(data)


# Функция для записи ключа в key.txt
def write_key(key):
    with open('key.txt', 'w') as key_file:
        key_file.write(str(key))


# Функция для чтения ключа из key.txt
def read_key():
    with open('key.txt', 'r') as key_file:
        return eval(key_file.read())


# Шифрование файла с помощью выбранного алгоритма
def encrypt_file(file_path, algorithm):
    data = read_file(file_path)

    if algorithm == 'RSA':
        P, Q = random_prime_pair()
        public_key, private_key = rsa_generate_keys(P, Q)
        N = public_key[1]
        block_size = (N.bit_length() - 1) // 8  # Максимальный размер блока для шифрования
        encrypted_data = bytearray()
        for i in range(0, len(data), block_size):
            block = int.from_bytes(data[i:i + block_size], byteorder='big')
            encrypted_block = rsa_encrypt(public_key, block)
            encrypted_block_size = (N.bit_length() + 7) // 8
            encrypted_data.extend(encrypted_block.to_bytes(encrypted_block_size, byteorder='big'))
        return encrypted_data, private_key

    elif algorithm == 'ElGamal':
        p = generate_large_prime()
        g = random.randint(2, p - 1)
        x, y = elgamal_generate_keys(p, g)
        encrypted_data = [elgamal_encrypt(p, g, y, byte) for byte in data]
        encrypted_data_bytes = bytearray() 
        for a, b in encrypted_data:
            a_bytes = a.to_bytes((p.bit_length() + 7) // 8, byteorder='big')
            b_bytes = b.to_bytes((p.bit_length() + 7) // 8, byteorder='big')
            encrypted_data_bytes.extend(a_bytes + b_bytes)
        return encrypted_data_bytes, (p, g, x)

    # elif algorithm == 'ElGamal':

    elif algorithm == 'Vernam':
        key = generate_key(len(data))
        encrypted_data = vernam_encrypt(data, key)
        return bytes(encrypted_data), key

    elif algorithm == 'Shamir':
        p = generate_large_prime()
        C_A, D_A = generate_key_pair(p - 1)
        C_B, D_B = generate_key_pair(p - 1)
        encrypted_data = bytearray()
        for byte in data:
            x1 = encrypt_step(byte, C_A, p)
            x2 = encrypt_step(x1, C_B, p)
            x3 = decrypt_step(x2, D_A, p)
            encrypted_data.append(decrypt_step(x3, D_B, p))  # Преобразуем обратно в байт
        return encrypted_data, (C_A, D_A, C_B, D_B, p)


# Расшифрование файла с помощью выбранного алгоритма
def decrypt_file(file_path, algorithm, key):
    encrypted_data = read_file(file_path)

    if algorithm == 'RSA':
        private_key = key
        N = private_key[1]
        block_size = (N.bit_length() + 7) // 8  # Размер блока для расшифрования
        decrypted_data = bytearray()
        for i in range(0, len(encrypted_data), block_size):
            encrypted_block = int.from_bytes(encrypted_data[i:i + block_size], byteorder='big')
            decrypted_block = rsa_decrypt(private_key, encrypted_block)
            decrypted_data.extend(decrypted_block.to_bytes(block_size - 1, byteorder='big'))
        return bytes(decrypted_data)

    elif algorithm == 'ElGamal':
        p, g, x = key
        decrypted_data = bytearray()
        byte_len = (p.bit_length() + 7) // 8
        encrypted_pairs = [(int.from_bytes(encrypted_data[i:i+byte_len], byteorder='big'),
                            int.from_bytes(encrypted_data[i+byte_len:i+2*byte_len], byteorder='big'))
                           for i in range(0, len(encrypted_data), 2*byte_len)]
        for a, b in encrypted_pairs:
            decrypted_byte = elgamal_decrypt(p, a, b, x)
            decrypted_data.extend(decrypted_byte.to_bytes(1, byteorder='big'))
        return bytes(decrypted_data)

    elif algorithm == 'Vernam':
        key = key
        decrypted_data = vernam_decrypt(encrypted_data, key)
        return bytes(decrypted_data)

    elif algorithm == 'Shamir':
        C_A, D_A, C_B, D_B, p = key
        decrypted_data = bytearray()
        for byte in encrypted_data:
            x1 = encrypt_step(byte, C_A, p)
            x2 = encrypt_step(x1, C_B, p)
            x3 = decrypt_step(x2, D_A, p)
            decrypted_data.append(decrypt_step(x3, D_B, p))
        return decrypted_data


# Генерация двух больших простых чисел для RSA и ElGamal
def random_prime_pair():
    top = 1000
    P = random.randint(2, top)
    Q = random.randint(2, top)
    while not test_ferma(P, 100):
        P = random.randint(2, top)
    while not test_ferma(Q, 100) or Q == P:
        Q = random.randint(2, top)
    return P, Q


def generate_large_prime():
    top = 1000
    p = random.randint(2, top)
    while not test_ferma(p, 100):
        p = random.randint(2, top)
    return p


# Основная функция программы
def main():
    print("Выберите операцию: шифрование (1) или расшифрование (2): ")
    operation = input().strip()

    if operation == '1':
        file_path = input("Введите путь к файлу для шифрования: ").strip()
        algorithm = input("Выберите алгоритм (RSA, ElGamal, Vernam, Shamir): ").strip()

        encrypted_data, key = encrypt_file(file_path, algorithm)
        output_file = file_path + '.enc'
        write_file(output_file, encrypted_data)
        write_key(key)  # Записываем секретный ключ в key.txt

        print(f"Файл зашифрован и сохранен как {output_file}")
        print("Секретный ключ сохранён в key.txt")

    elif operation == '2':
        file_path = input("Введите путь к зашифрованному файлу: ").strip()
        algorithm = input("Выберите алгоритм (RSA, ElGamal, Vernam, Shamir): ").strip()
        key = read_key()  # Читаем ключ из key.txt

        decrypted_data = decrypt_file(file_path, algorithm, key)
        output_file = file_path + '.dec'
        write_file(output_file, decrypted_data)

        print(f"Файл расшифрован и сохранен как {output_file}")


if __name__ == "__main__":
    main()