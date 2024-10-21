import random
from utils import mod_exp, extended_gcd, test_ferma, miller_rabin, baby_step_giant_step, diffie_hellman_key_exchange

# Тест для mod_exp
def test_mod_exp():
    a = random.randint(10**6, 10**9)  # a в диапазоне 10^6 - 10^9
    print(f"Сгенерированное значение a: {a}")

    top = 10**6
    p = random.randint(2, top - 1)
    while not test_ferma(p):
        p = random.randint(2, top - 1)

    print(f"Сгенерированное вероятно простое число p: {p}")

    x = random.randint(1, p - 1)
    print(f"Сгенерированное значение x: {x}")

    result = mod_exp(a, x, p, debug=False)
    print(f"Результат вычисления y = a^x mod p: {result}")

# Тест для extended_gcd
def test_extended_gcd():
    a = random.randint(10**6, 10**9)
    print(f"Сгенерированное значение a: {a}")
    b = random.randint(10**6, 10**9)
    print(f"Сгенерированное значение b: {b}")
    gcd, x, y = extended_gcd(a, b, debug=True)
    print(f"gcd({a}, {b}) = {gcd}, x = {x}, y = {y}")

# Тест для diffie_hellman_key_exchange
def test_diffie_hellman():
    top = 10**6
    p = random.randint(2, top - 1)
    while not test_ferma(p) or not test_ferma(p // 2):
        p = random.randint(2, top - 1)

    q = p // 2

    g = random.randint(1, p - 1)
    while not mod_exp(g, q, p) == 1:
        g = random.randint(1, p - 1)

    X_A = random.randint(1, p - 1)  # Секретный ключ Алисы
    X_B = random.randint(1, p - 1)  # Секретный ключ Боба

    # Генерация общего ключа
    secret_key = diffie_hellman_key_exchange(p, g, X_A, X_B, debug=True)
    print(f"Общий секретный ключ: {secret_key}")

# Тест для baby_step_giant_step
def test_baby_step_giant_step():
    a = random.randint(10**6, 10**9)
    print(f"Сгенерированное значение a: {a}")

    p = random.randint(10**8, 10**9)
    while not miller_rabin(p, 100):
        p = random.randint(10**8, 10**9)
    print(f"Сгенерированное значение p: {p}")

    x1 = random.randint(1, p - 1)
    print(f"Сгенерированное значение x1: {x1}")
    y = mod_exp(a, x1, p)

    x = baby_step_giant_step(a, y, p)

    if x is not None:
        print(f"Решение: x = {x}")
        # Проверка правильности
        assert mod_exp(a, x, p) == y, "Проверка не прошла!"
        print(mod_exp(a, x, p))
    else:
        print("Решение не найдено.")

# Запуск всех тестов
if __name__ == "__main__":
    P = 3
    Q = 11
    phi = 20
    while True:
        e = 3
        gcd, d, _ = extended_gcd(e, phi)
        if gcd == 1:
            d = d % phi
            if d < 0:
                d += phi
            print(e, extended_gcd(e, phi))
            break
                
    print(mod_exp(15, 3, 33))
    print(mod_exp(9, 7, 33))
            # return (e, N), (d, N)
    # print("Тестирование mod_exp:")
    # test_mod_exp()
    # print("\nТестирование extended_gcd:")
    # test_extended_gcd()
    # print("\nТестирование Diffie-Hellman:")
    # test_diffie_hellman()
    # print("\nТестирование baby_step_giant_step:")
    # test_baby_step_giant_step()