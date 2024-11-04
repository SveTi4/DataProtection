from math import isqrt, ceil
import random

def generate_large_prime(bits):
    """
    Генерация большого простого числа заданной битовой длины.
    """
    lower = 1 << (bits - 1)  # Нижняя граница: 2^(bits - 1)
    upper = (1 << bits) - 1  # Верхняя граница: 2^bits - 1

    while True:
        candidate = random.randint(lower, upper)
        if is_prime(candidate):
            return candidate

def is_prime(n, k=5):
    """
    Тест Миллера-Рабина для проверки простоты числа.
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Представляем n-1 как 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Тестируем k раз
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = mod_exp(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = mod_exp(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def mod_exp(base, exponent, modulus):
    """
    Возведение числа в степень по модулю с использованием метода двоичного возведения в степень.
    """
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

def extended_gcd(a, b):
    """
    Расширенный алгоритм Евклида для нахождения НОД и коэффициентов уравнения Безу.
    Возвращает кортеж: (gcd, x, y), где gcd — наибольший общий делитель a и b,
    а x и y — коэффициенты, такие что ax + by = gcd.
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t

def test_ferma(p, k=5):
    """
    Тест простоты Ферма для числа p.
    Возвращает True, если p, вероятно, простое.
    """
    if p == 2:
        return True
    if p % 2 == 0:
        return False
    for _ in range(k):
        a = random.randint(2, p - 2)
        if mod_exp(a, p - 1, p) != 1:
            return False
    return True

# Тест на простоту Миллера-Рабина
def miller_rabin(n, k=5):
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = mod_exp(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = mod_exp(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Baby-step Giant-step для решения задачи дискретного логарифма
def baby_step_giant_step(a, y, p, debug=False):
    m = ceil(isqrt(p))
    a_m = mod_exp(a, m, p)
    baby_steps = {}
    current = y
    for j in range(m):
        baby_steps[current] = j
        current = (current * a) % p
    current = 1
    for i in range(m):
        if current in baby_steps:
            j = baby_steps[current]
            return i * m - j
        current = (current * a_m) % p
    return None

# Алгоритм обмена ключами по Диффи-Хеллману
def diffie_hellman_key_exchange(p, g, X_A, X_B, debug=False):
    # Открытые ключи для Алисы и Боба
    Y_A = mod_exp(g, X_A, p)
    Y_B = mod_exp(g, X_B, p)

    # Вычисляем общий секретный ключ
    Z_AB = mod_exp(Y_B, X_A, p)
    Z_BA = mod_exp(Y_A, X_B, p)

    if debug:
        print(f"Z_AB = {Z_AB}, Z_BA = {Z_BA}")

    assert Z_AB == Z_BA, "Ошибка: ключи не совпадают!"

    return Z_AB  # Возвращаем общий ключ