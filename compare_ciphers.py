#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Програма: Порівняння шифрів Цезар та Віженер
УВАГА: ключі вводяться користувачем (без генерації з ПД).
Запуск: python3 compare_ciphers_keys.py
"""

import re
import math

# Алфавіти (укр. і англ.)
UKR_LOWER = [
 'а','б','в','г','ґ','д','е','є','ж','з','и','і','ї','й',
 'к','л','м','н','о','п','р','с','т','у','ф','х','ц','ч','ш','щ','ь','ю','я'
]
UKR_UPPER = [c.upper() for c in UKR_LOWER]
ENG_LOWER = list("abcdefghijklmnopqrstuvwxyz")
ENG_UPPER = [c.upper() for c in ENG_LOWER]

def contains_cyrillic(s: str) -> bool:
    return bool(re.search(r'[А-Яа-яґҐєЄіІїЇ]', s))

def choose_alphabet(text: str):
    if contains_cyrillic(text):
        return (UKR_LOWER, UKR_UPPER)
    else:
        return (ENG_LOWER, ENG_UPPER)

# Цезар
def caesar_encrypt(text: str, shift: int):
    lower, upper = choose_alphabet(text)
    n = len(lower)
    res = []
    for ch in text:
        if ch in lower:
            i = lower.index(ch)
            res.append(lower[(i + shift) % n])
        elif ch in upper:
            i = upper.index(ch)
            res.append(upper[(i + shift) % n])
        else:
            res.append(ch)
    return "".join(res)

def caesar_decrypt(text: str, shift: int):
    return caesar_encrypt(text, -shift)

# Віженер
def only_letters(s: str) -> str:
    return re.sub(r'[^A-Za-zА-Яа-яґҐєЄіІїЇ]', '', s)

def vigenere_encrypt(text: str, key: str):
    lower, upper = choose_alphabet(text)
    n = len(lower)
    # підготувати ключ: залишаємо тільки символи з поточного алфавіту
    key_filtered = [k for k in key.lower() if k in lower]
    if not key_filtered:
        # якщо ключ не підходить — використовуємо букву 'a' або 'а' як fallback
        key_filtered = ['a'] if lower is ENG_LOWER else ['а']
    res = []
    ki = 0
    for ch in text:
        if ch in lower:
            shift = lower.index(key_filtered[ki % len(key_filtered)])
            i = lower.index(ch)
            res.append(lower[(i + shift) % n])
            ki += 1
        elif ch in upper:
            shift = lower.index(key_filtered[ki % len(key_filtered)])
            i = upper.index(ch)
            res.append(upper[(i + shift) % n])
            ki += 1
        else:
            res.append(ch)
    return "".join(res)

def vigenere_decrypt(text: str, key: str):
    lower, upper = choose_alphabet(text)
    n = len(lower)
    key_filtered = [k for k in key.lower() if k in lower]
    if not key_filtered:
        key_filtered = ['a'] if lower is ENG_LOWER else ['а']
    res = []
    ki = 0
    for ch in text:
        if ch in lower:
            shift = lower.index(key_filtered[ki % len(key_filtered)])
            i = lower.index(ch)
            res.append(lower[(i - shift) % n])
            ki += 1
        elif ch in upper:
            shift = lower.index(key_filtered[ki % len(key_filtered)])
            i = upper.index(ch)
            res.append(upper[(i - shift) % n])
            ki += 1
        else:
            res.append(ch)
    return "".join(res)

# Прості метрики для порівняння
def simple_metrics(ciphertext: str):
    unique_chars = len(set(ciphertext))
    letter_count = sum(1 for c in ciphertext if c.isalpha())
    nonletter_count = len(ciphertext) - letter_count
    readability_est = max(0.0, 1.0 - (nonletter_count / max(1, len(ciphertext))))
    return {
        "length": len(ciphertext),
        "unique_chars": unique_chars,
        "letters": letter_count,
        "nonletters": nonletter_count,
        "readability_est": round(readability_est, 2)
    }

def parse_shift(s: str, mod: int):
    try:
        val = int(s)
        return val % mod
    except Exception:
        return None

def main():
    print("=== Порівняльний аналіз шифрів: Цезар та Віженер ===")
    text = input("Введіть текст для шифрування:\n> ").strip()
    if not text:
        print("Порожній текст — вихід.")
        return

    # Запитуємо ключі прямо від користувача (як ти просив)
    caesar_input = input("Введіть ключ для Цезаря (ціле число зсуву). Якщо пусто — за замовчуванням 3:\n> ").strip()
    vig_key = input("Введіть ключ для Віженера (рядок):\n> ").strip()

    # Визначаємо алфавіт та модуль для зсуву
    alph_lower, alph_upper = choose_alphabet(text)
    alpha_len = len(alph_lower)

    # Обробка зсуву
    caesar_shift = parse_shift(caesar_input, alpha_len)
    if caesar_shift is None:
        caesar_shift = 3  # дефолт

    # Якщо ключ Віженера порожній — використовуємо простий fallback
    if not vig_key:
        vig_key = "key"

    # Шифруємо та дешифруємо
    caesar_ct = caesar_encrypt(text, caesar_shift)
    caesar_pt = caesar_decrypt(caesar_ct, caesar_shift)

    vigenere_ct = vigenere_encrypt(text, vig_key)
    vigenere_pt = vigenere_decrypt(vigenere_ct, vig_key)

    # Метрики
    caesar_metrics = simple_metrics(caesar_ct)
    vigenere_metrics = simple_metrics(vigenere_ct)

    # Вивід (без висновків)
    print("\n--- Ключі ---")
    print(f"Цезар: зсув = {caesar_shift}")
    print(f"Віженер: ключ = '{vig_key}'")

    print("\n--- Результати шифрування ---")
    print("\n[Цезар] шифртекст:")
    print(caesar_ct)
    print("\n[Цезар] дешифрований (перевірка):")
    print(caesar_pt)

    print("\n[Віженер] шифртекст:")
    print(vigenere_ct)
    print("\n[Віженер] дешифрований (перевірка):")
    print(vigenere_pt)

    # Порівняльна таблиця
    print("\n--- Порівняльна таблиця ---")
    print(f"{'Метод':<12} {'len':>5} {'uniq':>6} {'letters':>8} {'nonletters':>10} {'readable':>10}")
    print("-"*65)
    print(f"{'Цезар':<12} {caesar_metrics['length']:>5} {caesar_metrics['unique_chars']:>6} "
          f"{caesar_metrics['letters']:>8} {caesar_metrics['nonletters']:>10} {caesar_metrics['readability_est']:>10}")
    print(f"{'Віженер':<12} {vigenere_metrics['length']:>5} {vigenere_metrics['unique_chars']:>6} "
          f"{vigenere_metrics['letters']:>8} {vigenere_metrics['nonletters']:>10} {vigenere_metrics['readability_est']:>10}")

if __name__ == "__main__":
    main()
