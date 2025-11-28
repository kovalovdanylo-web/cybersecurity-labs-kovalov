#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import math

COMMON_WORDS = {
    "password","qwerty","123456","12345678","letmein","admin","welcome",
    "iloveyou","football","monkey","dragon","sun","ivan","oleg","anna","kate"
}

def normalize(s):
    if s is None:
        return ""
    return re.sub(r'\s+','', str(s).lower())

def extract_date_variants(dob_str):
    s = re.sub(r'[^0-9]', '', dob_str)
    variants = set()
    if len(s) >= 4:
        variants.add(s[-4:])
        variants.add(s[-2:])
    if len(s) == 8:
        variants.add(s)
        variants.add(s[2:8])
        variants.add(s[:4])
    if len(s) >= 6:
        variants.add(s[-6:])
    if len(s) >= 2:
        variants.add(s[:2])
        variants.add(s[2:4])
    found = re.findall(r'(\d{1,2})', dob_str)
    for f in found:
        variants.add(f.zfill(2))
    return {v for v in variants if v}

def check_personal_matches(password, name, surname, dob):
    pw = normalize(password)
    name_n = normalize(name)
    surname_n = normalize(surname)
    matches = []

    if name_n and name_n in pw:
        matches.append(('name_full', name))
    if surname_n and surname_n in pw:
        matches.append(('surname_full', surname))

    translit_map = {
        "а": "a","б": "b","в": "v","г": "h","ґ": "g","д": "d","е": "e","є": "ie",
        "ж": "zh","з": "z","и": "y","і": "i","ї": "i","й": "i","к": "k","л": "l",
        "м": "m","н": "n","о": "o","п": "p","р": "r","с": "s","т": "t","у": "u",
        "ф": "f","х": "kh","ц": "ts","ч": "ch","ш": "sh","щ": "shch","ю": "yu","я": "ya"
    }
    def transliterate(text):
        return "".join(translit_map.get(ch, ch) for ch in text.lower())

    name_lat = normalize(transliterate(name))
    if name_lat and name_lat in pw:
        matches.append(('name_translit', name_lat))

    if dob:
        for v in extract_date_variants(dob):
            if v in pw:
                matches.append(('dob_variant', v))

    years = re.findall(r'19\d{2}|20\d{2}', pw)
    for y in years:
        matches.append(('year_in_pw', y))

    digit_runs = re.findall(r'\d{2,}', pw)
    for d in digit_runs:
        matches.append(('digit_run', d))

    return matches

def entropy_estimate(password):
    pool = 0
    if re.search(r'[a-z]', password): pool += 26
    if re.search(r'[A-Z]', password): pool += 26
    if re.search(r'[0-9]', password): pool += 10
    if re.search(r'[^A-Za-z0-9]', password): pool += 32
    if pool == 0:
        return 0.0
    return math.log2(pool) * len(password)

def dictionary_checks(password):
    pw_low = normalize(password)
    found = []
    for w in COMMON_WORDS:
        if w in pw_low:
            found.append(w)
    m = re.match(r'([a-zA-Zа-яА-Я]+)(\d+)$', password)
    if m:
        found.append(m.group(1))
    return list(set(found))

def score_password(password, personal_matches, dict_matches, entropy):
    if entropy < 20: base = 1
    elif entropy < 40: base = 2
    elif entropy < 60: base = 3
    elif entropy < 80: base = 4
    elif entropy < 100: base = 5
    else: base = 6

    penalty_personal = min(len(personal_matches), 3)
    penalty_dict = min(len(dict_matches), 2)

    bonus = 0
    if len(password) >= 12: bonus += 2
    if re.search(r'[^A-Za-z0-9]', password): bonus += 1
    if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password) and re.search(r'[0-9]', password):
        bonus += 1

    raw = base + bonus - penalty_personal - penalty_dict
    return max(1, min(10, raw))

def recommendations(password, personal_matches, dict_matches, entropy):
    recs = []
    if personal_matches:
        recs.append("Уникайте використання особистих даних (ім'я, прізвище, дати) у паролі.")
    if dict_matches:
        recs.append("Не використовуйте словникові слова або популярні паролі.")
    if entropy < 40:
        recs.append("Збільшіть довжину пароля до щонайменше 12 символів.")
        recs.append("Додавайте великі й малі літери, цифри та спеціальні символи.")
    if entropy >= 40 and entropy < 80:
        recs.append("Пароль середньої міцності — краще зробити його складнішим.")
    if entropy >= 80:
        recs.append("Пароль має хорошу ентропію, але перевірте, чи не містить персональних даних.")
    recs.append("Використовуйте унікальні паролі для різних сервісів.")
    return list(dict.fromkeys(recs))  # видаляє дублікати

def analyze_password(password, name="", surname="", dob=""):
    personal_matches = check_personal_matches(password, name, surname, dob)
    dict_matches = dictionary_checks(password)
    entropy = entropy_estimate(password)
    score = score_password(password, personal_matches, dict_matches, entropy)
    recs = recommendations(password, personal_matches, dict_matches, entropy)
    return {
        "password": password,
        "length": len(password),
        "entropy": round(entropy,1),
        "personal_matches": personal_matches,
        "dictionary_matches": dict_matches,
        "score_1_10": score,
        "recommendations": recs
    }

def pretty_print(report):
    print("=== ЗВІТ ПРО АНАЛІЗ ПАРОЛЯ ===")
    print(f"Пароль: {report['password']}")
    print(f"Довжина: {report['length']}, Ентропія: {report['entropy']} біт")
    print(f"Оцінка (1..10): {report['score_1_10']}")
    if report['personal_matches']:
        print("Збіги з персональними даними:")
        for t,v in report['personal_matches']:
            print(f" - {t}: {v}")
    if report['dictionary_matches']:
        print("Словникові слова:", ", ".join(report['dictionary_matches']))
    print("Рекомендації:")
    for r in report['recommendations']:
        print(" -", r)
    print("===============================")

if __name__ == "__main__":
    pw = input("Введіть пароль: ")
    name = input("Введіть ім'я: ")
    surname = input("Введіть прізвище (можна пропустити): ")
    dob = input("Введіть дату народження (наприклад 15.03.1995): ")

    report = analyze_password(pw, name, surname, dob)
    pretty_print(report)
