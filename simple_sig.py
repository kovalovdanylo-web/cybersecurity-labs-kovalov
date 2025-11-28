import hashlib
import os
import json
import sys

MOD = 1000007


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def sha256_int_mod(data: bytes, mod: int = MOD) -> int:
    h = hashlib.sha256(data).hexdigest()
    return int(h, 16) % mod

def generate_private_key(name: str, dob: str, secret_word: str) -> int:
    concat = (name + dob + secret_word).encode('utf-8')
    return sha256_int_mod(concat, MOD)

def generate_public_key(private_key: int) -> int:
    return (private_key * 7) % MOD

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        return None
    return x % m


def sign_file(file_path: str, private_key: int) -> int:
    if not os.path.isfile(file_path):
        raise FileNotFoundError("Файл не знайдено.")
    with open(file_path, 'rb') as f:
        data = f.read()
    h_mod = sha256_int_mod(data, MOD)
    signature = (h_mod * private_key) % MOD
    return signature

def verify_signature(file_path: str, signature: int, public_key: int) -> bool:
    if not os.path.isfile(file_path):
        raise FileNotFoundError("Файл не знайдено.")
    inv = modinv(public_key, MOD)
    if inv is None:
        raise ValueError("Публічний ключ не має оберненого по модулю; не можна перевірити.")
    with open(file_path, 'rb') as f:
        data = f.read()
    h_mod = sha256_int_mod(data, MOD)
    # signature = h_mod * private_key (mod MOD)
    # signature * inv(public_key) = h_mod * private_key * inv(private_key * 7) = h_mod * inv(7)
    recovered = (signature * inv * 7) % MOD
    return recovered == h_mod


def prompt(s, default=None):
    if default:
        r = input(f"{s} [{default}]: ").strip()
        return r if r != "" else default
    else:
        return input(f"{s}: ").strip()

def save_sig_file(sig_path: str, meta: dict):
    with open(sig_path, 'w', encoding='utf-8') as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

def load_sig_file(sig_path: str) -> dict:
    with open(sig_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def demo_tamper(file_path: str) -> str:
    """Створює копію файлу з невеликою модифікацією для демонстрації підробки."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError("Файл не знайдено.")
    base, ext = os.path.splitext(file_path)
    tampered = base + "_tampered" + ext
    with open(file_path, 'rb') as fr, open(tampered, 'wb') as fw:
        data = fr.read()
        # додаємо один байт або міняємо останній — невелика зміна
        if len(data) == 0:
            fw.write(b'\x00')
        else:
            fw.write(data[:-1] + bytes([(data[-1] + 1) % 256]))
    return tampered

def main():
    print("Проста система цифрових підписів (демо).")
    while True:
        print("\nОберіть дію:")
        print("1) Згенерувати ключі з персональних даних")
        print("2) Підписати файл (генерація .sig метаданих)")
        print("3) Перевірити підпис (за .sig файлом або вручну)")
        print("4) Демонстрація підробки (створити tampered файл і перевірити)")
        print("5) Вихід")
        choice = prompt("Номер опції")
        if choice == '1':
            name = prompt("ПІБ (наприклад: Петренко)")
            dob = prompt("Дата народження (формат: DDMMYYYY, наприклад 15031995)")
            secret_word = prompt("Секретне слово")
            priv = generate_private_key(name, dob, secret_word)
            pub = generate_public_key(priv)
            print("\n--- Згенеровані ключі ---")
            print(f"Приватний ключ (mod {MOD}): {priv}")
            print(f"Публічний ключ (mod {MOD}): {pub}")
            print("Зверніть увагу: приватний ключ слід зберігати в безпеці.")
        elif choice == '2':
            name = prompt("ПІБ (щоб отримати приватний ключ)")
            dob = prompt("Дата народження (DDMMYYYY)")
            secret_word = prompt("Секретне слово")
            priv = generate_private_key(name, dob, secret_word)
            pub = generate_public_key(priv)
            file_path = prompt("Шлях до файлу для підпису (наприклад resume.pdf)")
            try:
                sig_val = sign_file(file_path, priv)
                sig_path = prompt("Шлях для збереження файлу підпису (наприклад resume.sig)", default=file_path + ".sig")
                meta = {
                    "file": os.path.basename(file_path),
                    "signature": sig_val,
                    "public_key": pub,
                    "mod": MOD,
                    "hash_algo": "SHA-256 (reduced mod)",
                    "sign_method": "signature = (hash_mod * private_key) % MOD",
                    "author": name
                }
                save_sig_file(sig_path, meta)
                print("\nПідпис створено і збережено в:", sig_path)
                print("Дані підпису (коротко):")
                print(f"  signature: {sig_val}")
                print(f"  public_key: {pub}")
            except Exception as e:
                print("Помилка:", e)
        elif choice == '3':
            mode = prompt("Перевірити за (1) .sig файлом або (2) вручну? Введи 1 або 2", default="1")
            file_path = prompt("Шлях до перевіряємого файлу")
            if mode == '1':
                sig_path = prompt("Шлях до .sig (JSON) файлу")
                try:
                    meta = load_sig_file(sig_path)
                    sig_val = int(meta['signature'])
                    pub = int(meta['public_key'])
                    ok = verify_signature(file_path, sig_val, pub)
                    print("\nРЕЗУЛЬТАТ ПЕРЕВІРКИ:")
                    print("Підпис ДІЙСНИЙ" if ok else "Підпис ПІДРОБЛЕНИЙ")
                except Exception as e:
                    print("Помилка під час перевірки:", e)
            else:
                pub_input = prompt("Введіть публічний ключ (число mod {})".format(MOD))
                sig_input = prompt("Введіть значення підпису (число)")
                try:
                    pub = int(pub_input)
                    sig_val = int(sig_input)
                    ok = verify_signature(file_path, sig_val, pub)
                    print("\nРЕЗУЛЬТАТ ПЕРЕВІРКИ:")
                    print("Підпис ДІЙСНИЙ" if ok else "Підпис ПІДРОБЛЕНИЙ")
                except Exception as e:
                    print("Помилка:", e)
        elif choice == '4':
            print("Демонстрація підробки: підпишемо файл, створимо tampered версію і перевіримо обидва.")
            name = prompt("ПІБ для ключа")
            dob = prompt("Дата народження (DDMMYYYY)")
            secret_word = prompt("Секретне слово")
            priv = generate_private_key(name, dob, secret_word)
            pub = generate_public_key(priv)
            file_path = prompt("Шлях до файлу для підпису")
            try:
                sig_val = sign_file(file_path, priv)
                sig_info = {"signature": sig_val, "public_key": pub}
                print("\nПідпис створено:", sig_val)
                ok_orig = verify_signature(file_path, sig_val, pub)
                print("Перевірка оригіналу:", "ДІЙСНИЙ" if ok_orig else "ПІДРОБЛЕНИЙ")
                tampered = demo_tamper(file_path)
                print("Створено підроблений файл:", tampered)
                ok_tampered = verify_signature(tampered, sig_val, pub)
                print("Перевірка підробленого:", "ДІЙСНИЙ" if ok_tampered else "ПІДРОБЛЕНИЙ")
            except Exception as e:
                print("Помилка:", e)
        elif choice == '5':
            print("Вихід.")
            sys.exit(0)
        else:
            print("Невірна опція. Спробуйте ще раз.")

if __name__ == "__main__":
    main()