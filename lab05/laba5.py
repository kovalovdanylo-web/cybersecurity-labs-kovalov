import argparse
import base64
import os
from getpass import getpass
import sys
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Параметри KDF
KDF_ITERATIONS = 200_000
KEY_LEN = 32  # 256-bit AES
SALT_LEN = 16 # 128-bit Salt
NONCE_LEN = 12 # 96-bit Nonce

def derive_key_from_personal(personal_string: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """Використовує PBKDF2 для створення ключа з текстового рядка та солі."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(personal_string.encode('utf-8'))

def encrypt_bytes(key: bytes, plaintext: bytes) -> (bytes, bytes):
    """Шифрує байти, повертаючи Nonce та шифртекст (з тегом GCM)."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN) 
    # Associated_data (AAD) тут не використовується, встановлюємо None
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)  
    
    # ct містить шифртекст + тег автентифікації GCM (зазвичай 16 байт)
    return nonce, ct

def decrypt_bytes(key: bytes, nonce: bytes, ct: bytes) -> bytes:
    """Розшифровує байти. Якщо тег GCM не дійсний, виникає виняток InvalidTag."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, associated_data=None)

def pack_output(salt: bytes, nonce: bytes, ct: bytes) -> str:
    """Упаковує сіль, nonce та шифртекст у base64 blob."""
    # Структура: [SALT (16B)] + [NONCE (12B)] + [CIPHERTEXT + TAG (змінна довжина)]
    blob = salt + nonce + ct
    return base64.b64encode(blob).decode('utf-8')

def unpack_input(b64blob: str) -> (bytes, bytes, bytes):
    """Розпаковує base64 blob на сіль, nonce та шифртекст."""
    data = base64.b64decode(b64blob)
    if len(data) < SALT_LEN + NONCE_LEN:
        raise ValueError("Некоректний формат BLOB: занадто короткий.")
        
    salt = data[:SALT_LEN]
    nonce = data[SALT_LEN:SALT_LEN + NONCE_LEN]
    ct = data[SALT_LEN + NONCE_LEN:]
    return salt, nonce, ct

# --- Потоки шифрування/розшифрування ---

def encrypt_message_flow(personal_source: str, message: str) -> str:
    """Потік шифрування текстового повідомлення."""
    salt = os.urandom(SALT_LEN)
    key = derive_key_from_personal(personal_source, salt)
    nonce, ct = encrypt_bytes(key, message.encode('utf-8'))
    return pack_output(salt, nonce, ct)

def decrypt_message_flow(personal_source: str, b64blob: str) -> str:
    """Потік розшифрування текстового повідомлення."""
    salt, nonce, ct = unpack_input(b64blob)
    key = derive_key_from_personal(personal_source, salt)
    pt = decrypt_bytes(key, nonce, ct)
    return pt.decode('utf-8')

def encrypt_file_flow(personal_source: str, in_path: str, out_path: str):
    """Потік шифрування файлу."""
    with open(in_path, 'rb') as f:
        data = f.read()
    if not data:
        raise ValueError("Вхідний файл порожній. Шифрування неможливе.")
        
    salt = os.urandom(SALT_LEN)
    key = derive_key_from_personal(personal_source, salt)
    nonce, ct = encrypt_bytes(key, data)
    b64 = pack_output(salt, nonce, ct)
    with open(out_path, 'w') as f:
        f.write(b64)

def decrypt_file_flow(personal_source: str, in_path: str, out_path: str):
    """Потік розшифрування файлу."""
    if not os.path.exists(in_path):
        raise FileNotFoundError(f"Вхідний файл {in_path} не знайдено.")
        
    with open(in_path, 'r') as f:
        b64 = f.read().strip()
        
    salt, nonce, ct = unpack_input(b64)
    key = derive_key_from_personal(personal_source, salt)
    pt = decrypt_bytes(key, nonce, ct)
    
    with open(out_path, 'wb') as f:
        f.write(pt)

# --- Інтерактивне меню ---

def prompt(s, default=None):
    if default:
        r = input(f"{s} [{default}]: ").strip()
        return r if r != "" else default
    else:
        r = input(f"{s}: ").strip()
        if not r:
            raise ValueError("Поле не може бути порожнім.")
        return r

def handle_encrypt_message():
    print("\n--- Шифрування повідомлення ---")
    personal = getpass("Введи секретну фразу/пароль (не буде відображатися): ").strip()
    message = prompt("Введи повідомлення")
    if not personal:
        print("Помилка: Секретна фраза не може бути порожньою.")
        return
    try:
        blob = encrypt_message_flow(personal, message)
        print("\n=== УСПІХ: Зашифрований BLOB (передай отримувачу) ===")
        print(blob)
        print("\nПримітка: Отримувач повинен використати ТУ САМУ секретну фразу.")
    except Exception as e:
        print(f"Помилка шифрування: {e}")

def handle_decrypt_message():
    print("\n--- Розшифрування повідомлення ---")
    personal = getpass("Введи секретну фразу/пароль (не буде відображатися): ").strip()
    blob = prompt("Вставте отриманий base64 BLOB")
    if not personal:
        print("Помилка: Секретна фраза не може бути порожньою.")
        return
    try:
        pt = decrypt_message_flow(personal, blob)
        print("\n=== УСПІХ: Розшифрований текст ===")
        print(pt)
    except InvalidTag:
        print("\n!!! ПОМИЛКА: Неправильний пароль або пошкоджений BLOB.")
        print("Тег автентифікації GCM не співпав. Дані були змінені або ключ невірний.")
    except Exception as e:
        print(f"Помилка розшифрування: {e}")

def handle_encrypt_file():
    print("\n--- Шифрування файлу ---")
    personal = getpass("Введи секретну фразу/пароль (не буде відображатися): ").strip()
    in_path = prompt("Шлях до вхідного файлу (який потрібно зашифрувати)")
    out_path = prompt("Шлях для збереження зашифрованого файлу", default=in_path + ".enc")
    if not personal:
        print("Помилка: Секретна фраза не може бути порожньою.")
        return
    try:
        encrypt_file_flow(personal, in_path, out_path)
        print(f"\n=== УСПІХ: Файл зашифровано → {out_path} (вміст — base64 BLOB) ===")
    except Exception as e:
        print(f"Помилка шифрування файлу: {e}")

def handle_decrypt_file():
    print("\n--- Розшифрування файлу ---")
    personal = getpass("Введи секретну фразу/пароль (не буде відображатися): ").strip()
    in_path = prompt("Шлях до зашифрованого файлу (.enc)")
    
    # Визначаємо шлях для збереження розшифрованого файлу
    default_out_path = os.path.splitext(in_path)[0]
    if default_out_path.endswith('.enc'): # Запобігаємо подвійному розширенню
        default_out_path = os.path.splitext(default_out_path)[0]
    out_path = prompt("Шлях для збереження розшифрованого файлу", default=default_out_path + ".dec")
    
    if not personal:
        print("Помилка: Секретна фраза не може бути порожньою.")
        return
    try:
        decrypt_file_flow(personal, in_path, out_path)
        print(f"\n=== УСПІХ: Файл розшифровано → {out_path} ===")
    except InvalidTag:
        print("\n!!! ПОМИЛКА: Неправильний пароль або пошкоджений файл.")
        print("Тег автентифікації GCM не співпав. Дані були змінені або ключ невірний.")
    except Exception as e:
        print(f"Помилка розшифрування файлу: {e}")

def main():
    print("=== AES-GCM Шифратор (Лабораторна робота №5) ===")
    
    while True:
        try:
            print("\nОберіть дію:")
            print("1) Зашифрувати текстове повідомлення")
            print("2) Розшифрувати текстове повідомлення (BLOB)")
            print("3) Зашифрувати файл")
            print("4) Розшифрувати файл")
            print("5) Вихід")
            
            choice = input("Номер опції: ").strip()
            
            if choice == '1':
                handle_encrypt_message()
            elif choice == '2':
                handle_decrypt_message()
            elif choice == '3':
                handle_encrypt_file()
            elif choice == '4':
                handle_decrypt_file()
            elif choice == '5':
                print("Вихід.")
                break
            else:
                print("Невірна опція. Спробуйте ще раз (1-5).")
        except KeyboardInterrupt:
            print("\nОперацію скасовано. Вихід.")
            break
        except Exception as e:
            print(f"\nНепередбачена помилка: {e}")

if __name__ == "__main__":
    main()