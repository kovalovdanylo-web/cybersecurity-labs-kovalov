import argparse
import base64
import os
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Параметри KDF
KDF_ITERATIONS = 200_000
KEY_LEN = 32  # 256-bit AES

def derive_key_from_personal(personal_string: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(personal_string.encode('utf-8'))

def encrypt_bytes(key: bytes, plaintext: bytes) -> (bytes, bytes, bytes):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)  
    
    return nonce, ct

def decrypt_bytes(key: bytes, nonce: bytes, ct: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, associated_data=None)

def pack_output(salt: bytes, nonce: bytes, ct: bytes) -> str:
    blob = salt + nonce + ct
    return base64.b64encode(blob).decode('utf-8')

def unpack_input(b64blob: str) -> (bytes, bytes, bytes):
    data = base64.b64decode(b64blob)
    salt = data[:16]
    nonce = data[16:28]
    ct = data[28:]
    return salt, nonce, ct

def encrypt_message_flow(personal_source: str, message: str) -> str:
    salt = os.urandom(16)
    key = derive_key_from_personal(personal_source, salt)
    nonce, ct = encrypt_bytes(key, message.encode('utf-8'))
    return pack_output(salt, nonce, ct)

def decrypt_message_flow(personal_source: str, b64blob: str) -> str:
    salt, nonce, ct = unpack_input(b64blob)
    key = derive_key_from_personal(personal_source, salt)
    pt = decrypt_bytes(key, nonce, ct)
    return pt.decode('utf-8')

def encrypt_file_flow(personal_source: str, in_path: str, out_path: str):
    with open(in_path, 'rb') as f:
        data = f.read()
    salt = os.urandom(16)
    key = derive_key_from_personal(personal_source, salt)
    nonce, ct = encrypt_bytes(key, data)
    b64 = pack_output(salt, nonce, ct)
    with open(out_path, 'w') as f:
        f.write(b64)

def decrypt_file_flow(personal_source: str, in_path: str, out_path: str):
    with open(in_path, 'r') as f:
        b64 = f.read().strip()
    salt, nonce, ct = unpack_input(b64)
    key = derive_key_from_personal(personal_source, salt)
    pt = decrypt_bytes(key, nonce, ct)
    with open(out_path, 'wb') as f:
        f.write(pt)

def main():
    parser = argparse.ArgumentParser(description="Простий Email-шифратор (симетричний AES-GCM).")
    sub = parser.add_subparsers(dest='cmd')

    e_msg = sub.add_parser('enc-msg', help='Зашифрувати текстове повідомлення')
    e_msg.add_argument('--personal', help='Персональні дані (наприклад: IvanPetrenko1995). Якщо не вказано — запитаєте.', required=False)

    d_msg = sub.add_parser('dec-msg', help='Розшифрувати текстове повідомлення (base64 blob)')
    d_msg.add_argument('--personal', help='Персональні дані', required=False)
    d_msg.add_argument('--blob', help='base64 blob (salt+nonce+ct)', required=False)

    e_file = sub.add_parser('enc-file', help='Зашифрувати файл')
    e_file.add_argument('infile')
    e_file.add_argument('outfile')
    e_file.add_argument('--personal', help='Персональні дані', required=False)

    d_file = sub.add_parser('dec-file', help='Розшифрувати файл')
    d_file.add_argument('infile')
    d_file.add_argument('outfile')
    d_file.add_argument('--personal', help='Персональні дані', required=False)

    args = parser.parse_args()

    if args.cmd == 'enc-msg':
        personal = args.personal or input("Введи персональні дані для генерації ключа (наприклад Name+DOB або пароль): ").strip()
        message = input("Введи повідомлення: ")
        blob = encrypt_message_flow(personal, message)
        print("\nЗашифрований blob (відправити отримувачу):\n")
        print(blob)
        print("\n---\nОтримувач розшифрує цей blob, знаючи ті самі персональні дані та отримавши blob.")
    elif args.cmd == 'dec-msg':
        personal = args.personal or input("Введи персональні дані (те саме, що використовував відправник): ").strip()
        blob = args.blob or input("Вставте отриманий base64 blob: ").strip()
        try:
            pt = decrypt_message_flow(personal, blob)
            print("\nРозшифрований текст:\n")
            print(pt)
        except Exception as e:
            print("Помилка розшифрування:", e)
    elif args.cmd == 'enc-file':
        personal = args.personal or input("Введи персональні дані: ").strip()
        encrypt_file_flow(personal, args.infile, args.outfile)
        print(f"Файл зашифровано → {args.outfile} (вміст — base64 blob)")
    elif args.cmd == 'dec-file':
        personal = args.personal or input("Введи персональні дані: ").strip()
        try:
            decrypt_file_flow(personal, args.infile, args.outfile)
            print(f"Файл розшифровано → {args.outfile}")
        except Exception as e:
            print("Помилка розшифрування:", e)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
