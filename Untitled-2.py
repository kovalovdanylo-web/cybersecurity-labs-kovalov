#!/usr/bin/env python3
"""
interactive_protect.py
Двоетапний захист: AES-GCM + LSB стеганографія.
Повністю інтерактивна версія з аналітикою.
"""

import os
import time
import struct
import numpy as np
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import pandas as pd
import matplotlib.pyplot as plt

# ----------------- Конфігурація -----------------
PBKDF2_ITERS = 200_000
KEY_LEN = 32      # AES-256
SALT_LEN = 16
NONCE_LEN = 12    # для GCM

# ----------------- Аналітика -----------------
class Analytics:
    def __init__(self):
        self.rows = []

    def record(self, step, input_path, output_path, time_s, input_size, output_size):
        self.rows.append({
            'step': step,
            'input_path': input_path,
            'output_path': output_path,
            'time_s': time_s,
            'input_size': input_size,
            'output_size': output_size
        })

    def to_csv(self, path):
        df = pd.DataFrame(self.rows)
        df.to_csv(path, index=False)

    def plot(self, prefix):
        df = pd.DataFrame(self.rows)
        if df.empty:
            return
        # Час виконання
        plt.figure()
        df.groupby('step')['time_s'].sum().plot(kind='bar', title='Час виконання кроків')
        plt.tight_layout()
        plt.savefig(f"{prefix}_time.png")
        plt.close()
        # Розміри файлів
        plt.figure()
        df.set_index('step')[['input_size','output_size']].plot(kind='bar', title='Розмір до/після кроків')
        plt.tight_layout()
        plt.savefig(f"{prefix}_sizes.png")
        plt.close()

# ----------------- AES-GCM -----------------
def derive_key(password: str, salt: bytes) -> bytes:
    from Crypto.Hash import SHA256
    return PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_LEN, count=PBKDF2_ITERS, hmac_hash_module=SHA256)

def aes_gcm_encrypt(data: bytes, password: str):
    salt = get_random_bytes(SALT_LEN)
    key = derive_key(password, salt)
    nonce = get_random_bytes(NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return salt + nonce + tag + ciphertext

def aes_gcm_decrypt(blob: bytes, password: str):
    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN:SALT_LEN+NONCE_LEN]
    tag = blob[SALT_LEN+NONCE_LEN:SALT_LEN+NONCE_LEN+16]
    ciphertext = blob[SALT_LEN+NONCE_LEN+16:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# ----------------- LSB стеганографія -----------------
def bytes_to_bits(data: bytes):
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))

def bits_to_bytes(bits: np.ndarray):
    return np.packbits(bits).tobytes()

def embed_in_image(cover_path: str, data: bytes, out_path: str):
    img = Image.open(cover_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    arr = np.array(img, dtype=np.uint8, copy=True)
    h, w, c = arr.shape
    capacity = h * w * c
    header = struct.pack('<Q', len(data))  # 8 байт заголовка
    payload = header + data
    bits = bytes_to_bits(payload).astype(np.uint8)  # <-- тип uint8
    if bits.size > capacity:
        raise ValueError("Недостатньо місця у зображенні для приховання файлу")
    flat = arr.flatten()
    flat[:bits.size] = (flat[:bits.size] & 254) | bits  # <-- безпечне & | для uint8
    arr2 = flat.reshape(arr.shape)
    Image.fromarray(arr2.astype(np.uint8)).save(out_path, format='PNG')


def extract_from_image(stego_path: str):
    img = Image.open(stego_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    arr = np.array(img).flatten()
    header_bits = arr[:64] & 1
    header_bytes = bits_to_bytes(header_bits)
    data_len = struct.unpack('<Q', header_bytes)[0]
    total_bits = (8 + data_len) * 8
    bits = arr[:total_bits] & 1
    payload = bits_to_bytes(bits)
    return payload[8:8+data_len]

# ----------------- Основні функції -----------------
def encrypt_file(input_file, cover_image, password, stego_out, analytics):
    t0 = time.perf_counter()
    with open(input_file, 'rb') as f:
        data = f.read()
    t1 = time.perf_counter()
    analytics.record("read_input", input_file, input_file, t1-t0, len(data), len(data))

    t0 = time.perf_counter()
    encrypted = aes_gcm_encrypt(data, password)
    t1 = time.perf_counter()
    analytics.record("encrypt_aes", input_file, "encrypted_data", t1-t0, len(data), len(encrypted))

    t0 = time.perf_counter()
    embed_in_image(cover_image, encrypted, stego_out)
    t1 = time.perf_counter()
    analytics.record("embed_lsb", cover_image, stego_out, t1-t0, os.path.getsize(cover_image), os.path.getsize(stego_out))

def decrypt_file(stego_file, password, recovered_out, analytics):
    t0 = time.perf_counter()
    encrypted = extract_from_image(stego_file)
    t1 = time.perf_counter()
    analytics.record("extract_lsb", stego_file, "extracted_data", t1-t0, os.path.getsize(stego_file), len(encrypted))

    t0 = time.perf_counter()
    decrypted = aes_gcm_decrypt(encrypted, password)
    t1 = time.perf_counter()
    analytics.record("decrypt_aes", "extracted_data", recovered_out, t1-t0, len(encrypted), len(decrypted))

    t0 = time.perf_counter()
    with open(recovered_out, 'wb') as f:
        f.write(decrypted)
    t1 = time.perf_counter()
    analytics.record("write_output", recovered_out, recovered_out, t1-t0, len(decrypted), len(decrypted))

# ----------------- Інтерактивна логіка -----------------
def main():
    print("=== Двоетапний захист файлу ===")
    input_file = input("Файл для захисту: ").strip()
    cover_image = input("Обкладинка PNG: ").strip()
    stego_out = input("Зберегти зашифрований файл у: ").strip()
    password = input("Пароль для шифрування: ").strip()
    analytics = Analytics()

    encrypt_file(input_file, cover_image, password, stego_out, analytics)
    print(f"\nФайл захищено і збережено у {stego_out}")

    recovered_out = input("\nВведіть шлях для відновленого файлу: ").strip()
    decrypt_file(stego_out, password, recovered_out, analytics)
    print(f"Файл відновлено: {recovered_out}")

    metrics_csv = "metrics_interactive.csv"
    analytics.to_csv(metrics_csv)
    analytics.plot("metrics_interactive")
    print(f"\nМетрики збережено у {metrics_csv}")
    print("Графіки часу та розмірів: metrics_interactive_time.png та metrics_interactive_sizes.png")

    # Перевірка цілісності
    with open(input_file, 'rb') as f:
        orig = f.read()
    with open(recovered_out, 'rb') as f:
        rec = f.read()
    print("Цілісність файлу:", "OK" if orig == rec else "ПОМИЛКА")

if __name__ == "__main__":
    main()
