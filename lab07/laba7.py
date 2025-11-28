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
import sys 
from cryptography.exceptions import InvalidTag 
from Crypto.Hash import SHA256 

# ----------------- Конфігурація -----------------
PBKDF2_ITERS = 200_000
KEY_LEN = 32 # AES-256
SALT_LEN = 16
NONCE_LEN = 12 # для GCM
AES_TAG_LEN = 16 # Тег автентифікації GCM

# ----------------- Аналітика -----------------
class Analytics:
    """Клас для збору метрик часу та розміру файлів."""
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
        """Зберігає зібрані метрики у CSV."""
        df = pd.DataFrame(self.rows)
        if df.empty:
            print("Попередження: Жодних даних для збереження.")
            return
        df.to_csv(path, index=False)

    def plot(self, prefix):
        """Генерує графіки та зберігає їх у PNG."""
        df = pd.DataFrame(self.rows)
        if df.empty:
            return

        # Час виконання
        plt.figure(figsize=(10, 5))
        df_time = df.groupby('step')['time_s'].sum()
        df_time.plot(kind='bar', title='Час виконання кроків', rot=45)
        plt.ylabel('Час (секунди)')
        plt.xlabel('Крок')
        plt.tight_layout()
        plt.savefig(f"{prefix}_time.png")
        plt.close()

        # Розміри файлів (Тільки ті, що мають сенс як вхід/вихід)
        df_sizes = df.set_index('step')[['input_size','output_size']]
        plt.figure(figsize=(10, 5))
        df_sizes.plot(kind='bar', title='Розмір до/після кроків', rot=45)
        plt.ylabel('Розмір (байти)')
        plt.xlabel('Крок')
        plt.tight_layout()
        plt.savefig(f"{prefix}_sizes.png")
        plt.close()

# ----------------- AES-GCM -----------------
def derive_key(password: str, salt: bytes) -> bytes:
    """Використовує PBKDF2 для створення ключа з пароля та солі."""
    return PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_LEN, count=PBKDF2_ITERS,
                  hmac_hash_module=SHA256)

def aes_gcm_encrypt(data: bytes, password: str):
    """Шифрування даних за допомогою AES-256-GCM."""
    salt = get_random_bytes(SALT_LEN)
    key = derive_key(password, salt)
    nonce = get_random_bytes(NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # Порядок: [Salt] + [Nonce] + [Tag] + [Ciphertext]
    return salt + nonce + tag + ciphertext

def aes_gcm_decrypt(blob: bytes, password: str):
    """Розшифрування даних за допомогою AES-256-GCM."""
    if len(blob) < SALT_LEN + NONCE_LEN + AES_TAG_LEN:
        raise ValueError("BLOB занадто короткий для розшифрування.")
        
    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN:SALT_LEN+NONCE_LEN]
    tag = blob[SALT_LEN+NONCE_LEN:SALT_LEN+NONCE_LEN+AES_TAG_LEN]
    ciphertext = blob[SALT_LEN+NONCE_LEN+AES_TAG_LEN:]
    
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    # Використовуємо decrypt_and_verify для перевірки GCM тегу
    return cipher.decrypt_and_verify(ciphertext, tag)

# ----------------- LSB стеганографія -----------------
def bytes_to_bits(data: bytes):
    """Перетворює байти на масив бітів (0 або 1)."""
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))

def bits_to_bytes(bits: np.ndarray):
    """Перетворює масив бітів на байти."""
    # Переконаємось, що довжина кратна 8
    if len(bits) % 8 != 0:
         # Це не повинно траплятися, але як захист
        raise ValueError("Кількість бітів не кратна 8.")
        
    return np.packbits(bits).tobytes()

def embed_in_image(cover_path: str, data: bytes, out_path: str):
    """Вбудовує дані у зображення-обкладинку LSB-методом."""
    img = Image.open(cover_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    
    # Створюємо копію масиву, щоб уникнути зміни вихідного зображення в пам'яті
    arr = np.array(img, dtype=np.uint8, copy=True) 
    h, w, c = arr.shape
    capacity = h * w * c # Загальна кількість каналів (бітів)
    
    header = struct.pack('<Q', len(data)) # 8 байт (64 біти) для довжини даних
    payload = header + data
    bits = bytes_to_bits(payload).astype(np.uint8) 

    if bits.size > capacity:
        raise ValueError(f"Недостатньо місця у зображенні ({capacity} біт) для приховання файлу ({bits.size} біт).")
    
    flat = arr.flatten()
    
    # Вбудовування бітів даних у LSB
    # flat[:bits.size] & 254: Обнуляємо LSB пікселів
    # | bits: Встановлюємо LSB на біт даних
    flat[:bits.size] = (flat[:bits.size] & 254) | bits 
    
    arr2 = flat.reshape(arr.shape)
    # Важливо: Збереження у форматі PNG є критичним, оскільки він стискає без втрат, 
    # зберігаючи точність пікселів.
    Image.fromarray(arr2.astype(np.uint8)).save(out_path, format='PNG')

def extract_from_image(stego_path: str):
    """Витягує приховані дані із стего-зображення."""
    img = Image.open(stego_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
        
    arr = np.array(img).flatten()
    
    # 1. Читаємо заголовок (64 біти = 8 байти)
    header_bits = arr[:64] & 1 # Витягуємо LSB перших 64 пікселів/каналів
    header_bytes = bits_to_bytes(header_bits)
    data_len = struct.unpack('<Q', header_bytes)[0]
    
    # 2. Визначаємо загальну кількість бітів для витягування
    total_bits = (8 + data_len) * 8 # Заголовок (8Б) + Дані (data_len Б)
    
    if total_bits > len(arr):
        raise ValueError("Зображення занадто мале або заголовок пошкоджено. Неможливо витягти дані.")
        
    # 3. Витягуємо всі біти payload (заголовок + дані)
    bits = arr[:total_bits] & 1
    payload = bits_to_bytes(bits)
    
    # Повертаємо тільки фактичні дані (після 8-байтового заголовка)
    return payload[8:8+data_len]

# ----------------- Основні функції -----------------
def encrypt_file(input_file, cover_image, password, stego_out, analytics):
    """Головний потік шифрування та вбудовування."""
    print(f"\n[КРОК 1/3] Читання {input_file}...")
    try:
        t0 = time.perf_counter()
        with open(input_file, 'rb') as f:
            data = f.read()
        t1 = time.perf_counter()
        analytics.record("read_input", input_file, input_file, t1-t0, len(data), len(data))
    except FileNotFoundError:
        raise FileNotFoundError(f"Вхідний файл '{input_file}' не знайдено.")

    print(f"[КРОК 2/3] Шифрування {len(data)} байт AES-GCM...")
    t0 = time.perf_counter()
    encrypted = aes_gcm_encrypt(data, password)
    t1 = time.perf_counter()
    analytics.record("encrypt_aes", input_file, "encrypted_data", t1-t0, len(data), len(encrypted))

    print(f"[КРОК 3/3] Вбудовування {len(encrypted)} байт у {cover_image}...")
    t0 = time.perf_counter()
    embed_in_image(cover_image, encrypted, stego_out)
    t1 = time.perf_counter()
    
    try:
        cover_size = os.path.getsize(cover_image)
    except FileNotFoundError:
        cover_size = -1 # Якщо файл-обкладинка не існує (хоча має бути)
    
    analytics.record("embed_lsb", cover_image, stego_out, t1-t0, cover_size, os.path.getsize(stego_out))
    
    print("Шифрування та вбудовування завершено.")


def decrypt_file(stego_file, password, recovered_out, analytics):
    """Головний потік витягування та розшифрування."""
    print(f"\n[КРОК 1/3] Витягування даних із {stego_file}...")
    try:
        t0 = time.perf_counter()
        encrypted = extract_from_image(stego_file)
        t1 = time.perf_counter()
        analytics.record("extract_lsb", stego_file, "extracted_data", t1-t0, 
                         os.path.getsize(stego_file), len(encrypted))
    except FileNotFoundError:
        raise FileNotFoundError(f"Стего-файл '{stego_file}' не знайдено.")
    except Exception as e:
        raise Exception(f"Помилка витягування стего-даних: {e}")

    print(f"[КРОК 2/3] Розшифрування {len(encrypted)} байт AES-GCM...")
    try:
        t0 = time.perf_counter()
        decrypted = aes_gcm_decrypt(encrypted, password)
        t1 = time.perf_counter()
        analytics.record("decrypt_aes", "extracted_data", recovered_out, t1-t0, len(encrypted), len(decrypted))
    except ValueError as e:
        if "mac check failed" in str(e).lower() or "cipher.decrypt_and_verify" in str(e).lower():
             # PyCryptodome не має InvalidTag, але помилка Mac check failed signalizuє те саме
            raise Exception("ПОМИЛКА GCM: Неправильний пароль або дані пошкоджені (Mac check failed).")
        raise e
    except Exception as e:
        raise Exception(f"Помилка розшифрування: {e}")


    print(f"[КРОК 3/3] Збереження відновленого файлу у {recovered_out}...")
    t0 = time.perf_counter()
    with open(recovered_out, 'wb') as f:
        f.write(decrypted)
    t1 = time.perf_counter()
    analytics.record("write_output", recovered_out, recovered_out, t1-t0, len(decrypted), len(decrypted))
    
    print("Витягування та розшифрування завершено.")


# ----------------- Інтерактивна логіка -----------------
def main():
    """Основна інтерактивна функція для демонстрації."""
    print("=== Двоетапний захист файлу (Стеганографія + Шифрування) ===")
    
    try:
        input_file = input("1. Файл для захисту: ").strip()
        cover_image = input("2. Обкладинка (PNG, достатньо велика): ").strip()
        stego_out = input("3. Зберегти зашифрований BLOB у (наприклад, stego.png): ").strip()
        password = input("4. Пароль для шифрування: ").strip()
        
        if not all([input_file, cover_image, stego_out, password]):
            print("Помилка: Усі поля мають бути заповнені.")
            return

        analytics = Analytics()
        
        # --- ФАЗА ШИФРУВАННЯ ТА ВБУДОВУВАННЯ ---
        encrypt_file(input_file, cover_image, password, stego_out, analytics)
        print(f"\n>>> УСПІХ: Файл захищено та збережено у {stego_out}")

        # --- ФАЗА ВИЯВЛЕННЯ ТА РОЗШИФРУВАННЯ ---
        recovered_out = input("\n5. Введіть шлях для відновленого файлу (наприклад, recovered.txt): ").strip()
        if not recovered_out:
            print("Помилка: Шлях для відновленого файлу не може бути порожнім.")
            return
            
        decrypt_file(stego_out, password, recovered_out, analytics)
        print(f">>> УСПІХ: Файл відновлено: {recovered_out}")
        
        # --- ФАЗА АНАЛІТИКИ ---
        metrics_csv = "metrics_interactive.csv"
        analytics.to_csv(metrics_csv)
        analytics.plot("metrics_interactive")
        print(f"\n--- АНАЛІТИКА ---")
        print(f"Метрики збережено у {metrics_csv}")
        print("Графіки часу та розмірів: metrics_interactive_time.png та metrics_interactive_sizes.png")
        
        # --- ПЕРЕВІРКА ЦІЛІСНОСТІ ---
        print("\n--- ПЕРЕВІРКА ЦІЛІСНОСТІ ---")
        with open(input_file, 'rb') as f:
            orig = f.read()
        with open(recovered_out, 'rb') as f:
            rec = f.read()
        
        print("Цілісність файлу:", "OK (Файли ідентичні)" if orig == rec else "ПОМИЛКА (Файли відрізняються)")
        
    except FileNotFoundError as e:
        print(f"\n!!! КРИТИЧНА ПОМИЛКА: {e}")
    except ValueError as e:
        print(f"\n!!! КРИТИЧНА ПОМИЛКА ДАНИХ: {e}")
    except Exception as e:
        print(f"\n!!! КРИТИЧНА ПОМИЛКА: {e}")
    
if __name__ == "__main__":
    main()