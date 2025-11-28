from PIL import Image
import os
import sys
import math

def bytes_to_bits(b: bytes) -> str:
    return ''.join(f'{byte:08b}' for byte in b)

def bits_to_bytes(bits: str) -> bytes:
    bytelist = [bits[i:i+8] for i in range(0, len(bits) - len(bits)%8, 8)]
    return bytes(int(b, 2) for b in bytelist)

def int_to_32bits(n: int) -> str:
    return f'{n:032b}'

def bits_to_int(bits: str) -> int:
    return int(bits, 2)

def hide_message(input_path: str, output_path: str, message: str) -> dict:

    img = Image.open(input_path)
    mode = img.mode
    if mode not in ('RGB', 'RGBA'):
        img = img.convert('RGB')
        mode = 'RGB'

    width, height = img.size
    pixels = list(img.getdata())

    msg_bytes = message.encode('utf-8')
    msg_len = len(msg_bytes)
    header_bits = int_to_32bits(msg_len)  
    msg_bits = bytes_to_bits(msg_bytes)
    data_bits = header_bits + msg_bits
    total_bits = len(data_bits)

    channels_per_pixel = 3  
    capacity = width * height * channels_per_pixel

    if total_bits > capacity:
        raise ValueError(f"Недостатня ємність зображення: потрібно {total_bits} біт, доступно {capacity} біт. "
                         "Зменшіть повідомлення або візьміть інше зображення.")

    new_pixels = []
    bit_idx = 0
    changed_pixels = 0

    for px in pixels:
        channels = list(px)
        orig = channels.copy()
        for c in range(channels_per_pixel):
            if bit_idx < total_bits:
                bit = int(data_bits[bit_idx])
                channels[c] = (channels[c] & ~1) | bit  
                bit_idx += 1
            else:
                pass
        if tuple(channels[:channels_per_pixel]) != tuple(orig[:channels_per_pixel]):
            changed_pixels += 1
        if mode == 'RGBA':
            new_pixels.append((channels[0], channels[1], channels[2], channels[3]))
        else:
            new_pixels.append((channels[0], channels[1], channels[2]))

    out_img = Image.new(mode, (width, height))
    out_img.putdata(new_pixels)
    out_img.save(output_path)

    return {
        'input_path': input_path,
        'output_path': output_path,
        'width': width,
        'height': height,
        'capacity_bits': capacity,
        'used_bits': total_bits,
        'message_bytes': msg_len,
        'changed_pixels': changed_pixels
    }

def extract_message(stego_path: str) -> str:
    img = Image.open(stego_path)
    mode = img.mode
    if mode not in ('RGB', 'RGBA'):
        img = img.convert('RGB')
        mode = 'RGB'

    pixels = list(img.getdata())

    channels_per_pixel = 3
    bits = []

    for px in pixels:
        for c in range(channels_per_pixel):
            bits.append(str(px[c] & 1))

    bits_str = ''.join(bits)
    header = bits_str[:32]
    msg_len = bits_to_int(header)
    msg_bits_needed = msg_len * 8
    msg_bits = bits_str[32:32 + msg_bits_needed]

    msg_bytes = bits_to_bytes(msg_bits)
    try:
        message = msg_bytes.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        message = msg_bytes.decode('utf-8', errors='replace')
    return message

def analyze_changes(original_path: str, stego_path: str, diff_out: str = None) -> dict:

    orig = Image.open(original_path).convert('RGBA')
    stego = Image.open(stego_path).convert('RGBA')

    if orig.size != stego.size:
        raise ValueError("Розміри зображень відрізняються.")

    w, h = orig.size
    orig_px = list(orig.getdata())
    stego_px = list(stego.getdata())

    changed_pixels = 0
    total_diff = [0, 0, 0]  # R,G,B
    diff_img = Image.new('RGBA', (w, h))
    diff_data = []

    for o, s in zip(orig_px, stego_px):
        rdiff = abs(o[0] - s[0])
        gdiff = abs(o[1] - s[1])
        bdiff = abs(o[2] - s[2])
        if rdiff or gdiff or bdiff:
            changed_pixels += 1
            diff_data.append((255, 0, 0, 255))
        else:
            diff_data.append((0, 0, 0, 0))
        total_diff[0] += rdiff
        total_diff[1] += gdiff
        total_diff[2] += bdiff

    diff_img.putdata(diff_data)
    if diff_out:
        diff_img.save(diff_out)

    pixel_count = w * h
    avg_diff_per_channel = [total_diff[i] / pixel_count for i in range(3)]
    return {
        'orig_size_bytes': os.path.getsize(original_path),
        'stego_size_bytes': os.path.getsize(stego_path),
        'changed_pixels': changed_pixels,
        'avg_diff_per_channel': avg_diff_per_channel,
        'diff_image': diff_out if diff_out else None
    }

def prompt(prompt_text: str, default: str = None) -> str:
    if default:
        return input(f"{prompt_text} [{default}]: ") or default
    else:
        return input(f"{prompt_text}: ")

def main():
    print("LSB Steganography (проста реалізація) — Python + Pillow")
    print("Оберіть режим:")
    print("1) Сховати повідомлення")
    print("2) Витягти повідомлення")
    mode = prompt("Введи 1 або 2")

    if mode.strip() == '1':
        in_path = prompt("Шлях до вхідного зображення (jpg/png/ bmp ...)")
        out_path = prompt("Шлях для збереження стего-зображення", default="stego_out.png")
        print("Введи текст (повідомлення). Тільки текст (utf-8). Закінчи введення клавішею Enter.")
        msg = prompt("Повідомлення")
        try:
            stats = hide_message(in_path, out_path, msg)
            print("\n--- УСПІХ: повідомлення вбудовано ---")
            print(f"Змінено пікселів: {stats['changed_pixels']} / {stats['width'] * stats['height']}")
            print(f"Використано бітів: {stats['used_bits']} з {stats['capacity_bits']}")
            # аналіз
            diff_file = os.path.splitext(out_path)[0] + "_diff.png"
            analysis = analyze_changes(in_path, out_path, diff_out=diff_file)
            print("\n--- Аналіз змін ---")
            print(f"Розмір (оригінал): {analysis['orig_size_bytes']} байт")
            print(f"Розмір (стего): {analysis['stego_size_bytes']} байт")
            print(f"Кількість змінених пікселів: {analysis['changed_pixels']}")
            print(f"Середня абсолютна різниця на канал (R,G,B): "
                  f"{analysis['avg_diff_per_channel'][0]:.4f}, "
                  f"{analysis['avg_diff_per_channel'][1]:.4f}, "
                  f"{analysis['avg_diff_per_channel'][2]:.4f}")
            print(f"Diff-зображення збережено: {diff_file}")
            print("\nПримітка: для форматів JPEG стегозображення може бути пошкоджене через стиснення — "
                  "краще використовувати PNG/BMP (без втрат).")
        except Exception as e:
            print("Помилка:", e)

    elif mode.strip() == '2':
        in_path = prompt("Шлях до стего-зображення")
        try:
            message = extract_message(in_path)
            print("\n--- ВИТЯГНУТЕ ПОВІДОМЛЕННЯ ---")
            print(message)
        except Exception as e:
            print("Помилка при витяганні:", e)
    else:
        print("Невірна опція. Вихід.")

if __name__ == '__main__':
    main()