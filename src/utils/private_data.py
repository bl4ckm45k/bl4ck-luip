import base64
import hashlib
import logging

from Crypto.Cipher import AES

from loader import config

key = hashlib.sha256(config.settings.secret_key.encode()).digest()

def encrypt_password(password: str) -> str:
    """Шифрует пароль с использованием AES-GCM"""
    cipher = AES.new(key, AES.MODE_GCM)  # Создаем шифратор
    ciphertext, tag = cipher.encrypt_and_digest(password.encode())  # Шифруем и создаем тег аутентификации
    encrypted_data = cipher.nonce + tag + ciphertext  # Склеиваем все компоненты
    return base64.urlsafe_b64encode(encrypted_data).decode()  # Кодируем в Base64


def decrypt_password(encrypted_password: str) -> str:
    """Расшифровывает пароль с использованием AES-GCM"""
    try:
        encrypted_data = base64.urlsafe_b64decode(encrypted_password.encode())  # Декодируем из Base64
        nonce = encrypted_data[:16]  # Первые 16 байт — это nonce
        tag = encrypted_data[16:32]  # Следующие 16 байт — это тег
        ciphertext = encrypted_data[32:]  # Остальное — зашифрованные данные

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)  # Воссоздаем шифратор
        return cipher.decrypt_and_verify(ciphertext, tag).decode()  # Расшифровываем и проверяем подлинность
    except AttributeError:
        return ''
    except ValueError as e:
        if "MAC check failed" == str(e):
            raise ValueError(f"MAC check failed: Maybe you change secret key?")
        logging.error(f'', exc_info=True)
        raise e
