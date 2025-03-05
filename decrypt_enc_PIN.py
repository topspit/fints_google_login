from Crypto.Cipher import AES
import base64
import os

SECRET_KEY = os.getenv("FIRESTORE_ENCRYPTION_KEY")  # Muss 32 Byte lang sein
# Auffüllen mit 'a' bis 32 Bytes, aber auch Abschneiden, falls der Key länger ist
SECRET_KEY = SECRET_KEY.ljust(32, 'a')[:32]

def pad(s):
    """Padding für die Verschlüsselung, da AES Blockgröße 16 ist"""
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

def unpad(s):
    """Padding entfernen nach Entschlüsselung"""
    return s[:-ord(s[-1])]

def encrypt_pin(pin):
    """Verschlüsselt die PIN mit AES"""
    cipher = AES.new(SECRET_KEY.encode(), AES.MODE_ECB)
    encrypted_bytes = cipher.encrypt(pad(pin).encode())
    return base64.b64encode(encrypted_bytes).decode()

def decrypt_pin(encrypted_pin):
    """Entschlüsselt die PIN"""
    cipher = AES.new(SECRET_KEY.encode(), AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(base64.b64decode(encrypted_pin))
    return unpad(decrypted_bytes.decode())