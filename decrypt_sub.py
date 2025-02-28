import subprocess

def decrypt_file(encrypted_file, decrypted_file, password):
    # Der OpenSSL-Befehl zur Entschlüsselung
    command = [
        "openssl", 
        "enc", 
        "-aes-256-cbc", 
        "-d",  # Entschlüsselung
        "-salt", 
        "-pbkdf2", 
        "-in", encrypted_file, 
        "-out", decrypted_file, 
        "-pass", f"pass:{password}"
    ]

    # Führe den OpenSSL-Befehl aus
    try:
        subprocess.run(command, check=True)
        print(f"Die Datei wurde erfolgreich entschlüsselt und in {decrypted_file} gespeichert.")
    except subprocess.CalledProcessError as e:
        print(f"Fehler beim Entschlüsseln der Datei: {e}")

# Beispielaufruf der Funktion

