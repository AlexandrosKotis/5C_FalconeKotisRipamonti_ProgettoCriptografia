from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import os

# Funzione per aggiungere padding al testo
# Aggiunge padding al testo per garantire che la sua lunghezza sia un multiplo della dimensione del blocco (128 bit).
# @param text (bytes) Il testo in chiaro da criptare.
# @return (bytes) Testo in chiaro con il padding applicato.
def add_padding(text):
    padder = padding.PKCS7(128).padder()
    return padder.update(text) + padder.finalize()

# Funzione per rimuovere il padding dal testo
# Rimuove il padding da un testo precedentemente criptato e decifrato.
# @param padded_text (bytes) Testo con padding da rimuovere.
# @return (bytes) Testo senza padding.
def remove_padding(padded_text):
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_text) + unpadder.finalize()

# Decrittazione AES con ECB
# Decifra il testo cifrato utilizzando l'algoritmo AES in modalità ECB.
# @param key (bytes) La chiave di decrittazione AES (16 byte per AES-128).
# @param ciphertext (bytes) Il testo cifrato da decifrare.
# @return (bytes) Testo in chiaro decifrato.
def decrypt_ecb(key, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return remove_padding(padded_plaintext)

# Decrittazione AES con CBC
# Decifra il testo cifrato utilizzando l'algoritmo AES in modalità CBC.
# @param key (bytes) La chiave di decrittazione AES (16 byte per AES-128).
# @param iv (bytes) Il vettore di inizializzazione (16 byte).
# @param ciphertext (bytes) Il testo cifrato da decifrare.
# @return (bytes) Testo in chiaro decifrato.
def decrypt_cbc(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return remove_padding(padded_plaintext)

# Criptazione AES con ECB
# Cripta il testo in chiaro utilizzando l'algoritmo AES in modalità ECB.
# @param key (bytes) La chiave di criptazione AES (16 byte per AES-128).
# @param plaintext (bytes) Il testo in chiaro da criptare.
# @return (bytes) Testo cifrato in modalità ECB.
def encrypt_ecb(key, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_plaintext = add_padding(plaintext)
    return encryptor.update(padded_plaintext) + encryptor.finalize()

# Criptazione AES con CBC
# Cripta il testo in chiaro utilizzando l'algoritmo AES in modalità ECB.
# @param key (bytes) La chiave di criptazione AES (16 byte per AES-128).
# @param plaintext (bytes) Il testo in chiaro da criptare.
# @return iv (bytes) Il vettore di inizializzazione (16 byte).
# @return ciphertext (bytes) Il testo cifrato in modalità CBC.
def encrypt_cbc(key, plaintext):
    iv = os.urandom(16)  # Initialization vector casuale
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_plaintext = add_padding(plaintext)
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return iv, ciphertext

# Codifica Base64
# Converte dati binari in formato Base64 per rappresentazione testuale.
# @param data (bytes) Dati binari da convertire.
# @return (str) Dati codificati in Base64 come stringa.
def to_base64(data):
    return base64.b64encode(data).decode()

# Decodifica Base64
# Decodifica dati Base64 in formato binario originale.
# @param data (str) Stringa codificata in Base64.
# @return (bytes) Dati binari originali.
def from_base64(data):
    return base64.b64decode(data)

# Punto di ingresso del programma.
# Genera una chiave AES casuale, cifra un messaggio in modalità ECB e CBC, 
# e stampa i risultati in formato Base64.





if __name__ == "__main__":
    key = os.urandom(16)  # Chiave AES a 128 bit

    # Testo con ripetizioni
    with open("/home/trustypixel/Scuola/Sistemi/Laboratorio/Progetti/Progetto_Criptografia/5C_FalconeKotisRipamonti_ProgettoCriptografia/src/testo.txt", "r") as file:
        data = "".join(file.readlines())
    data = bytes(data, "utf8")

    # ECB
    text = "\n--------------------------------------\n"
    ciphertext_ecb = encrypt_ecb(key, data)
    text += "ECB Base64:" + to_base64(ciphertext_ecb)

    text += "\n"

    # Decrittazione ECB
    decrypted_ecb = decrypt_ecb(key, ciphertext_ecb)
    text += "ECB Decifrato:" + decrypted_ecb.decode()

    text += "\n--------------------------------------\n"
    
    # CBC
    iv, ciphertext_cbc = encrypt_cbc(key, data)
    text += "CBC Base64:" + to_base64(iv + ciphertext_cbc)

    text += "\n"

    decrypted_cbc = decrypt_cbc(key, iv, ciphertext_cbc)
    text += "CBC Decifrato:" + decrypted_cbc.decode()

    text += "\n--------------------------------------\n"

    file = open("/home/trustypixel/Scuola/Sistemi/Laboratorio/Progetti/Progetto_Criptografia/5C_FalconeKotisRipamonti_ProgettoCriptografia/src/scritto.txt", "w")
    file.write(text)
    file.close()

    
    
