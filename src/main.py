from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os
import itertools

#Apertura del file
def read_file(file_path):
    with open(file_path, 'r') as file:
        return "".join(file.readlines())


#Generazione della chiave
def generate_key():
    return os.urandom(16)


#Criptografia ECB
def encrypt_ecb(text, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_text = padder.update(text.encode()) + padder.finalize()
    return encryptor.update(padded_text) + encryptor.finalize()


#Crittografia CBC
def encrypt_cbc(text, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_text = padder.update(text.encode()) + padder.finalize()
    return encryptor.update(padded_text) + encryptor.finalize()


#Decrittazione con ECB
def decrypt_ecb(ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    return unpadder.update(decrypted_padded) + unpadder.finalize()


#Decrittazione con CBC
def decrypt_cbc(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    return unpadder.update(decrypted_padded) + unpadder.finalize()


#Funzione per generare tutte le chiavi possibili di lunghezza n
def generate_any_key(max_length):
    alphabet = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
    li = []
    for i in itertools.product(alphabet, repeat=max_length):
        li.append(''.join(i))
    return li


FILE_PATH = "text.txt"
ORIGINAL_TEXT = read_file(FILE_PATH).upper() #Rendo la stringa in maiuscolo per facilitare la decrittazione

toRemove = [",", ":", ".", ";", "-", "_"]

for char in toRemove:
    ORIGINAL_TEXT = ORIGINAL_TEXT.replace(char, "") #Rimuovo tutte le occorrenze di ogni carattere per una migliore crittazione


print("Initial text:\n", ORIGINAL_TEXT)

KEY = generate_key()
IV = generate_key()

ENCRYPTED_TEXT_ECB = encrypt_ecb(ORIGINAL_TEXT, KEY)
print("Encrypted file (ECB):\n", ENCRYPTED_TEXT_ECB)

ENCRYPTED_TEXT_CBC = encrypt_cbc(ORIGINAL_TEXT, KEY, IV)
print("Encrypted file (CBC):\n", ENCRYPTED_TEXT_CBC)

DECRYPTED_TEXT_ECB = decrypt_ecb(ENCRYPTED_TEXT_ECB, KEY).decode()
print("Decrypted file (ECB):\n", DECRYPTED_TEXT_ECB)

DECRYPTED_TEXT_CBC = decrypt_cbc(ENCRYPTED_TEXT_CBC, KEY, IV).decode()
print("Decrypted file (CBC):\n", DECRYPTED_TEXT_CBC)

KEY_CHARACTERS = 32
poss = generate_any_key(KEY_CHARACTERS)
print(f"All key possbile{poss}")