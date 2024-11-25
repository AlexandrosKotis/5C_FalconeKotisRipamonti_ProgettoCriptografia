from cryptography.fernet import Fernet
import base64
import itertools
import time

# Step 1: Dichiarare un messaggio segreto semplice
secret_message = b"8Ho3dOuByFUJYnRKGJyc6y09jnIEbjrLN9JXwKDiuDcYP4GJAcVRGDDvgnIS1egRXfP8uKUpUiZV4xSzDkoniwy1g54GDwmzgvTaPKjWrUxudGXDpSgol"  

# Step 2: Cifrare il messaggio con Fernet
# Generare una chiave valida Fernet
key = Fernet.generate_key()
fernet = Fernet(key)
encrypted_message = fernet.encrypt(secret_message)

# Stampare il messaggio cifrato e la chiave usata
print(f"Encrypted Message: {encrypted_message}")
print(f"Original Key (for reference): {key.decode()}")

# Step 5: Calcolare il numero massimo di tentativi
character_set = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"  # Set di caratteri
key_length = 4  # Lunghezza breve della chiave per testare il brute-forcing
max_tries = len(character_set) ** key_length
print(f"Maximum number of attempts: {max_tries}")

# Funzione per decifrare un messaggio
def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    try:
        decrypted_message = fernet.decrypt(encrypted_message)
        return decrypted_message
    except Exception:
        return None

# Genera tutte le possibili chiavi basate su character_set e key_length
def generate_keys(character_set, key_length):
    for key_tuple in itertools.product(character_set, repeat=key_length):
        # Crea una chiave a partire dalla tupla di caratteri
        key = ''.join(key_tuple).encode('utf-8')
        # Riempi la chiave fino a 32 byte con null byte e codifica in Base64
        padded_key = key.ljust(32, b'\0')  # Riempi con byte null
        # Codifica in Base64 e assicurati che sia valida
        yield base64.urlsafe_b64encode(padded_key)

# Step 3: Tentativo di brute-force per trovare la chiave
found = False
attempts = 0
start_time = time.time()

for key in generate_keys(character_set, key_length):
    # Assicurarsi che la chiave abbia esattamente 44 byte dopo la codifica
    if len(key) != 44:  # Le chiavi codificate in Base64 sono sempre di 44 byte
        continue

    decrypted_message = decrypt_message(encrypted_message, key)
    attempts += 1

    # Step 4: Stampare lo stato ogni 10.000 tentativi
    if attempts % 10000 == 0:
        elapsed_time = time.time() - start_time
        print(f"Attempts: {attempts}, Time Elapsed: {elapsed_time:.2f} seconds")

    if decrypted_message is not None:
        print(f"Key found: {key.decode()}")
        print(f"Decrypted message: {decrypted_message.decode()}")
        found = True
        break

# Step 6: Stampare il riepilogo finale
end_time = time.time()
elapsed_time = end_time - start_time

if not found:
    print("Failed to find the key within the specified range.")
    print(f"Brute force failed after {attempts} attempts and {elapsed_time:.2f} seconds.")
else:
    print(f"Brute force successful in {attempts} attempts and {elapsed_time:.2f} seconds.")
