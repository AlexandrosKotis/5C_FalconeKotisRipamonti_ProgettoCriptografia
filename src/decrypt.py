from cryptography.fernet import Fernet
import base64
import itertools
import time

# Step 1: Declare a simple secret message
secret_message = b"8Ho3dOuByFUJYnRKGJyc6y09jnIEbjrLN9JXwKDiuDcYP4GJAcVRGDDvgnIS1egRXfP8uKUpUiZV4xSzDkoniwy1g54GDwmzgvTaPKjWrUxudGXDpSgol"  # A simple message

# Step 2: Encrypt the message with Fernet
# Generate a valid Fernet key
key = Fernet.generate_key()
fernet = Fernet(key)
encrypted_message = fernet.encrypt(secret_message)

# Print the encrypted message and the key used
print(f"Encrypted Message: {encrypted_message}")
print(f"Original Key (for reference): {key.decode()}")

# Step 5: Calculate the maximum number of attempts
character_set = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"  # Character set for testing
key_length = 4  # Short key length for faster brute-forcing
max_tries = len(character_set) ** key_length
print(f"Maximum number of attempts: {max_tries}")

# Step 3: Attempt to brute-force the key
found = False
attempts = 0
start_time = time.time()

def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    try:
        decrypted_message = fernet.decrypt(encrypted_message)
        return decrypted_message
    except Exception:
        return None

def generate_keys(character_set, key_length):
    for key_tuple in itertools.product(character_set, repeat=key_length):
        # Create a key from the character tuple
        key = ''.join(key_tuple).encode('utf-8')
        # Pad the key to 32 bytes and then base64 encode it
        padded_key = key.ljust(32, b'\0')  # Pad with null bytes
        # Base64 encode and ensure it's valid
        yield base64.urlsafe_b64encode(padded_key)

for key in generate_keys(character_set, key_length):
    # Ensure the key is exactly 44 bytes long after encoding
    if len(key) != 44:  # Base64-encoded keys are always 44 bytes long
        continue

    decrypted_message = decrypt_message(encrypted_message, key)
    attempts += 1

    # Step 4: Print status every 10,000 attempts
    if attempts % 10000 == 0:
        elapsed_time = time.time() - start_time
        print(f"Attempts: {attempts}, Time Elapsed: {elapsed_time:.2f} seconds")

    if decrypted_message is not None:
        print(f"Key found: {key.decode()}")
        print(f"Decrypted message: {decrypted_message.decode()}")
        found = True
        break

if not found: