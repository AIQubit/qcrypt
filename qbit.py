import os
import base64
import gzip
import io
from tqdm import tqdm
from typing import Optional
from cryptography.fernet import Fernet

def generate_key() -> bytes:
    return Fernet.generate_key()

def save_key_to_file(key: bytes, key_file_path: str) -> None:
    try:
        with open(key_file_path, 'wb') as key_file:
            key_file.write(key)
        print(f"Key saved to {key_file_path}.")
    except Exception as e:
        print(f"An error occurred while saving the key: {e}")

def encrypt_data(data: bytes, key: bytes) -> bytes:
    fernet = Fernet(key)
    return fernet.encrypt(data)

def file_to_base64(file_path: str) -> Optional[bytes]:
    try:
        with open(file_path, 'rb') as file:
            file_size = os.path.getsize(file_path)
            encoded_chunks = []
            with tqdm(total=file_size, unit='B', unit_scale=True, desc="Encoding file") as pbar:
                while True:
                    chunk = file.read(4096)
                    if not chunk:
                        break
                    encoded_chunks.append(chunk)
                    pbar.update(len(chunk))
            return b''.join(encoded_chunks)
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
    except Exception as e:
        print(f"An error occurred while encoding the file: {e}")
    return None

def base64_to_file(file_content: bytes, output_file_path: str) -> None:
    try:
        total_size = len(file_content)
        with open(output_file_path, 'wb') as file:
            with tqdm(total=total_size, unit='B', unit_scale=True, desc="Writing file") as pbar:
                for i in range(0, total_size, 4096):
                    file.write(file_content[i:i + 4096])
                    pbar.update(min(4096, total_size - i))
    except Exception as e:
        print(f"An error occurred while writing to the file: {e}")

def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data)

def compress_data(data: bytes) -> bytes:
    return gzip.compress(data)

def decompress_data(data: bytes) -> bytes:
    return gzip.decompress(data)

def main():
    file_path = input("Enter the path of the file you want to encrypt: ")

    # Validate if the file exists
    if not os.path.isfile(file_path):
        print("Error: The specified file does not exist.")
        return

    original_data = file_to_base64(file_path)

    if original_data is not None:
        num_layers = int(input("Enter the number of layers of encryption to generate: "))
        keys = []
        
        # Generate multiple keys and encrypt the data for each layer
        encrypted_data = original_data
        for i in range(num_layers):
            key = generate_key()
            keys.append(key)
            save_key_to_file(key, f'secret_layer_{i + 1}.key')
            print(f'Encrypting layer {i + 1}...')
            encrypted_data = encrypt_data(encrypted_data, key)

        # Optionally compress the final layer of encrypted data
        compress_choice = input("Do you want to compress the encrypted data? (y/n): ").strip().lower()
        
        if compress_choice == 'y':
            print('Compressing...')
            compressed_data = compress_data(encrypted_data)
        else:
            compressed_data = encrypted_data

        # Store the (possibly compressed) encrypted data in a file
        with open('encrypted.bin', 'wb') as enc_file:
            enc_file.write(compressed_data)

        print("All layers encrypted (optionally compressed), and saved as 'encrypted.bin'.")

        # To decrypt: Read back stored data, decompress if necessary
        with open('encrypted.bin', 'rb') as enc_file:
            stored_data = enc_file.read()
        
        # Decompress the data if it was compressed
        if compress_choice == 'y':
            print("Decompressing...")
            stored_data = decompress_data(stored_data)

        # Decrypt each layer, starting from the last layer's key
        for key in reversed(keys):
            stored_data = decrypt_data(stored_data, key)

        # Save the decrypted data back to a file, maintain the original filename
        output_file_path = 'decrypted_' + os.path.basename(file_path)
        base64_to_file(stored_data, output_file_path)
        print(f"Decrypted file saved as '{output_file_path}'.")

if __name__ == "__main__":
    main()