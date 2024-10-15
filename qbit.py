import os
import base64
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
                    file.write(file_content[i:i+4096])
                    pbar.update(min(4096, total_size - i))
    except Exception as e:
        print(f"An error occurred while writing to the file: {e}")

def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data)

def main():
    file_path = input("Enter the path of the file you want to encrypt: ")
    
    # Validate if the file exists
    if not os.path.isfile(file_path):
        print("Error: The specified file does not exist.")
        return

    original_data = file_to_base64(file_path)
    
    if original_data is not None:
        key = generate_key()
        save_key_to_file(key, 'secret.key')  
        
        encrypted_data = encrypt_data(original_data, key)
        
        # Store the encrypted data in a file instead of base64
        with open('encrypted.bin', 'wb') as enc_file:
            enc_file.write(encrypted_data)

        print("File encrypted and saved as 'encrypted.bin'.")

        # Decrypt the data back to verify
        with open('encrypted.bin', 'rb') as enc_file:
            encrypted_data = enc_file.read()
        
        decrypted_data = decrypt_data(encrypted_data, key)
        
        # Save the decrypted data back to a file, maintain the original filename
        output_file_path = 'decrypted_' + os.path.basename(file_path)
        base64_to_file(decrypted_data, output_file_path)  
        print(f"Decrypted file saved as '{output_file_path}'.")

if __name__ == "__main__":
    main()