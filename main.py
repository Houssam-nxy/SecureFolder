import os
import time
import bcrypt
from cryptography.fernet import Fernet

KEYFILE = 'keyfile.key'
PASSWORD_FILE = 'password.key'

def generate_key():
    if not os.path.isfile(KEYFILE):
        key = Fernet.generate_key()
        with open(KEYFILE, 'wb') as keyFile:
            keyFile.write(key)
        return key
    else:
        with open(KEYFILE, 'rb') as keyFile:
            return keyFile.read()
            
key = generate_key()
            
def encrypt(file_path):
    try:
        with open(file_path, 'rb') as file:
            original = file.read()
            
        fernet = Fernet(key)
        encryption = fernet.encrypt(original)
        
        with open(file_path, 'wb') as encrypted_file:
            encrypted_file.write(encryption)
    except Exception as e:
        print(f"Error encrypting file {file_path}: {e}")
    
def decrypt(file_path):
    with open(file_path, 'rb') as file:
        original = file.read()
        
    fernet = Fernet(key)
    decryption = fernet.decrypt(original)
    
    with open(file_path, 'wb') as decrypted_file:
        decrypted_file.write(decryption)
        
def process(folder_path, action):
    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        
        if file_name == ".DS_Store":
            print(f"Skipping system file: {file_name}")
            continue
        
        if os.path.isfile(file_path):
            print(f"Processing file: {file_name}")
            if action == 'e':
                encrypt(file_path)
            elif action == 'd':
                decrypt(file_path)
        
        elif os.path.isdir(file_path):
            print(f"Processing folder: {file_name}")
            old_folder_path = file_path
            try:
                if action == 'e':
                    new_folder_name = Fernet(key).encrypt(file_name.encode()).decode()
                elif action == 'd':
                    new_folder_name = Fernet(key).decrypt(file_name.encode()).decode()
                new_folder_path = os.path.join(folder_path, new_folder_name)

                os.rename(old_folder_path, new_folder_path)
                print(f"Renamed folder: {file_name} -> {new_folder_name}")

                process(new_folder_path, action)
            except Exception as e:
                print(f"Failed to process folder {file_name}: {e}")


def acces(original_password):
    with open(PASSWORD_FILE, 'rb') as read_passkey:
        read_hashed_password = read_passkey.read()
        
    if bcrypt.checkpw(original_password.encode(), read_hashed_password):
        return True
    else:
        return False

def main():
    original_password = input("Enter your password: ")
    attempts = 0
    lockout_time = 60

    while attempts < 3:
        if acces(original_password):
            print("Welcome to the Dashboard!")
            query = input("Encrypt or decrypt (e/d): ").lower()

            if query in ['e', 'd']:
                folder_path = input("Enter the folder path to process: ").strip()
                if os.path.isdir(folder_path):
                    process(folder_path, query)
                else:
                    print(f"Error: The folder path '{folder_path}' does not exist.")
            else:
                print("Invalid input. Please select 'e' to encrypt or 'd' to decrypt.")
            break 
        else:
            attempts += 1
            remaining_attempts = 3 - attempts
            print(f"Incorrect password. You have {remaining_attempts} attempt(s) left.")
            original_password = input("Enter your password: ")
            if attempts == 3:
                print("Too many failed attempts. System locked.")
                time.sleep(lockout_time)
                print("Data is being destroyed...")
                break

if __name__ == "__main__":
    main()