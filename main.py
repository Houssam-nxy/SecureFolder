import os
import time
import bcrypt
import getpass
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
fernet = Fernet(key)
            
def encrypt(original):
    if isinstance(original, bytes):
        return fernet.encrypt(original)
    return fernet.encrypt(original.encode())
     
    
def decrypt(encrypted):
    if isinstance(encrypted, bytes):
        return fernet.decrypt(encrypted)
    return fernet.decrypt(encrypted).decode()
     
def process_encrypt_files(file_path):
    print("\nStarting encryption process...")
    for item in os.listdir(file_path):
        full_item_path = os.path.join(file_path, item)
        old_name = full_item_path
        
        if item.startswith('.'):
            print(f"Skipping hidden/system file: {item}")
            continue
        
        try:
            if os.path.isdir(full_item_path):
                print(f"Entering directory: {item}")
                process_encrypt_files(full_item_path)
                
                new_name = os.path.join(file_path, fernet.encrypt(item.encode()).decode())
                os.rename(old_name, new_name)
                print(f"Renamed directory: {item} -> {new_name}")
            
            elif os.path.isfile(full_item_path):
                with open(full_item_path, 'rb') as read_file:
                    original = read_file.read()
                    
                encrypted = encrypt(original)
                
                with open(full_item_path, 'wb') as write_file:
                    write_file.write(encrypted)
                    
                new_name = os.path.join(file_path, fernet.encrypt(item.encode()).decode()) 
                os.rename(old_name, new_name)
                print(f"Encrypted and renamed file: {item} -> {new_name}")
        except Exception as e:
            print(f"Error processing {item}: {e.__class__.__name__}: {e}")    
    print("Encryption complete!\n")
    
def process_decrypt_files(file_path):
    print("\nStarting decryption process...")
    for item in os.listdir(file_path):
        full_item_path = os.path.join(file_path, item)
        
        if item.startswith('.'):
            print(f"Skipping hidden/system file: {item}")
            continue
            
        try:
            if os.path.isdir(full_item_path):
                print(f"Entering directory: {item}")
                process_decrypt_files(full_item_path) 
                
                decrypted_name = os.path.join(file_path, decrypt(item))
                os.rename(full_item_path, decrypted_name)
                print(f"Renamed directory: {item} -> {decrypted_name}")
                
            elif os.path.isfile(full_item_path):
                with open(full_item_path, 'rb') as read_file:
                    encrypted_content = read_file.read()
                decrypted_content = decrypt(encrypted_content)
                
                with open(full_item_path, 'wb') as write_file:
                    write_file.write(decrypted_content)
                
                
                decrypted_name = os.path.join(file_path, decrypt(item))
                os.rename(full_item_path, decrypted_name)
                print(f"Encrypted and renamed file: {item} -> {decrypted_name}")
        except Exception as e:
            print(f"Error processing {item}: {e.__class__.__name__}: {e}")
    print("Decryption complete!\n") 
            
def handle_encryption():
    query = input("Enter the folder path to Encrypt: ").strip()
    if os.path.isdir(query):
        process_encrypt_files(query)
    else:
        print(f"Invalid directory path: {query}")

def handle_decryption():
    query = input("Enter the folder path to Decrypt: ").strip()
    if os.path.isdir(query):
        process_decrypt_files(query)
    else:
        print(f"Invalid directory path: {query}")

def acces(original_password):
    if not os.path.isfile(PASSWORD_FILE):
        print("Password file missing. Unable to authenticate.")
        return False
    
    with open(PASSWORD_FILE, 'rb') as read_passkey:
        read_hashed_password = read_passkey.read()
        
    if bcrypt.checkpw(original_password.encode(), read_hashed_password):
        return True
    else:
        return False

def main():
    print("Welcome to SecureFolder - File Encryption & Decryption System")
    original_password = getpass.getpass("Enter your password: ")
    attempts = 0
    lockout_time = 60

    while attempts < 3:
        original_password = getpass.getpass("Enter your password: ").strip()
        if acces(original_password):
            print("\nAccess granted! Welcome to the Dashboard.")
            print("Options:")
            print("  [e] Encrypt files")
            print("  [d] Decrypt files")
            print("  [q] Quit\n")
            
            while True:
                ask_permission = input("Select an option (e/d/q): ").lower().strip()

                if ask_permission == 'e':
                    handle_encryption()
                elif ask_permission == 'd':
                    handle_decryption()
                elif ask_permission == 'q':
                    print("Exiting the system. Goodbye!")
                    return
                else:
                    print("Invalid input. Please select 'e' to encrypt, 'd' to decrypt, or 'q' to quit.")
            break
        else:
            attempts += 1
            remaining_attempts = 3 - attempts
            print(f"Incorrect password. You have {remaining_attempts} attempt(s) left.\n")
            if attempts == 3:
                print("Too many failed attempts. System locked for 60 seconds.")
                time.sleep(lockout_time)
                print("You can now try again.\n")

if __name__ == "__main__":
    main()