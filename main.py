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
            print(f"Error processing {item}: {e}")    
                
    print("All files were successfully encrypted.")   
    
def process_decrypt_files(file_path):
    for item in os.listdir(file_path):
        full_item_path = os.path.join(file_path, item)
        
        if item.startswith('.'):
            print(f"Skipping hidden/system file: {item}")
            continue
            
        try:
            if os.path.isdir(full_item_path):
                process_decrypt_files(full_item_path) 
                
                decrypted_name = os.path.join(file_path, decrypt(item))
                os.rename(full_item_path, decrypted_name)
                
            elif os.path.isfile(full_item_path):
                with open(full_item_path, 'rb') as read_file:
                    encrypted_content = read_file.read()
                decrypted_content = decrypt(encrypted_content)
                
                with open(full_item_path, 'wb') as write_file:
                    write_file.write(decrypted_content)
                
                
                decrypted_name = os.path.join(file_path, decrypt(item))
                os.rename(full_item_path, decrypted_name)
        except Exception as e:
            print(f"Error processing {item}: {e}")
            
        print("All files were successfully decrypted.")  
        
        
# def process(folder_path, action):
#     for item in os.listdir(folder_path):
#         file_path = os.path.join(folder_path, item)
        
#         if item == ".DS_Store":
#             print(f"Skipping system file: {item}")
#             continue
        
#         if os.path.isfile(file_path):
#             print(f"Processing file: {item}")
#             if action == 'e':
#                 encrypt(file_path)
#             elif action == 'd':
#                 decrypt(file_path)
        
#         elif os.path.isdir(file_path):
#             print(f"Processing folder: {item}")
#             old_folder_path = file_path
#             try:
#                 if action == 'e':
#                     new_folder_name = Fernet(key).encrypt(item.encode()).decode()
#                 elif action == 'd':
#                     new_folder_name = Fernet(key).decrypt(item.encode()).decode()
#                 new_folder_path = os.path.join(folder_path, new_folder_name)

#                 os.rename(old_folder_path, new_folder_path)
#                 print(f"Renamed folder: {item} -> {new_folder_name}")

#                 process(new_folder_path, action)
#             except Exception as e:
#                 print(f"Failed to process folder {item}: {e}")


# def acces(original_password):
#     with open(PASSWORD_FILE, 'rb') as read_passkey:
#         read_hashed_password = read_passkey.read()
        
#     if bcrypt.checkpw(original_password.encode(), read_hashed_password):
#         return True
#     else:
#         return False

# def main():
#     original_password = input("Enter your password: ")
#     attempts = 0
#     lockout_time = 60

#     while attempts < 3:
#         if acces(original_password):
#             print("Welcome to the Dashboard!")
#             query = input("Encrypt or decrypt (e/d): ").lower()

#             if query in ['e', 'd']:
#                 folder_path = input("Enter the folder path to process: ").strip()
#                 if os.path.isdir(folder_path):
#                     process(folder_path, query)
#                 else:
#                     print(f"Error: The folder path '{folder_path}' does not exist.")
#             else:
#                 print("Invalid input. Please select 'e' to encrypt or 'd' to decrypt.")
#             break 
#         else:
#             attempts += 1
#             remaining_attempts = 3 - attempts
#             print(f"Incorrect password. You have {remaining_attempts} attempt(s) left.")
#             original_password = input("Enter your password: ")
#             if attempts == 3:
#                 print("Too many failed attempts. System locked.")
#                 time.sleep(lockout_time)
#                 print("Data is being destroyed...")
#                 break

def main():
    ask = input("encryption or decryption (e/d): ")
    
    if ask == 'e':
        query = input("Enter the path: ")
        process_encrypt_files(query)
    elif ask == 'd':
        query = input("Enter the path: ")
        process_decrypt_files(query)
    else:
        print('Invalid input')
    
if __name__ == "__main__":
    main()