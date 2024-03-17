import os
import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import time
import pyperclip

def generate_random_password():
    return os.urandom(16)  # 16 bytes is equivalent to 128 bits

password = generate_random_password()

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        length=32,  # Length of the derived key in bytes (256 bits)
        salt=salt,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_image(image_path, output_path, password):
    with open(image_path, "rb") as f:
        plaintext = f.read()

    salt = os.urandom(16)
    key = derive_key(password, salt)

    start_time = time.time()

    cipher = Cipher(algorithms.AES(key), modes.CFB(salt), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    end_time = time.time()  # Record the end time

    with open(output_path, "wb") as f:
        f.write(salt + ciphertext)

    elapsed_time_ms = (end_time - start_time) * 1000
    print(f"Image '{os.path.basename(image_path)}' encrypted in {elapsed_time_ms:.2f} milliseconds")

def stop_program():
    root.destroy()

# Function to copy the encryption key to clipboard
def copy_key():
    global password  # Access the global password variable
    key_str = password.hex()  # Convert bytes to a hex string
    pyperclip.copy(key_str)  # Copy the key string to the clipboard
    print("Encryption key copied to clipboard.")

def open_source_folder():
    global source_folder
    source_folder = filedialog.askdirectory()
    source_folder_label.config(text=source_folder)

def open_output_folder():
    global output_folder
    output_folder = filedialog.askdirectory()
    output_folder_label.config(text=output_folder)

def encrypt():
    if not source_folder or not output_folder:
        print("Please select source and output folders.")
        return

    for filename in os.listdir(source_folder):
        if filename.endswith(".jpg") or filename.endswith(".jpeg") or filename.endswith(".png"):
            image_path = os.path.join(source_folder, filename)
            encrypted_output_path = os.path.join(output_folder, filename)
            encrypt_image(image_path, encrypted_output_path, password)

    copy_key_button.config(state=tk.NORMAL)  # Enable the copy key button

root = tk.Tk()
root.title("Image Encryption")

source_folder = ""
output_folder = ""

source_folder_label = tk.Label(root, text="Source Folder: ")
source_folder_label.pack()

source_folder_button = tk.Button(root, text="Select Source Folder", command=open_source_folder)
source_folder_button.pack()

output_folder_label = tk.Label(root, text="Output Folder: ")
output_folder_label.pack()

output_folder_button = tk.Button(root, text="Select encrypted Folder", command=open_output_folder)
output_folder_button.pack()

encrypt_button = tk.Button(root, text="Encrypt Images", command=encrypt)
encrypt_button.pack()

copy_key_button = tk.Button(root, text="Copy Key to Clipboard", command=copy_key)
copy_key_button.pack()
copy_key_button.config(state=tk.DISABLED)  # Disable the copy key button initially

exit_button = tk.Button(root, text="Exit", command=stop_program)
exit_button.pack()

root.mainloop()
