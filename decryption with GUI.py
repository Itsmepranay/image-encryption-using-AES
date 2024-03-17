import os
import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import time

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        length=32,  # Length of the derived key in bytes (256 bits)
        salt=salt,
        backend=default_backend()
    )
    return kdf.derive(password)

def decrypt_image(encrypted_image_path, output_path, password):
    with open(encrypted_image_path, "rb") as f:
        data = f.read()

    salt = data[:16]
    ciphertext = data[16:]

    key = derive_key(password, salt)

    start_time = time.time()  # Record the start time

    cipher = Cipher(algorithms.AES(key), modes.CFB(salt), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    end_time = time.time()  # Record the end time

    with open(output_path, "wb") as f:
        f.write(plaintext)

    elapsed_time_ms = (end_time - start_time) * 1000
    print(f"Image '{os.path.basename(encrypted_image_path)}' decrypted in {elapsed_time_ms:.2f} milliseconds")

def open_encrypted_folder():
    global encrypted_folder
    encrypted_folder = filedialog.askdirectory()
    encrypted_folder_label.config(text=encrypted_folder)

def open_decrypted_folder():
    global decrypted_folder
    decrypted_folder = filedialog.askdirectory()
    decrypted_folder_label.config(text=decrypted_folder)

def read_key():
    global decryption_key
    decryption_key = bytes.fromhex(key_entry.get())
    key_entry.delete(0, tk.END)  # Clear the key entry field

def decrypt():
    if not encrypted_folder or not decrypted_folder:
        print("Please select encrypted and decrypted folders.")
        return
    if not decryption_key:
        print("Please enter the decryption key.")
        return

    completed_label.config(text="Decrypting...")  # Display a message during decryption

    for filename in os.listdir(encrypted_folder):
        if filename.endswith(".jpg") or filename.endswith(".jpeg") or filename.endswith(".png"):
            encrypted_image_path = os.path.join(encrypted_folder, filename)
            decrypted_output_path = os.path.join(decrypted_folder, filename)
            decrypt_image(encrypted_image_path, decrypted_output_path, decryption_key)

    completed_label.config(text="Decryption completed")  # Update message after decryption

root = tk.Tk()
root.title("Image Decryption")

encrypted_folder = ""
decrypted_folder = ""
decryption_key = None

encrypted_folder_label = tk.Label(root, text="Encrypted Folder: ")
encrypted_folder_label.pack()

encrypted_folder_button = tk.Button(root, text="Select Encrypted Folder", command=open_encrypted_folder)
encrypted_folder_button.pack()

decrypted_folder_label = tk.Label(root, text="Decrypted Folder (output) : ")
decrypted_folder_label.pack()

decrypted_folder_button = tk.Button(root, text="Select Decrypted Folder", command=open_decrypted_folder)
decrypted_folder_button.pack()

key_label = tk.Label(root, text="Enter Decryption Key: ")
key_label.pack()

key_entry = tk.Entry(root)
key_entry.pack()

key_button = tk.Button(root, text="Read Key", command=read_key)
key_button.pack()

decrypt_button = tk.Button(root, text="Decrypt Images", command=decrypt)
decrypt_button.pack()

completed_label = tk.Label(root, text="")
completed_label.pack()

exit_button = tk.Button(root, text="Exit", command=root.destroy)
exit_button.pack()

root.mainloop()
