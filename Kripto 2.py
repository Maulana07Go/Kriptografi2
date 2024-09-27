import tkinter as tk
from tkinter import messagebox
import numpy as np

def vigenere_encrypt(plaintext, key):
    plaintext = plaintext.upper()
    key = key.upper()
    ciphertext = ''
    for i in range(len(plaintext)):
        if plaintext[i].isalpha():
            p = ord(plaintext[i]) - ord('A')
            k = ord(key[i % len(key)]) - ord('A')
            c = (p + k) % 26
            ciphertext += chr(c + ord('A'))
        else:
            ciphertext += plaintext[i]
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    ciphertext = ciphertext.upper()
    key = key.upper()
    plaintext = ''
    for i in range(len(ciphertext)):
        if ciphertext[i].isalpha():
            c = ord(ciphertext[i]) - ord('A')
            k = ord(key[i % len(key)]) - ord('A')
            p = (c - k) % 26
            plaintext += chr(p + ord('A'))
        else:
            plaintext += ciphertext[i]
    return plaintext

def playfair_matrix(key):
    matrix = []
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    key = "".join(dict.fromkeys(key.upper()))  
    for char in key:
        if char in alphabet:
            matrix.append(char)
            alphabet = alphabet.replace(char, "")
    matrix.extend(alphabet)
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def playfair_encrypt(plaintext, key):
    matrix = playfair_matrix(key)
    plaintext = plaintext.upper().replace("J", "I")
    ciphertext = ''
    
    for i in range(0, len(plaintext), 2):
        if i+1 == len(plaintext) or plaintext[i] == plaintext[i+1]:
            plaintext = plaintext[:i+1] + 'X' + plaintext[i+1:]

        pair = plaintext[i:i+2]
        row1, col1 = divmod([row.index(pair[0]) for row in matrix if pair[0] in row][0], 5)
        row2, col2 = divmod([row.index(pair[1]) for row in matrix if pair[1] in row][0], 5)

        if row1 == row2:
            ciphertext += matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            ciphertext += matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
        else:
            ciphertext += matrix[row1][col2] + matrix[row2][col1]
    return ciphertext

def playfair_decrypt(ciphertext, key):
    matrix = playfair_matrix(key)
    ciphertext = ciphertext.upper()
    plaintext = ''
    for i in range(0, len(ciphertext), 2):
        pair = ciphertext[i:i+2]
        row1, col1 = divmod([row.index(pair[0]) for row in matrix if pair[0] in row][0], 5)
        row2, col2 = divmod([row.index(pair[1]) for row in matrix if pair[1] in row][0], 5)

        if row1 == row2:
            plaintext += matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            plaintext += matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
        else:
            plaintext += matrix[row1][col2] + matrix[row2][col1]
    return plaintext


def hill_encrypt(plaintext, key_matrix):
    plaintext = plaintext.upper()
    ciphertext = ''
    
    while len(plaintext) % 2 != 0:
        plaintext += 'X'
    key_matrix = np.array(key_matrix)
    for i in range(0, len(plaintext), 2):
        vector = np.array([ord(plaintext[i]) - ord('A'), ord(plaintext[i+1]) - ord('A')])
        result = np.dot(key_matrix, vector) % 26
        ciphertext += chr(result[0] + ord('A')) + chr(result[1] + ord('A'))
    return ciphertext

def hill_decrypt(ciphertext, key_matrix):
    ciphertext = ciphertext.upper()
    plaintext = ''
    
    det = int(np.round(np.linalg.det(key_matrix)))
    inv_det = pow(det, -1, 26)
    key_matrix_inv = inv_det * np.round(np.linalg.inv(key_matrix)).astype(int) % 26
    for i in range(0, len(ciphertext), 2):
        vector = np.array([ord(ciphertext[i]) - ord('A'), ord(ciphertext[i+1]) - ord('A')])
        result = np.dot(key_matrix_inv, vector) % 26
        plaintext += chr(result[0] + ord('A')) + chr(result[1] + ord('A'))
    return plaintext


def process_text():
    plaintext = entry_plaintext.get("1.0", tk.END).strip()
    key = entry_key.get("1.0", tk.END).strip()
    method = method_var.get()
    operation = operation_var.get()
    
    if method == "Vigenere":
        if operation == "Encrypt":
            result = vigenere_encrypt(plaintext, key)
        else:
            result = vigenere_decrypt(plaintext, key)
    elif method == "Playfair":
        if operation == "Encrypt":
            result = playfair_encrypt(plaintext, key)
        else:
            result = playfair_decrypt(plaintext, key)
    elif method == "Hill":
        key_matrix = [[3, 3], [2, 5]] 
        if operation == "Encrypt":
            result = hill_encrypt(plaintext, key_matrix)
        else:
            result = hill_decrypt(plaintext, key_matrix)
    else:
        result = "Invalid method!"
    
    
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, result)


root = tk.Tk()
root.title("Program Kriptografi")
root.geometry("600x600")  


tk.Label(root, text="Masukkan Plaintext:").grid(row=0, column=0, sticky='w', padx=10, pady=10)
entry_plaintext = tk.Text(root, height=5, width=60)  
entry_plaintext.grid(row=0, column=1, padx=10, pady=10)


tk.Label(root, text="Masukkan Key:").grid(row=1, column=0, sticky='w', padx=10, pady=10)
entry_key = tk.Text(root, height=2, width=60)  
entry_key.grid(row=1, column=1, padx=10, pady=10)


tk.Label(root, text="Pilih Cipher Method:").grid(row=2, column=0, sticky='w', padx=10, pady=10)
method_var = tk.StringVar(value="Vigenere")
tk.Radiobutton(root, text="Vigenere Cipher", variable=method_var, value="Vigenere").grid(row=2, column=1, sticky='w', padx=10)
tk.Radiobutton(root, text="Playfair Cipher", variable=method_var, value="Playfair").grid(row=3, column=1, sticky='w', padx=10)
tk.Radiobutton(root, text="Hill Cipher", variable=method_var, value="Hill").grid(row=4, column=1, sticky='w', padx=10)


tk.Label(root, text="Pilih Operasi:").grid(row=5, column=0, sticky='w', padx=10, pady=10)
operation_var = tk.StringVar(value="Encrypt")
tk.Radiobutton(root, text="Encrypt", variable=operation_var, value="Encrypt").grid(row=5, column=1, sticky='w', padx=10)
tk.Radiobutton(root, text="Decrypt", variable=operation_var, value="Decrypt").grid(row=6, column=1, sticky='w', padx=10)


tk.Button(root, text="Process", command=process_text, width=20, height=2).grid(row=7, column=1, pady=10)


tk.Label(root, text="Hasil:").grid(row=8, column=0, sticky='w', padx=10, pady=10)
output_text = tk.Text(root, height=5, width=60, state=tk.NORMAL)  
output_text.grid(row=8, column=1, padx=10, pady=10)

root.mainloop()