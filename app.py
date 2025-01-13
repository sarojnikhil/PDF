from flask import Flask, request, render_template, redirect
import os
import fitz  # PyMuPDF
import itertools
import base64
from Crypto.Cipher import AES, DES, Blowfish, ChaCha20
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import unpad
import hashlib

# Define the charset with specific characters
charset = 'nikds'

# Define a targeted wordlist for dictionary attack
wordlist = ['apple', 'admin', 'hello', 'world', 'password', 'qwert', 'niks']

# Dictionary Attack Function
def dictionary_attack(pdf_path, wordlist):
    with fitz.open(pdf_path) as doc:
        for password in wordlist:
            print(f"Attempting dictionary password: {password}")
            if doc.authenticate(password):
                print(f"Password cracked: {password}")
                return password
    return None

# Brute Force Attack
def brute_force_attack(pdf_path, max_length=5):
    for comb in itertools.product(charset, repeat=max_length):
        password = ''.join(comb)
        print(f"Attempting brute force password: {password}")
        with fitz.open(pdf_path) as doc:
            if doc.authenticate(password):
                print(f"Password cracked: {password}")
                return password
    print("Password not found.")
    return None

# Function to extract and print text from the PDF
def extract_text_from_pdf(pdf_path, password):
    with fitz.open(pdf_path) as doc:
        if doc.authenticate(password):
            print("Password verified. Extracting text from the PDF...")
            text = ""
            for page_num in range(doc.page_count):
                page = doc.load_page(page_num)
                text += page.get_text("text")
            return text
    return None

# A predefined list of words/phrases to check if the text is likely plain or encrypted
def analyze_text_with_keywords(text):
    encryption_keywords = ['encrypted', 'cipher', 'key', 'algorithm', 'crypto']
    if any(keyword in text.lower() for keyword in encryption_keywords):
        return "encrypted"
    else:
        return "plain text"

# Decrypt AES-encrypted text
def decrypt_text_aes(encrypted_text, key):
    try:
        encrypted_data = base64.b64decode(encrypted_text)
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted_data.decode('utf-8')
    except Exception as e:
        print(f"AES Decryption failed: {e}")
        return None

# Decrypt DES-encrypted text
def decrypt_des(encrypted_text, key):
    try:
        cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
        decrypted = cipher.decrypt(base64.b64decode(encrypted_text))
        return decrypted.decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"DES Decryption failed: {e}")
        return None

# Decrypt Blowfish-encrypted text
def decrypt_blowfish(encrypted_text, key):
    try:
        cipher = Blowfish.new(key.encode('utf-8'), Blowfish.MODE_ECB)
        decrypted = cipher.decrypt(base64.b64decode(encrypted_text))
        return decrypted.decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"Blowfish Decryption failed: {e}")
        return None

# Function to decrypt text using ChaCha20
def decrypt_text_chacha20(encrypted_text, key):
    try:
        # Ensure the key length is 32 bytes
        if len(key) != 32:
            print("Invalid key length. ChaCha20 requires a 32-byte key.")
            return None
        
        encrypted_data = base64.b64decode(encrypted_text)
        nonce = encrypted_data[:8]  # Extract nonce
        ciphertext = encrypted_data[8:]  # Extract ciphertext
        cipher = ChaCha20.new(key=key, nonce=nonce)
        return cipher.decrypt(ciphertext).decode()  # Decrypt text
    except (ValueError, KeyError) as e:
        print(f"Decryption failed: {e}")
        return None


# Main function to initiate dictionary attack and brute force
def main(pdf_path):
    print("Attempting dictionary attack...")
    password_found = dictionary_attack(pdf_path, wordlist)

    if password_found:
        return password_found

    print("Dictionary attack failed. Attempting brute force...")
    return brute_force_attack(pdf_path)

# Flask setup
app = Flask(__name__, static_folder=None)


# Route to render HTML for uploading PDF
@app.route('/')
def index():
    return render_template('index.html')

# Route to handle file upload
@app.route('/upload', methods=['POST'])
def upload():
    if 'pdf' not in request.files:
        return "No file part"

    file = request.files['pdf']
    if file.filename == '':
        return "No selected file"

    if file and file.filename.endswith('.pdf'):
        uploads_dir = os.path.join(os.getcwd(), 'uploads')
        if not os.path.exists(uploads_dir):
            os.makedirs(uploads_dir)  # Create the directory if it doesn't exist

        pdf_path = os.path.join(uploads_dir, file.filename)
        file.save(pdf_path)

        # Call the main function to crack the password and extract text
        password = main(pdf_path)

        if password:
            text = extract_text_from_pdf(pdf_path, password)
            analysis_result = analyze_text_with_keywords(text) if text else "Failed to extract text."

            # Attempt decryption with AES, DES, Blowfish, and ChaCha20
            decrypted_text_aes = decrypt_text_aes(text, "mysecretkey12345")
            decrypted_text_des = decrypt_des(text, "desnik23")
            decrypted_text_blowfish = decrypt_blowfish(text, "bmySecureKey9876")
            decrypted_text_chacha20 = decrypt_text_chacha20(text, "c-C\xd1-&O\x01\xf0\xb4\xf5^x\x8dn\xdb\x808qa:\xe0Q\xf0\xfeR\x8f\xe9\xeeE3Lu")

            return render_template('result.html', password=password, text=text,
                                   analysis=analysis_result, aes=decrypted_text_aes,
                                   des=decrypted_text_des, blowfish=decrypted_text_blowfish,
                                   chacha20=decrypted_text_chacha20)
        else:
            return redirect('/fail')
        
    return "Invalid file type."

# Route for the fail page
@app.route('/fail')
def fail():
    return render_template('fail.html')

if __name__ == '__main__':
    app.run(debug=True)