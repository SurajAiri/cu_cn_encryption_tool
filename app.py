from flask import Flask, render_template, request, send_from_directory, jsonify
from Crypto.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from werkzeug.utils import secure_filename
import os

# AES configuration
KEY = b'This is a key123'  # 16-byte AES key
BLOCK_SIZE = 16  # Block size for AES

UPLOAD_FOLDER = './uploads'
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# AES Encryption function
def encrypt_file(data):
    cipher = AES.new(KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, BLOCK_SIZE))
    return cipher.iv + ct_bytes  # Concatenate IV with ciphertext

# AES Decryption function
def decrypt_file(data):
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), BLOCK_SIZE)

# Route to render the main page
@app.route('/')
def index():
    return render_template('index.html')

# Endpoint to handle file encryption
@app.route('/encrypt', methods=['POST'])
def upload_encrypt_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"})

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"})

    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Read the file and encrypt it
        with open(file_path, 'rb') as f:
            file_data = f.read()
            encrypted_data = encrypt_file(file_data)

        encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"encrypted_{filename}")
        with open(encrypted_file_path, 'wb') as ef:
            ef.write(encrypted_data)

        return jsonify({
            "message": "File encrypted successfully!",
            "encrypted_file": f"encrypted_{filename}"
        })

# Endpoint to handle file decryption
@app.route('/decrypt', methods=['POST'])
def upload_decrypt_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"})

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"})

    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Read the file and decrypt it
        with open(file_path, 'rb') as f:
            file_data = f.read()
            decrypted_data = decrypt_file(file_data)

        decrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"decrypted_{filename}")
        with open(decrypted_file_path, 'wb') as df:
            df.write(decrypted_data)

        return jsonify({
            "message": "File decrypted successfully!",
            "decrypted_file": f"decrypted_{filename}"
        })

# Endpoint to serve the uploaded files
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)
