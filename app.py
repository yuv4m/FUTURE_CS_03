from dotenv import load_dotenv
import os
import io

load_dotenv()  # this reads the .env file

import os, base64, sqlite3, uuid
from flask import Flask, request, redirect, url_for, send_file, render_template, abort, jsonify
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

# config
UPLOAD_DIR = os.path.join(os.getcwd(), "secure_files")
DB_PATH = os.path.join(os.getcwd(), "filemeta.db")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# load master key from env (base64)
MASTER_KEY = base64.b64decode(os.getenv("MASTER_KEY_BASE64", ""))  # must be 32 bytes

if not MASTER_KEY or len(MASTER_KEY) < 16:
    raise RuntimeError("Set MASTER_KEY_BASE64 in environment to a base64 32-byte key")

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB limit (adjust)

ALLOWED_EXTENSIONS = None  # set to set([...]) if you want to restrict

# DB helpers
def init_db():
    conn = sqlite3.connect("files.db")
    cur = conn.cursor()
    cur.execute("""
      CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY,
        original_name TEXT,
        storage_path TEXT,
        nonce TEXT,
        tag TEXT,
        size INTEGER
      )""")
    conn.commit()
    conn.close()

def save_meta(file_id, original_name, storage_path, nonce, tag, size):
    conn = sqlite3.connect("files.db")
    cur = conn.cursor()
    cur.execute("INSERT INTO files (id, original_name, storage_path, nonce, tag, size) VALUES (?, ?, ?, ?, ?, ?)",
                (file_id, original_name, storage_path, nonce.hex(), tag.hex(), size))
    conn.commit()
    conn.close()

def get_meta(file_id):
    conn = sqlite3.connect("files.db")
    cur = conn.cursor()
    cur.execute("SELECT id, original_name, storage_path, nonce, tag, size FROM files WHERE id=?", (file_id,))
    row = cur.fetchone()
    conn.close()
    return row

def list_files():
    conn = sqlite3.connect("files.db")
    cur = conn.cursor()
    cur.execute("SELECT id, original_name, size FROM files ORDER BY rowid DESC")
    rows = cur.fetchall()
    conn.close()
    return rows

# Key derivation: derive per-file key deterministically from master key + file_id
def derive_file_key(file_id: str, length=32):
    # HKDF(master, length, salt=file_id_bytes, hashmod=SHA256)
    salt = file_id.encode()
    return HKDF(MASTER_KEY, length, salt, SHA256)

# Encryption & Decryption
def encrypt_bytes(plaintext: bytes, file_id: str):
    key = derive_file_key(file_id)
    nonce = get_random_bytes(12)  # recommended size for GCM
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, nonce, tag

def decrypt_bytes(ciphertext: bytes, nonce: bytes, tag: bytes, file_id: str):
    key = derive_file_key(file_id)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# routes
@app.route("/")
def index():
    files = list_files()
    return render_template("index.html", files=files)

@app.route("/upload", methods=["POST"])
def upload():
    if 'file' not in request.files:
        return "No file part", 400
    f = request.files['file']
    if f.filename == '':
        return "No selected file", 400
    original = secure_filename(f.filename)
    data = f.read()
    file_id = uuid.uuid4().hex
    ciphertext, nonce, tag = encrypt_bytes(data, file_id)
    storage_name = f"{file_id}.bin"
    storage_path = os.path.join(UPLOAD_DIR, storage_name)
    with open(storage_path, "wb") as fh:
        fh.write(ciphertext)
    save_meta(file_id, original, storage_path, nonce, tag, len(data))
    return redirect(url_for('index'))

@app.route("/download/<file_id>", methods=["GET"])
def download(file_id):
    meta = get_meta(file_id)
    if not meta:
        abort(404)
    _, original_name, storage_path, nonce_hex, tag_hex, _size = meta
    with open(storage_path, "rb") as fh:
        ciphertext = fh.read()
    try:
        nonce = bytes.fromhex(nonce_hex)
        tag = bytes.fromhex(tag_hex)
        plaintext = decrypt_bytes(ciphertext, nonce, tag, file_id)
    except Exception as e:
        return "Decryption failed (integrity check failed or key mismatch).", 500
    # send as attachment
    return send_file(
        io.BytesIO(plaintext),
        as_attachment=True,
        download_name=original_name,
        mimetype='application/octet-stream'
    )

# small API example
@app.route("/api/files", methods=["GET"])
def api_files():
    rows = list_files()
    return jsonify([{"id": r[0], "name": r[1], "size": r[2]} for r in rows])

if __name__ == "__main__":
    import io
    init_db()
    app.run(debug=True)
