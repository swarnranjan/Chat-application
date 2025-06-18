# crypto_utils.py

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import hashlib
import os

KEY = b'sixteen byte key'  # 16-byte key for AES-128

def encrypt_message(message, verbose=False):
    iv = get_random_bytes(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv_enc = base64.b64encode(iv).decode()
    ct_enc = base64.b64encode(ct_bytes).decode()
    encrypted_text = iv_enc + ":" + ct_enc
    if verbose:
        print(f"[ENCRYPT] Original: '{message}'")
        print(f"[ENCRYPT] IV: '{iv_enc}'")
        print(f"[ENCRYPT] Ciphertext: '{ct_enc}'")
        print(f"[ENCRYPT] Encrypted (iv:ct): '{encrypted_text}'")
    return encrypted_text

def decrypt_message(cipher_text, verbose=False):
    iv_str, ct_str = cipher_text.split(":", 1)
    iv = base64.b64decode(iv_str)
    ct = base64.b64decode(ct_str)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    decrypted_text = pt.decode()
    if verbose:
        print(f"[DECRYPT] Encrypted input: '{cipher_text}'")
        print(f"[DECRYPT] IV: '{iv_str}'")
        print(f"[DECRYPT] Ciphertext: '{ct_str}'")
        print(f"[DECRYPT] Decrypted: '{decrypted_text}'")
    return decrypted_text

def generate_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def verify_sha256(data: bytes, checksum: str) -> bool:
    return generate_sha256(data) == checksum

def sign_data(data: bytes, private_key_path: str) -> bytes:
    key = RSA.import_key(open(private_key_path).read())
    h = SHA256.new(data)
    signature = pkcs1_15.new(key).sign(h)
    return signature

def verify_signature(data: bytes, signature: bytes, public_key_path: str) -> bool:
    key = RSA.import_key(open(public_key_path).read())
    h = SHA256.new(data)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def encrypt_file(input_path, output_path, hash_path, verbose=False):
    iv = get_random_bytes(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    padded_data = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    with open(output_path, 'wb') as f:
        f.write(iv + ciphertext)
    with open(hash_path, 'w') as hf:
        hf.write(generate_sha256(iv + ciphertext))
    if verbose:
        print(f"[ENCRYPT-FILE] Input: {input_path}")
        print(f"[ENCRYPT-FILE] Output: {output_path}")
        print(f"[ENCRYPT-FILE] SHA256 written to: {hash_path}")

def decrypt_file(input_path, output_path, hash_path, verbose=False):
    with open(input_path, 'rb') as f:
        file_data = f.read()
    with open(hash_path, 'r') as hf:
        original_hash = hf.read().strip()
    if not verify_sha256(file_data, original_hash):
        print("[WARNING] File integrity check failed. Aborting decryption.")
        return False
    iv = file_data[:16]
    ciphertext = file_data[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    with open(output_path, 'wb') as f:
        f.write(plaintext)
    if verbose:
        print(f"[DECRYPT-FILE] Input: {input_path}")
        print(f"[DECRYPT-FILE] Output: {output_path}")
        print(f"[DECRYPT-FILE] SHA256 verified: {original_hash}")
    return True
