import socket
import os
import threading
import base64
from Crypto.PublicKey import RSA
from crypto_utils import (
    encrypt_message, decrypt_message,
    encrypt_file, decrypt_file,
    generate_sha256, sign_data
)

class ChatClient:
    def __init__(self, username, host='127.0.0.1', port=5000):
        self.HOST = host
        self.PORT = port
        self.USERNAME = username
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.callbacks = {
            'on_message': None,
            'on_file': None,
            'on_error': None
        }

    def connect(self):
        self.sock.connect((self.HOST, self.PORT))
        self.sock.send(self.USERNAME.encode().ljust(20))

        privkey_path = f"private_{self.USERNAME}.pem"
        pubkey_path = f"public_{self.USERNAME}.pem"

        if not (os.path.exists(privkey_path) and os.path.exists(pubkey_path)):
            print(f"[KEYGEN] RSA keys not found for '{self.USERNAME}'. Generating...")
            key = RSA.generate(2048)
            with open(privkey_path, "wb") as priv_file:
                priv_file.write(key.export_key())
            with open(pubkey_path, "wb") as pub_file:
                pub_file.write(key.publickey().export_key())
            print(f"[KEYGEN] Keys saved.")

        with open(pubkey_path, 'rb') as f:
            key_data = f.read()
            self.sock.send(str(len(key_data)).zfill(4).encode())
            self.sock.send(key_data)

        threading.Thread(target=self.receive_messages, daemon=True).start()

    def on(self, event, callback):
        if event in self.callbacks:
            self.callbacks[event] = callback

    def receive_messages(self):
        while True:
            try:
                header = self.sock.recv(4)
                if not header:
                    break

                if header == b"FILE":
                    sender = self.sock.recv(20).decode().strip()
                    name_len = int(self.sock.recv(3).decode())
                    filename = self.sock.recv(name_len).decode()
                    filesize = int(self.sock.recv(12).decode())
                    enc_file = f"recv_enc_{filename}"
                    sha_file = f"recv_enc_{filename}.sha"

                    with open(enc_file, 'wb') as f:
                        remaining = filesize
                        while remaining > 0:
                            chunk = self.sock.recv(min(4096, remaining))
                            if not chunk:
                                break
                            f.write(chunk)
                            remaining -= len(chunk)

                    sha_checksum = self.sock.recv(64).decode()
                    with open(sha_file, 'w') as f:
                        f.write(sha_checksum)

                    out_file = f"recv_{filename}"
                    success = decrypt_file(enc_file, out_file, sha_file)

                    os.remove(enc_file)
                    os.remove(sha_file)

                    if self.callbacks['on_file']:
                        self.callbacks['on_file'](sender, filename, out_file, success)
                else:
                    data = header + self.sock.recv(1024)
                    if self.callbacks['on_message']:
                        self.callbacks['on_message'](data.decode())

            except Exception as e:
                if self.callbacks['on_error']:
                    self.callbacks['on_error'](str(e))
                break

    def send_message(self, recipient, message):
        encrypted_str = encrypt_message(message)
        checksum = generate_sha256(encrypted_str.encode())
        private_key_path = f"private_{self.USERNAME}.pem"
        signature = sign_data(encrypted_str.encode(), private_key_path)
        signature_b64 = base64.b64encode(signature).decode()

        payload = encrypted_str + "::" + checksum + "::" + signature_b64
        self.sock.send(b"MSG ")
        self.sock.send(recipient.encode().ljust(20))
        self.sock.send(str(len(payload)).zfill(10).encode())
        self.sock.send(payload.encode())

    def send_file(self, recipient, filepath):
        if not os.path.isfile(filepath):
            if self.callbacks['on_error']:
                self.callbacks['on_error']("File does not exist.")
            return

        filename = os.path.basename(filepath)
        enc_file = f"enc_{filename}"
        sha_file = f"enc_{filename}.sha"
        encrypt_file(filepath, enc_file, sha_file)

        filesize = os.path.getsize(enc_file)
        with open(sha_file, 'r') as f:
            sha_checksum = f.read().strip()

        self.sock.send(b"FILE")
        self.sock.send(recipient.encode().ljust(20))
        self.sock.send(str(len(filename)).zfill(3).encode())
        self.sock.send(filename.encode())
        self.sock.send(str(filesize).zfill(12).encode())

        with open(enc_file, 'rb') as f:
            while chunk := f.read(4096):
                self.sock.send(chunk)

        self.sock.send(sha_checksum.encode())

        os.remove(enc_file)
        os.remove(sha_file)

    def disconnect(self):
        self.sock.close()
