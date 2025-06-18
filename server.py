# ===== improved server.py =====
import socket
import threading
import base64
import os
import json
from crypto_utils import decrypt_message, verify_sha256, verify_signature

HOST = '0.0.0.0'
PORT = 5000
clients = {}  # username -> socket
public_keys = {}  # username -> RSA public key file
lock = threading.Lock()


def handle_client(conn, addr):
    try:
        username = conn.recv(20).decode().strip()
        public_key_data_len = int(conn.recv(4).decode())
        public_key_data = conn.recv(public_key_data_len)
        public_key_path = f"public_{username}.pem"

        with open(public_key_path, 'wb') as f:
            f.write(public_key_data)

        with lock:
            if username in clients:
                conn.send(b"Username already taken.")
                conn.close()
                return
            clients[username] = conn
            public_keys[username] = public_key_path

        print(f"[SERVER] {username} connected from {addr}")

        while True:
            msg_type = conn.recv(4)
            if not msg_type:
                break

            recipient = conn.recv(20).decode().strip()

            if msg_type == b"MSG ":
                length = int(conn.recv(10).decode())
                payload = conn.recv(length).decode()

                try:
                    encrypted_str, checksum, signature_b64 = payload.split("::", 2)
                    signature = base64.b64decode(signature_b64)
                except ValueError:
                    print(f"[WARNING] Invalid message format from {username}. Dropped.")
                    continue

                if verify_sha256(encrypted_str.encode(), checksum) and \
                   verify_signature(encrypted_str.encode(), signature, public_keys[username]):

                    decrypted = decrypt_message(encrypted_str, verbose=True)
                    print(f"[SERVER] Message from {username} to {recipient}: {decrypted}")

                    with lock:
                        if recipient in clients:
                            clients[recipient].send(f"{username}: {decrypted}".encode())
                else:
                    print(f"[WARNING] Integrity or signature check failed for message from {username}. Dropped.")

            elif msg_type == b"FILE":
                name_len = int(conn.recv(3).decode())
                filename = conn.recv(name_len).decode()
                filesize = int(conn.recv(12).decode())
                enc_filename = f"enc_recv_{username}_{filename}"

                with open(enc_filename, 'wb') as f:
                    remaining = filesize
                    while remaining > 0:
                        chunk = conn.recv(min(4096, remaining))
                        if not chunk:
                            break
                        f.write(chunk)
                        remaining -= len(chunk)

                sha_checksum = conn.recv(64).decode()

                with open(enc_filename + ".sha", 'w') as hf:
                    hf.write(sha_checksum)

                print(f"[SERVER] File received from {username} to {recipient}: {filename} ({filesize} bytes)")

                with lock:
                    if recipient in clients:
                        clients[recipient].send(b"FILE")
                        clients[recipient].send(username.encode().ljust(20))
                        clients[recipient].send(str(len(filename)).zfill(3).encode())
                        clients[recipient].send(filename.encode())
                        clients[recipient].send(str(filesize).zfill(12).encode())

                        with open(enc_filename, 'rb') as f:
                            while chunk := f.read(4096):
                                clients[recipient].send(chunk)

                        clients[recipient].send(sha_checksum.encode())

    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        with lock:
            for user, client in list(clients.items()):
                if client == conn:
                    del clients[user]
                    if user in public_keys:
                        del public_keys[user]
        conn.close()
        print(f"[SERVER] {username} disconnected")


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[SERVER] Listening on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
