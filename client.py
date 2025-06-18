import socket
import os
import threading
import base64
from crypto_utils import (
    encrypt_message, decrypt_message,
    encrypt_file, decrypt_file,
    generate_sha256, sign_data
)

HOST = '127.0.0.1'
PORT = 5000
USERNAME = ""


def receive_messages(sock):
    while True:
        try:
            header = sock.recv(4)
            if not header:
                break
            if header == b"FILE":
                sender = sock.recv(20).decode().strip()
                name_len = int(sock.recv(3).decode())
                filename = sock.recv(name_len).decode()
                filesize = int(sock.recv(12).decode())
                enc_file = f"recv_enc_{filename}"
                sha_file = f"recv_enc_{filename}.sha"

                with open(enc_file, 'wb') as f:
                    remaining = filesize
                    while remaining > 0:
                        chunk = sock.recv(min(4096, remaining))
                        if not chunk:
                            break
                        f.write(chunk)
                        remaining -= len(chunk)

                sha_checksum = sock.recv(64).decode()
                with open(sha_file, 'w') as f:
                    f.write(sha_checksum)

                out_file = f"recv_{filename}"
                success = decrypt_file(enc_file, out_file, sha_file, verbose=True)
                if success:
                    print(f"\n[RECEIVED FILE] From {sender}: {filename} saved as {out_file}")
                else:
                    print("\n[WARNING] File integrity failed. File not saved.")

                os.remove(enc_file)
                os.remove(sha_file)

            else:
                data = header + sock.recv(1024)
                print("\n[RECEIVED MESSAGE]", data.decode())
        except Exception as e:
            print(f"[ERROR] Receiving: {e}")
            break


def send_message(sock, recipient):
    message = input("Enter message: ")
    encrypted_str = encrypt_message(message, verbose=True)
    checksum = generate_sha256(encrypted_str.encode())
    private_key_path = f"private_{USERNAME}.pem"
    signature = sign_data(encrypted_str.encode(), private_key_path)
    signature_b64 = base64.b64encode(signature).decode()

    payload = encrypted_str + "::" + checksum + "::" + signature_b64
    sock.send(b"MSG ")
    sock.send(recipient.encode().ljust(20))
    sock.send(str(len(payload)).zfill(10).encode())
    sock.send(payload.encode())


def send_file(sock, recipient):
    filepath = input("Enter file path: ")
    if not os.path.isfile(filepath):
        print("[CLIENT] File does not exist.")
        return

    filename = os.path.basename(filepath)
    enc_file = f"enc_{filename}"
    sha_file = f"enc_{filename}.sha"
    encrypt_file(filepath, enc_file, sha_file, verbose=True)

    filesize = os.path.getsize(enc_file)
    with open(sha_file, 'r') as f:
        sha_checksum = f.read().strip()

    sock.send(b"FILE")
    sock.send(recipient.encode().ljust(20))
    sock.send(str(len(filename)).zfill(3).encode())
    sock.send(filename.encode())
    sock.send(str(filesize).zfill(12).encode())

    with open(enc_file, 'rb') as f:
        while chunk := f.read(4096):
            sock.send(chunk)

    sock.send(sha_checksum.encode())

    os.remove(enc_file)
    os.remove(sha_file)
    print(f"[CLIENT] File '{filename}' sent to {recipient}.")


def main():
    global USERNAME
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        USERNAME = input("Enter your unique username: ").strip()
        sock.send(USERNAME.encode().ljust(20))

        pubkey_path = f"public_{USERNAME}.pem"
        if not os.path.exists(pubkey_path):
            print("[CLIENT] Public key not found. Exiting.")
            return

        with open(pubkey_path, 'rb') as f:
            key_data = f.read()
            sock.send(str(len(key_data)).zfill(4).encode())
            sock.send(key_data)

        threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()

        while True:
            print("\n1. Send Message\n2. Send File\n3. Exit")
            choice = input("Choice: ")
            if choice == '1':
                recipient = input("Send to username: ").strip()
                send_message(sock, recipient)
            elif choice == '2':
                recipient = input("Send to username: ").strip()
                send_file(sock, recipient)
            elif choice == '3':
                print("Exiting...")
                break
            else:
                print("Invalid option.")


if __name__ == "__main__":
    main()
