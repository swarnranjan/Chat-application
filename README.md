# 🔐 Secure Chat Application (AES + SHA + RSA + PyQt)

A secure, real-time chat and file transfer application built using Python. It ensures **confidentiality, integrity, and authenticity** of communication using AES encryption, SHA-256 hashing, and RSA digital signatures. The system features a modern GUI built with **PyQt5** for ease of use.

---

## 🚀 Features

- 🔑 **RSA Digital Signatures** for message and file authentication
- 🔒 **AES-CBC Encryption** for confidentiality
- ✅ **SHA-256 Hashing** for integrity verification
- 💬 **Real-time Chat** using TCP Sockets
- 📁 **Encrypted File Transfer** with secure delivery
- 🧠 **Automatic RSA Key Pair Generation**
- 🖥️ **PyQt5 GUI** for client interaction
- 🔁 **Multiple Clients Supported** via a central threaded server

---

## 📂 Project Structure

```bash
├── server.py              # Server handling client communication and verification
├── client_logic.py        # Backend logic for secure messaging and file transfer
├── chat_gui.py            # PyQt GUI for client interaction
├── crypto_utils.py        # Cryptographic functions: AES, SHA, RSA
├── rsa_key.py             # Optional script to generate predefined keys
├── README.md              # This file
