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
├── README.md              # This file
```

---

## 🛡️ Security Components

| Mechanism      | Purpose                                 |
|----------------|------------------------------------------|
| **AES (CBC)**  | Symmetric encryption for messages/files |
| **SHA-256**    | Integrity check to detect tampering     |
| **RSA**        | Digital signatures to verify sender     |
| **Public Key Upload** | Sent during client connection     |

---

## 🖼️ GUI Preview

> A PyQt5 interface supports message input, recipient selection, chat log display, and file sending.

---

## 🧪 How to Run

### 1. Install dependencies
```bash
pip install pycryptodome pyqt5
```

### 2. Start the server
```bash
python server.py
```

### 3. Run the client (in a new terminal)
```bash
python chat_gui.py
```

> ✅ On first run, RSA keys are auto-generated and public key is sent to the server.

### 4. Usage
- Connect using a unique username (e.g., `John`, `Mary`)
- Specify recipient username
- Send messages and files securely

---

## 📥 File Handling

- Encrypted files are sent and automatically decrypted on the recipient's end
- Received files are named as: `recv_<original_filename>`

---

## 📌 Example Message Flow

```
[Connected] Logged in as 'John'.
You to Mary: Hello Mary!
[File] Sending 'document.pdf' to Mary...
[File Received] document.pdf from Mary saved as recv_document.pdf
```

---

## 📖 Future Improvements

- AES session keys via Diffie–Hellman
- Group chat support
- GUI enhancements (notifications, scroll lock)
- Chat history encryption and secure logging

---

## 📚 License

This project is developed as part of a research internship and is intended for educational and academic demonstration purposes.

---

## 👤 Author

**Swarn Ranjan**  
📧 swarnranjan.2004@gmail.com  
🔗 [LinkedIn](https://linkedin.com/in/swarn-ranjan)  
🔗 [GitHub](https://github.com/swarnranjan) ← *(update with actual repo link)*
