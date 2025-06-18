import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLineEdit, QLabel, QFileDialog, QMessageBox
)
from PyQt5.QtCore import Qt
from client_logic import ChatClient

class ChatWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Chat Client")
        self.setGeometry(100, 100, 600, 500)

        self.chat_client = None

        self.init_ui()

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)

        layout = QVBoxLayout()

        # Username
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username")
        layout.addWidget(QLabel("Username:"))
        layout.addWidget(self.username_input)

        # Connect button
        self.connect_btn = QPushButton("Connect")
        self.connect_btn.clicked.connect(self.connect_to_server)
        layout.addWidget(self.connect_btn)

        # Recipient
        self.recipient_input = QLineEdit()
        self.recipient_input.setPlaceholderText("Recipient username")
        layout.addWidget(QLabel("Recipient:"))
        layout.addWidget(self.recipient_input)

        # Chat log
        self.chat_log = QTextEdit()
        self.chat_log.setReadOnly(True)
        layout.addWidget(self.chat_log)

        # Message input and send
        msg_layout = QHBoxLayout()
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message...")
        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self.send_message)
        msg_layout.addWidget(self.message_input)
        msg_layout.addWidget(self.send_btn)
        layout.addLayout(msg_layout)

        # File button
        self.file_btn = QPushButton("Send File")
        self.file_btn.clicked.connect(self.send_file)
        layout.addWidget(self.file_btn)

        central.setLayout(layout)

    def connect_to_server(self):
        username = self.username_input.text().strip()
        if not username:
            QMessageBox.warning(self, "Error", "Username is required.")
            return

        self.chat_client = ChatClient(username)
        self.chat_client.on('on_message', self.display_message)
        self.chat_client.on('on_file', self.display_file_status)
        self.chat_client.on('on_error', self.display_error)
        try:
            self.chat_client.connect()
            self.chat_log.append(f"[Connected] Logged in as '{username}'.")
            self.connect_btn.setEnabled(False)
            self.username_input.setEnabled(False)
        except Exception as e:
            QMessageBox.critical(self, "Connection Error", str(e))

    def send_message(self):
        if not self.chat_client:
            return
        message = self.message_input.text().strip()
        recipient = self.recipient_input.text().strip()
        if message and recipient:
            self.chat_client.send_message(recipient, message)
            self.chat_log.append(f"You to {recipient}: {message}")
            self.message_input.clear()

    def send_file(self):
        if not self.chat_client:
            return
        recipient = self.recipient_input.text().strip()
        if not recipient:
            QMessageBox.warning(self, "Error", "Recipient username is required.")
            return
        filepath, _ = QFileDialog.getOpenFileName(self, "Select File")
        if filepath:
            self.chat_log.append(f"[File] Sending '{filepath}' to {recipient}...")
            self.chat_client.send_file(recipient, filepath)

    def display_message(self, msg):
        self.chat_log.append(f"{msg}")

    def display_file_status(self, sender, filename, out_file, success):
        if success:
            self.chat_log.append(f"[File Received] {filename} from {sender} saved as recv_{filename}")
        else:
            self.chat_log.append(f"[File Error] Failed to verify file from {sender}")

    def display_error(self, err):
        self.chat_log.append(f"[Error] {err}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    win = ChatWindow()
    win.show()
    sys.exit(app.exec_())
