import socket
import threading
import time
import logging
from datetime import datetime
from PyQt5 import QtWidgets, QtCore, QtGui

# Configuration
PORT = 65433  # Changed Port to avoid conflicts
BUFFER_SIZE = 4096  # Increased buffer size for larger messages

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_local_ip():
    """
    Fetches the local IP address of this machine.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = '127.0.0.1'
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception as e:
        logging.error(f"Error obtaining local IP: {e}")
    finally:
        s.close()
    return ip


class ChatServer:
    """
    A class representing the chat server.
    Manages groups and participants.
    """
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.groups = {}  # {group_name: {'passkey': str, 'participants': {username: connection}}}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lock = threading.Lock()  # For thread-safe access to shared data

    def start_server(self):
        """
        Starts the chat server to listen for incoming connections.
        """
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen()
            logging.info(f"Server listening on {self.host}:{self.port}...")
            while True:
                conn, addr = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
        except Exception as e:
            logging.error(f"Server error: {e}")
        finally:
            self.server_socket.close()

    def handle_client(self, conn, addr):
        """
        Handles communication with a connected client.
        """
        group_name = None
        username = None

        try:
            while True:
                data = conn.recv(BUFFER_SIZE).decode()
                if not data:
                    break

                command, *args = data.strip().split(' ', 1)
                if command == 'create':
                    if args:
                        username_group_passkey = args[0].split(' ', 2)
                        if len(username_group_passkey) == 3:
                            username, group_name, passkey = username_group_passkey
                            with self.lock:
                                if group_name in self.groups:
                                    conn.sendall(b'Group already exists!')
                                else:
                                    self.groups[group_name] = {'passkey': passkey, 'participants': {username: conn}}
                                    conn.sendall(b'Group created successfully. Waiting for participants...')
                                    logging.info(f"Group '{group_name}' created by {username}.")
                        else:
                            conn.sendall(b'Invalid command format for create.')
                    else:
                        conn.sendall(b'Missing arguments for create command.')
                elif command == 'join':
                    if args:
                        username_group_passkey = args[0].split(' ', 2)
                        if len(username_group_passkey) == 3:
                            username, group_name, passkey = username_group_passkey
                            with self.lock:
                                if group_name in self.groups and self.groups[group_name]['passkey'] == passkey:
                                    self.groups[group_name]['participants'][username] = conn
                                    conn.sendall(b'Joined group successfully.')
                                    self.broadcast_message(group_name, f"<{username}> joined the group.", exclude=username)
                                    logging.info(f"{username} joined group '{group_name}'.")
                                else:
                                    conn.sendall(b'Failed to join group. Check group name and passkey.')
                        else:
                            conn.sendall(b'Invalid command format for join.')
                    else:
                        conn.sendall(b'Missing arguments for join command.')
                elif command == 'msg':
                    if args:
                        if ' ' in args[0]:
                            group_name_msg = args[0].split(' ', 1)
                            group_name = group_name_msg[0]
                            message = group_name_msg[1]
                            with self.lock:
                                if group_name in self.groups and username in self.groups[group_name]['participants']:
                                    self.broadcast_message(group_name, f"{username}: {message}")
                                else:
                                    conn.sendall(b'You are not in this group.')
                        else:
                            conn.sendall(b'Invalid command format for msg.')
                    else:
                        conn.sendall(b'Missing arguments for msg command.')
                elif command == 'exit':
                    with self.lock:
                        if group_name and username:
                            participants = self.groups[group_name]['participants']
                            if username in participants:
                                del participants[username]
                                self.broadcast_message(group_name, f"<{username}> has left the group.")
                    break
                else:
                    conn.sendall(b'Unknown command.')
        except Exception as e:
            logging.error(f"Error handling client {addr}: {e}")
        finally:
            with self.lock:
                if group_name and username:
                    participants = self.groups.get(group_name, {}).get('participants', {})
                    if username in participants:
                        del participants[username]
            conn.close()
            logging.info(f"Disconnected from {addr}")

    def broadcast_message(self, group_name, message, exclude=None):
        """
        Sends a message to all participants in a group, optionally excluding one participant.
        """
        participants = self.groups.get(group_name, {}).get('participants', {})
        for participant, conn in participants.items():
            if participant != exclude:
                try:
                    conn.sendall(message.encode())
                except Exception as e:
                    logging.error(f"Failed to send message to {participant}: {e}")


class ChatClient(QtCore.QObject):
    """
    A class representing the chat client.
    Connects to a chat server and communicates with it.
    """
    message_received = QtCore.pyqtSignal(str)
    connection_error = QtCore.pyqtSignal(str)
    connected = QtCore.pyqtSignal(str)

    def __init__(self, username, group_name, passkey, server_ip, port):
        super().__init__()
        self.username = username
        self.group_name = group_name
        self.passkey = passkey
        self.server_ip = server_ip
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.stop_threads = threading.Event()

    def connect_to_server(self, mode):
        """
        Connects to the chat server and sends the appropriate command (create or join).
        """
        threading.Thread(target=self._connect, args=(mode,), daemon=True).start()

    def _connect(self, mode):
        try:
            self.sock.connect((self.server_ip, self.port))
            if mode == 'create':
                self.sock.sendall(f'create {self.username} {self.group_name} {self.passkey}'.encode())
            elif mode == 'join':
                self.sock.sendall(f'join {self.username} {self.group_name} {self.passkey}'.encode())
            else:
                self.connection_error.emit("Invalid mode.")
                self.sock.close()
                return

            response = self.sock.recv(BUFFER_SIZE).decode()
            if 'successfully' in response:
                self.connected.emit(response)
                threading.Thread(target=self.receive_messages, daemon=True).start()
            else:
                self.connection_error.emit(response)
                self.sock.close()
        except Exception as e:
            self.connection_error.emit(f"Connection error: {e}")
            self.sock.close()

    def receive_messages(self):
        """
        Receives messages from the server and emits them to the GUI.
        """
        while not self.stop_threads.is_set():
            try:
                message = self.sock.recv(BUFFER_SIZE).decode()
                if message:
                    self.message_received.emit(message)
                else:
                    self.stop_threads.set()
            except Exception as e:
                self.connection_error.emit(f"Receive error: {e}")
                self.stop_threads.set()
                break

    def send_message(self, message):
        """
        Sends a message to the server.
        """
        try:
            if message.strip().lower() == '/exit':
                self.sock.sendall('exit'.encode())
                self.stop_threads.set()
                self.sock.close()
            else:
                self.sock.sendall(f'msg {self.group_name} {message}'.encode())
        except Exception as e:
            self.connection_error.emit(f"Send error: {e}")
            self.stop_threads.set()
            self.sock.close()


class ChatGUI(QtWidgets.QMainWindow):
    """
    A class representing the chat GUI.
    Manages the user interface and interactions.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ChatMate")
        self.setGeometry(100, 100, 500, 500)
        self.client = None

        self.init_login_ui()

    def init_login_ui(self):
        """
        Creates the login screen for the user to enter credentials and server details.
        """
        self.central_widget = QtWidgets.QWidget()
        self.setCentralWidget(self.central_widget)

        layout = QtWidgets.QVBoxLayout(self.central_widget)

        title = QtWidgets.QLabel("Welcome to ChatMate")
        title.setAlignment(QtCore.Qt.AlignCenter)
        font = QtGui.QFont()
        font.setPointSize(18)
        font.setBold(True)
        title.setFont(font)
        layout.addWidget(title)

        form_layout = QtWidgets.QFormLayout()
        layout.addLayout(form_layout)

        # Username
        self.username_entry = QtWidgets.QLineEdit()
        form_layout.addRow("Username:", self.username_entry)

        # Group Name
        self.group_name_entry = QtWidgets.QLineEdit()
        form_layout.addRow("Group Name:", self.group_name_entry)

        # Passkey
        self.passkey_entry = QtWidgets.QLineEdit()
        self.passkey_entry.setEchoMode(QtWidgets.QLineEdit.Password)
        form_layout.addRow("Passkey:", self.passkey_entry)

        # Server IP
        self.server_ip_entry = QtWidgets.QLineEdit()
        self.server_ip_entry.setText("127.0.0.1")
        form_layout.addRow("Server IP:", self.server_ip_entry)

        # Buttons
        button_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(button_layout)

        create_button = QtWidgets.QPushButton("Create Group")
        create_button.clicked.connect(self.create_group)
        button_layout.addWidget(create_button)

        join_button = QtWidgets.QPushButton("Join Group")
        join_button.clicked.connect(self.join_group)
        button_layout.addWidget(join_button)

    def create_group(self):
        """
        Handles the creation of a new chat group and starts the server.
        """
        username = self.username_entry.text().strip()
        group_name = self.group_name_entry.text().strip()
        passkey = self.passkey_entry.text().strip()
        server_ip = self.server_ip_entry.text().strip()

        if not username or not group_name or not passkey:
            QtWidgets.QMessageBox.critical(self, "Error", "All fields are required.")
            return

        local_ip = server_ip if server_ip else get_local_ip()

        # Start server in a separate thread
        chat_server = ChatServer(local_ip, PORT)
        server_thread = threading.Thread(target=chat_server.start_server, daemon=True)
        server_thread.start()
        time.sleep(1)

        # Start client
        self.client = ChatClient(username, group_name, passkey, local_ip, PORT)
        self.client.message_received.connect(self.add_message)
        self.client.connection_error.connect(self.show_error)
        self.client.connected.connect(self.add_message)

        self.init_chat_ui()
        self.client.connect_to_server('create')

    def join_group(self):
        """
        Handles joining an existing chat group.
        """
        username = self.username_entry.text().strip()
        group_name = self.group_name_entry.text().strip()
        passkey = self.passkey_entry.text().strip()
        server_ip = self.server_ip_entry.text().strip()

        if not username or not group_name or not passkey or not server_ip:
            QtWidgets.QMessageBox.critical(self, "Error", "All fields are required.")
            return

        # Start client
        self.client = ChatClient(username, group_name, passkey, server_ip, PORT)
        self.client.message_received.connect(self.add_message)
        self.client.connection_error.connect(self.show_error)
        self.client.connected.connect(self.add_message)

        self.init_chat_ui()
        self.client.connect_to_server('join')

    def init_chat_ui(self):
        """
        Sets up the chat screen where messages are displayed and can be sent.
        """
        self.resize(800, 600)
        self.central_widget = QtWidgets.QWidget()
        self.setCentralWidget(self.central_widget)

        layout = QtWidgets.QVBoxLayout(self.central_widget)

        # Chat display
        self.chat_display = QtWidgets.QTextEdit()
        self.chat_display.setReadOnly(True)
        layout.addWidget(self.chat_display)

        # Message entry and send button
        entry_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(entry_layout)

        self.message_entry = QtWidgets.QLineEdit()
        self.message_entry.returnPressed.connect(self.send_message)
        entry_layout.addWidget(self.message_entry)

        send_button = QtWidgets.QPushButton("Send")
        send_button.clicked.connect(self.send_message)
        entry_layout.addWidget(send_button)

    def add_message(self, message):
        """
        Adds a message to the chat display with a timestamp.
        """
        timestamp = datetime.now().strftime('%H:%M:%S')

        if self.client and message.startswith(f"{self.client.username}:"):
            display_message = f"[{timestamp}] You: {message[len(self.client.username)+1:].strip()}\n"
        else:
            display_message = f"[{timestamp}] {message}\n"

        self.chat_display.append(display_message)

    def send_message(self):
        """
        Sends a message entered by the user.
        """
        message = self.message_entry.text().strip()
        if message:
            self.client.send_message(message)
            self.message_entry.clear()

    def show_error(self, error_message):
        """
        Displays an error message to the user.
        """
        QtWidgets.QMessageBox.critical(self, "Error", error_message)

    def closeEvent(self, event):
        """
        Handles the window close event to clean up resources.
        """
        if self.client:
            self.client.send_message('/exit')
        event.accept()


def main():
    import sys
    app = QtWidgets.QApplication(sys.argv)
    gui = ChatGUI()
    gui.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
