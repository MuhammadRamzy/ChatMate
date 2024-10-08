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
                                    self.send_user_list(group_name)
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
                                    self.send_user_list(group_name)
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
                            msg_group_name, message = args[0].split(' ', 1)
                            with self.lock:
                                if msg_group_name in self.groups and username in self.groups[msg_group_name]['participants']:
                                    self.broadcast_message(msg_group_name, f"{username}: {message}")
                                else:
                                    conn.sendall(b'You are not in this group.')
                        else:
                            conn.sendall(b'Invalid command format for msg.')
                    else:
                        conn.sendall(b'Missing arguments for msg command.')
                elif command == 'pm':
                    if args:
                        parts = args[0].split(' ', 2)
                        if len(parts) == 3:
                            pm_group_name, target_user, message = parts
                            with self.lock:
                                if pm_group_name in self.groups and username in self.groups[pm_group_name]['participants']:
                                    participants = self.groups[pm_group_name]['participants']
                                    if target_user in participants:
                                        conn_target = participants[target_user]
                                        conn_target.sendall(f"(Private) {username}: {message}".encode())
                                        conn.sendall(f"(Private to {target_user}) You: {message}".encode())
                                    else:
                                        conn.sendall(b'The user is not in the group.')
                                else:
                                    conn.sendall(b'You are not in this group.')
                        else:
                            conn.sendall(b'Invalid command format for pm.')
                    else:
                        conn.sendall(b'Missing arguments for pm command.')
                elif command == 'exit':
                    with self.lock:
                        if group_name and username:
                            participants = self.groups[group_name]['participants']
                            if username in participants:
                                del participants[username]
                                self.broadcast_message(group_name, f"<{username}> has left the group.")
                                self.send_user_list(group_name)
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
                        self.broadcast_message(group_name, f"<{username}> has left the group.")
                        self.send_user_list(group_name)
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

    def send_user_list(self, group_name):
        """
        Sends the updated user list to all participants in the group.
        """
        participants = self.groups.get(group_name, {}).get('participants', {})
        user_list = list(participants.keys())
        message = "userlist " + ",".join(user_list)
        for conn in participants.values():
            try:
                conn.sendall(message.encode())
            except Exception as e:
                logging.error(f"Failed to send user list: {e}")


class ChatClient(QtCore.QObject):
    """
    A class representing the chat client.
    Connects to a chat server and communicates with it.
    """
    message_received = QtCore.pyqtSignal(str)
    connection_error = QtCore.pyqtSignal(str)
    connected = QtCore.pyqtSignal(str)
    user_list_updated = QtCore.pyqtSignal(list)

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
                    if message.startswith("userlist"):
                        user_list = message[len("userlist "):].split(',')
                        self.user_list_updated.emit(user_list)
                    else:
                        self.message_received.emit(message)
                else:
                    self.stop_threads.set()
            except Exception as e:
                self.connection_error.emit(f"Receive error: {e}")
                self.stop_threads.set()
                break

    def send_message(self, message, target_user=None):
        """
        Sends a message to the server.
        """
        try:
            if message.strip().lower() == '/exit':
                self.sock.sendall('exit'.encode())
                self.stop_threads.set()
                self.sock.close()
            else:
                if target_user:
                    # Send private message
                    self.sock.sendall(f'pm {self.group_name} {target_user} {message}'.encode())
                else:
                    # Send public message
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
        self.setGeometry(500, 500, 1000, 700)  # Increased window size
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
        self.client.user_list_updated.connect(self.update_user_list)

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
        self.client.user_list_updated.connect(self.update_user_list)

        self.init_chat_ui()
        self.client.connect_to_server('join')

    def init_chat_ui(self):
        """
        Sets up the chat screen where messages are displayed and can be sent.
        """
        self.resize(1000, 700)  # Increased window size
        self.central_widget = QtWidgets.QWidget()
        self.setCentralWidget(self.central_widget)

        main_layout = QtWidgets.QHBoxLayout(self.central_widget)

        # Left side - Chat display and input
        left_layout = QtWidgets.QVBoxLayout()
        main_layout.addLayout(left_layout, 3)  # Give 3/4 of the space

        # Chat display
        self.chat_display = QtWidgets.QTextEdit()
        self.chat_display.setReadOnly(True)
        left_layout.addWidget(self.chat_display)

        # Message entry and send button
        entry_layout = QtWidgets.QHBoxLayout()
        left_layout.addLayout(entry_layout)

        self.message_entry = QtWidgets.QLineEdit()
        self.message_entry.returnPressed.connect(self.send_message)
        entry_layout.addWidget(self.message_entry)

        send_button = QtWidgets.QPushButton("Send")
        send_button.clicked.connect(self.send_message)
        entry_layout.addWidget(send_button)

        # Right side - User list
        right_layout = QtWidgets.QVBoxLayout()
        main_layout.addLayout(right_layout, 1)  # Give 1/4 of the space

        user_list_label = QtWidgets.QLabel("Users in Chat")
        font = QtGui.QFont()
        font.setPointSize(10)
        font.setBold(True)
        user_list_label.setFont(font)
        user_list_label.setAlignment(QtCore.Qt.AlignCenter)
        right_layout.addWidget(user_list_label)

        self.user_list_widget = QtWidgets.QListWidget()
        right_layout.addWidget(self.user_list_widget)

        # Private message button
        pm_button = QtWidgets.QPushButton("Send Private Message")
        pm_button.clicked.connect(self.send_private_message)
        right_layout.addWidget(pm_button)

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

    def update_user_list(self, user_list):
        """
        Updates the user list displayed in the GUI.
        """
        self.user_list_widget.clear()
        self.user_list_widget.addItems(user_list)

    def send_private_message(self):
        """
        Sends a private message to the selected user.
        """
        selected_items = self.user_list_widget.selectedItems()
        if selected_items:
            target_user = selected_items[0].text()
            if target_user == self.client.username:
                QtWidgets.QMessageBox.warning(self, "Warning", "You cannot send a private message to yourself.")
                return
            message, ok = QtWidgets.QInputDialog.getText(self, "Private Message",
                                                         f"Enter message to {target_user}:")
            if ok and message:
                self.client.send_message(message, target_user=target_user)
        else:
            QtWidgets.QMessageBox.warning(self, "Warning", "Please select a user to send a private message.")

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
