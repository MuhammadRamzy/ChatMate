import socket
import threading
import time
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import logging
from datetime import datetime

# Configuration
PORT = 65432  # Port to use for communication
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


class ChatClient:
    """
    A class representing the chat client.
    Connects to a chat server and communicates with it.
    """
    def __init__(self, username, group_name, passkey, server_ip, port, gui_app):
        self.username = username
        self.group_name = group_name
        self.passkey = passkey
        self.server_ip = server_ip
        self.port = port
        self.gui_app = gui_app
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.stop_threads = threading.Event()

    def connect_to_server(self, mode):
        """
        Connects to the chat server and sends the appropriate command (create or join).
        """
        try:
            self.sock.connect((self.server_ip, self.port))
            if mode == 'create':
                self.sock.sendall(f'create {self.username} {self.group_name} {self.passkey}'.encode())
            elif mode == 'join':
                self.sock.sendall(f'join {self.username} {self.group_name} {self.passkey}'.encode())
            else:
                self.gui_app.add_message("Invalid mode.")
                self.sock.close()
                return

            response = self.sock.recv(BUFFER_SIZE).decode()
            if 'successfully' in response:
                self.gui_app.add_message(response)
                threading.Thread(target=self.receive_messages, daemon=True).start()
            else:
                self.gui_app.add_message(response)
                self.sock.close()
        except Exception as e:
            self.gui_app.add_message(f"Connection error: {e}")
            self.sock.close()

    def receive_messages(self):
        """
        Receives messages from the server and displays them in the GUI.
        """
        while not self.stop_threads.is_set():
            try:
                message = self.sock.recv(BUFFER_SIZE).decode()
                if message:
                    self.gui_app.add_message(message)
                else:
                    self.stop_threads.set()
            except Exception as e:
                self.gui_app.add_message(f"Receive error: {e}")
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
            self.gui_app.add_message(f"Send error: {e}")
            self.stop_threads.set()
            self.sock.close()


class ChatGUI:
    """
    A class representing the chat GUI.
    Manages the user interface and interactions.
    """
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ChatMate")
        self.root.geometry("500x500")
        self.root.resizable(False, False)
        self.client = None

        # Set the style
        self.style = ttk.Style()
        self.style.theme_use('clam')

        self.create_login_screen()

    def create_login_screen(self):
        """
        Creates the login screen for the user to enter credentials and server details.
        """
        self.clear_screen()

        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_label = ttk.Label(main_frame, text="Welcome to ChatMate", font=("Helvetica", 18, 'bold'))
        title_label.pack(pady=20)

        form_frame = ttk.Frame(main_frame)
        form_frame.pack(pady=10)

        # Username
        ttk.Label(form_frame, text="Username:", font=("Helvetica", 12)).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.username_entry = ttk.Entry(form_frame, font=("Helvetica", 12))
        self.username_entry.grid(row=0, column=1, pady=5)

        # Group Name
        ttk.Label(form_frame, text="Group Name:", font=("Helvetica", 12)).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.group_name_entry = ttk.Entry(form_frame, font=("Helvetica", 12))
        self.group_name_entry.grid(row=1, column=1, pady=5)

        # Passkey
        ttk.Label(form_frame, text="Passkey:", font=("Helvetica", 12)).grid(row=2, column=0, sticky=tk.W, pady=5)
        self.passkey_entry = ttk.Entry(form_frame, show='*', font=("Helvetica", 12))
        self.passkey_entry.grid(row=2, column=1, pady=5)

        # Server IP
        ttk.Label(form_frame, text="Server IP:", font=("Helvetica", 12)).grid(row=3, column=0, sticky=tk.W, pady=5)
        self.server_ip_entry = ttk.Entry(form_frame, font=("Helvetica", 12))
        self.server_ip_entry.grid(row=3, column=1, pady=5)
        self.server_ip_entry.insert(0, "127.0.0.1")

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=20)

        create_button = ttk.Button(button_frame, text="Create Group", command=self.create_group, style='Accent.TButton')
        create_button.grid(row=0, column=0, padx=10)

        join_button = ttk.Button(button_frame, text="Join Group", command=self.join_group)
        join_button.grid(row=0, column=1, padx=10)

        # Style for Accent Button
        self.style.configure('Accent.TButton', foreground='white', background='#0078D7')
        self.style.map('Accent.TButton',
                       background=[('active', '#005A9E'), ('disabled', '#D6D6D6')])

    def create_group(self):
        """
        Handles the creation of a new chat group and starts the server.
        """
        username = self.username_entry.get().strip()
        group_name = self.group_name_entry.get().strip()
        passkey = self.passkey_entry.get().strip()
        server_ip = self.server_ip_entry.get().strip()

        if not username or not group_name or not passkey:
            messagebox.showerror("Error", "All fields are required.")
            return

        local_ip = server_ip if server_ip else '127.0.0.1'

        # Start server in a separate thread
        chat_server = ChatServer(local_ip, PORT)
        server_thread = threading.Thread(target=chat_server.start_server, daemon=True)
        server_thread.start()
        time.sleep(1)

        # Start client
        self.client = ChatClient(username, group_name, passkey, local_ip, PORT, self)
        self.client.connect_to_server('create')
        self.create_chat_screen()

    def join_group(self):
        """
        Handles joining an existing chat group.
        """
        username = self.username_entry.get().strip()
        group_name = self.group_name_entry.get().strip()
        passkey = self.passkey_entry.get().strip()
        server_ip = self.server_ip_entry.get().strip()

        if not username or not group_name or not passkey or not server_ip:
            messagebox.showerror("Error", "All fields are required.")
            return

        # Start client
        self.client = ChatClient(username, group_name, passkey, server_ip, PORT, self)
        self.client.connect_to_server('join')
        self.create_chat_screen()

    def create_chat_screen(self):
        """
        Sets up the chat screen where messages are displayed and can be sent.
        """
        self.clear_screen()

        self.root.geometry("600x500")
        self.root.resizable(True, True)

        main_frame = ttk.Frame(self.root, padding="5")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Chat display
        self.chat_display = scrolledtext.ScrolledText(main_frame, state='disabled', wrap=tk.WORD, font=("Helvetica", 12))
        self.chat_display.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        # Message entry frame
        entry_frame = ttk.Frame(main_frame)
        entry_frame.pack(fill=tk.X, pady=5)

        self.message_entry = ttk.Entry(entry_frame, font=("Helvetica", 12))
        self.message_entry.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)
        self.message_entry.bind("<Return>", self.send_message)

        send_button = ttk.Button(entry_frame, text="Send", command=self.send_message, style='Accent.TButton')
        send_button.pack(side=tk.RIGHT, padx=5)

    def add_message(self, message):
        """
        Adds a message to the chat display with a timestamp.
        """
        self.chat_display.configure(state='normal')
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.chat_display.insert(tk.END, f"[{timestamp}] {message}\n")
        self.chat_display.configure(state='disabled')
        self.chat_display.see(tk.END)

    def send_message(self, event=None):
        """
        Sends a message entered by the user.
        """
        message = self.message_entry.get().strip()
        if message:
            self.client.send_message(message)
            self.message_entry.delete(0, tk.END)

    def clear_screen(self):
        """
        Clears all widgets from the screen.
        """
        for widget in self.root.winfo_children():
            widget.destroy()

    def run(self):
        """
        Runs the GUI application.
        """
        self.root.mainloop()


def main():
    app = ChatGUI()
    app.run()


if __name__ == "__main__":
    main()
