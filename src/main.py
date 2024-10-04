import socket
import threading
import sys
import time
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox

# Configuration
PORT = 65432  # Port to use for communication
BUFFER_SIZE = 4096  # Increased buffer size for larger messages

def get_local_ip():
    """Fetches the local IP address of this machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

class ChatServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.groups = {}  # {group_name: {'passkey': str, 'participants': {username: connection}}}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lock = threading.Lock()  # For thread-safe access to shared data

    def start_server(self):
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen()
            print(f"Server listening on {self.host}:{self.port}...")
            while True:
                conn, addr = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.server_socket.close()

    def handle_client(self, conn, addr):
        group_name = None
        username = None

        try:
            while True:
                data = conn.recv(BUFFER_SIZE).decode()
                if not data:
                    break

                command, *args = data.strip().split(' ', 2)
                if command == 'create':
                    username, group_name, passkey = args[0].split(' ')
                    with self.lock:
                        if group_name in self.groups:
                            conn.sendall(b'Group already exists!')
                        else:
                            self.groups[group_name] = {'passkey': passkey, 'participants': {username: conn}}
                            conn.sendall(b'Group created successfully. Waiting for participants...')
                            print(f"Group '{group_name}' created by {username}.")
                elif command == 'join':
                    username, group_name, passkey = args[0].split(' ')
                    with self.lock:
                        if group_name in self.groups and self.groups[group_name]['passkey'] == passkey:
                            self.groups[group_name]['participants'][username] = conn
                            conn.sendall(b'Joined group successfully.')
                            self.broadcast_message(group_name, f"<{username}> joined the group.", exclude=username)
                            print(f"{username} joined group '{group_name}'.")
                        else:
                            conn.sendall(b'Failed to join group. Check group name and passkey.')
                elif command == 'msg':
                    group_name, message = args[0].split(' ', 1)
                    with self.lock:
                        if group_name in self.groups and username in self.groups[group_name]['participants']:
                            self.broadcast_message(group_name, f"{username}: {message}")
                        else:
                            conn.sendall(b'You are not in this group.')
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
            print(f"Error handling client {addr}: {e}")
        finally:
            with self.lock:
                if group_name and username:
                    participants = self.groups.get(group_name, {}).get('participants', {})
                    if username in participants:
                        del participants[username]
            conn.close()
            print(f"Disconnected from {addr}")

    def broadcast_message(self, group_name, message, exclude=None):
        participants = self.groups.get(group_name, {}).get('participants', {})
        for participant, conn in participants.items():
            if participant != exclude:
                try:
                    conn.sendall(message.encode())
                except:
                    print(f"Failed to send message to {participant}.")

class ChatClient:
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
        try:
            self.sock.connect((self.server_ip, self.port))
            if mode == 'create':
                self.sock.sendall(f'create {self.username} {self.group_name} {self.passkey}'.encode())
            elif mode == 'join':
                self.sock.sendall(f'join {self.username} {self.group_name} {self.passkey}'.encode())
            response = self.sock.recv(BUFFER_SIZE).decode()
            if 'successfully' in response:
                self.gui_app.add_message(response)
                threading.Thread(target=self.receive_messages, daemon=True).start()
            else:
                self.gui_app.add_message(response)
                self.sock.close()
        except Exception as e:
            self.gui_app.add_message(f"Connection error: {e}")

    def receive_messages(self):
        while not self.stop_threads.is_set():
            try:
                message = self.sock.recv(BUFFER_SIZE).decode()
                if message:
                    self.gui_app.add_message(message)
            except Exception as e:
                self.gui_app.add_message(f"Receive error: {e}")
                self.stop_threads.set()
                break

    def send_message(self, message):
        try:
            if message.strip().lower() == '/exit':
                self.sock.sendall(f'exit'.encode())
                self.stop_threads.set()
            else:
                self.sock.sendall(f'msg {self.group_name} {message}'.encode())
        except Exception as e:
            self.gui_app.add_message(f"Send error: {e}")
            self.stop_threads.set()
            self.sock.close()

class ChatGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ChatMate")
        self.root.geometry("500x500")
        self.client = None

        self.create_login_screen()

    def create_login_screen(self):
        self.clear_screen()

        tk.Label(self.root, text="Welcome to ChatMate", font=("Helvetica", 16)).pack(pady=10)

        tk.Label(self.root, text="Username:").pack()
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack()

        tk.Label(self.root, text="Group Name:").pack()
        self.group_name_entry = tk.Entry(self.root)
        self.group_name_entry.pack()

        tk.Label(self.root, text="Passkey:").pack()
        self.passkey_entry = tk.Entry(self.root, show='*')
        self.passkey_entry.pack()

        tk.Label(self.root, text="Server IP:").pack()
        self.server_ip_entry = tk.Entry(self.root)
        self.server_ip_entry.pack()
        self.server_ip_entry.insert(0, "127.0.0.1")

        tk.Button(self.root, text="Create Group", command=self.create_group).pack(pady=5)
        tk.Button(self.root, text="Join Group", command=self.join_group).pack(pady=5)

    def create_group(self):
        username = self.username_entry.get()
        group_name = self.group_name_entry.get()
        passkey = self.passkey_entry.get()
        server_ip = self.server_ip_entry.get()

        if not username or not group_name or not passkey:
            messagebox.showerror("Error", "All fields are required.")
            return

        # Start server in a separate thread
        local_ip = server_ip if server_ip else '127.0.0.1'
        chat_server = ChatServer(local_ip, PORT)
        server_thread = threading.Thread(target=chat_server.start_server, daemon=True)
        server_thread.start()
        time.sleep(1)

        # Start client
        self.client = ChatClient(username, group_name, passkey, local_ip, PORT, self)
        self.client.connect_to_server('create')
        self.create_chat_screen()

    def join_group(self):
        username = self.username_entry.get()
        group_name = self.group_name_entry.get()
        passkey = self.passkey_entry.get()
        server_ip = self.server_ip_entry.get()

        if not username or not group_name or not passkey or not server_ip:
            messagebox.showerror("Error", "All fields are required.")
            return

        # Start client
        self.client = ChatClient(username, group_name, passkey, server_ip, PORT, self)
        self.client.connect_to_server('join')
        self.create_chat_screen()

    def create_chat_screen(self):
        self.clear_screen()

        self.chat_display = scrolledtext.ScrolledText(self.root, state='disabled', wrap=tk.WORD)
        self.chat_display.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.message_entry = tk.Entry(self.root)
        self.message_entry.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.X, expand=True)
        self.message_entry.bind("<Return>", self.send_message)

        tk.Button(self.root, text="Send", command=self.send_message).pack(side=tk.RIGHT, padx=10, pady=10)

    def add_message(self, message):
        self.chat_display.configure(state='normal')
        self.chat_display.insert(tk.END, message + '\n')
        self.chat_display.configure(state='disabled')
        self.chat_display.see(tk.END)

    def send_message(self, event=None):
        message = self.message_entry.get()
        if message:
            self.client.send_message(message)
            self.message_entry.delete(0, tk.END)

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def run(self):
        self.root.mainloop()

def main():
    app = ChatGUI()
    app.run()

if __name__ == "__main__":
    main()
