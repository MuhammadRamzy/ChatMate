import socket
import threading
import os
import platform
import shutil
from termcolor import colored
from pyfiglet import Figlet
import sys
import time

# Configuration
PORT = 65432  # Port to use for communication
BUFFER_SIZE = 1024  # Buffer size for receiving messages

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

def clear_screen():
    """Clears the terminal screen."""
    if platform.system() == 'Windows':
        os.system('cls')
    else:
        os.system('clear')

def display_banner():
    """Displays the 'ChatMate' banner."""
    f = Figlet(font='slant')
    banner = f.renderText('ChatMate')
    terminal_size = shutil.get_terminal_size()
    banner_lines = banner.split('\n')
    centered_banner = '\n'.join(line.center(terminal_size.columns) for line in banner_lines)
    print(colored(centered_banner, 'cyan'))

class ChatServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.groups = {}  # {group_name: {'passkey': str, 'participants': [username]}}
        self.clients = {}  # {username: connection}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lock = threading.Lock()  # For thread-safe access to shared data

    def start_server(self):
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen()
            print(colored(f"[*] Server listening on {self.host}:{self.port}...", 'cyan'))
            while True:
                conn, addr = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
        except Exception as e:
            print(colored(f"[-] Server error: {e}", 'red'))
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

                command, *args = data.strip().split(' ')

                if command == 'create':
                    username, group_name, passkey = args
                    with self.lock:
                        if group_name in self.groups:
                            conn.sendall(b'Group already exists!')
                        else:
                            self.groups[group_name] = {'passkey': passkey, 'participants': [username]}
                            self.clients[username] = conn
                            conn.sendall(b'Group created successfully. Waiting for participants...')
                            print(colored(f"[+] Group '{group_name}' created by {username}.", 'cyan'))

                elif command == 'join':
                    username, group_name, passkey = args
                    with self.lock:
                        if group_name in self.groups and self.groups[group_name]['passkey'] == passkey:
                            self.groups[group_name]['participants'].append(username)
                            self.clients[username] = conn
                            conn.sendall(b'Joined group successfully.')
                            self.broadcast_message(group_name, f"<{username}> joined the group.", exclude=username)
                            print(colored(f"[+] {username} joined group '{group_name}'.", 'cyan'))
                        else:
                            conn.sendall(b'Failed to join group. Check group name and passkey.')

                elif command == 'msg':
                    group_name = args[0]
                    message = ' '.join(args[1:])
                    with self.lock:
                        if group_name in self.groups and username in self.groups[group_name]['participants']:
                            self.broadcast_message(group_name, f"{username}: {message}", exclude=None)
                        else:
                            conn.sendall(b'You are not in this group.')

                elif command == 'exit':
                    with self.lock:
                        if group_name and username and username in self.clients:
                            self.groups[group_name]['participants'].remove(username)
                            del self.clients[username]
                            self.broadcast_message(group_name, f"<{username}> has left the group.")
                    break

                else:
                    conn.sendall(b'Unknown command.')

        except Exception as e:
            print(colored(f"[-] Error handling client {addr}: {e}", 'red'))
        finally:
            with self.lock:
                if username and username in self.clients:
                    del self.clients[username]
                if group_name and username in self.groups.get(group_name, {}).get('participants', []):
                    self.groups[group_name]['participants'].remove(username)
            conn.close()
            print(colored(f"[-] Disconnected from {addr}", 'yellow'))

    def broadcast_message(self, group_name, message, exclude=None):
        participants = self.groups.get(group_name, {}).get('participants', [])
        for participant in participants:
            if participant != exclude:
                participant_conn = self.clients.get(participant)
                if participant_conn:
                    try:
                        participant_conn.sendall(message.encode())
                    except:
                        print(colored(f"[-] Failed to send message to {participant}.", 'red'))

class ChatClient:
    def __init__(self, username, group_name, passkey, server_ip, port):
        self.username = username
        self.group_name = group_name
        self.passkey = passkey
        self.server_ip = server_ip
        self.port = port
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
            print(response)
            if 'successfully' in response:
                threading.Thread(target=self.receive_messages, daemon=True).start()
                self.send_messages()
            else:
                self.sock.close()
        except Exception as e:
            print(colored(f"[-] Connection error: {e}", 'red'))

    def receive_messages(self):
        while not self.stop_threads.is_set():
            try:
                message = self.sock.recv(BUFFER_SIZE).decode()
                if message:
                    print(f"\r{message}\n{self.username} > ", end='')
            except Exception as e:
                print(colored(f"[-] Receive error: {e}", 'red'))
                self.stop_threads.set()
                break

    def send_messages(self):
        try:
            while not self.stop_threads.is_set():
                message = input(f"{self.username} > ")
                if message.strip().lower() == 'exit':
                    self.sock.sendall(f'exit'.encode())
                    self.stop_threads.set()
                    break
                else:
                    self.sock.sendall(f'msg {self.group_name} {message}'.encode())
        except KeyboardInterrupt:
            self.sock.sendall(f'exit'.encode())
            self.stop_threads.set()
        except Exception as e:
            print(colored(f"[-] Send error: {e}", 'red'))
            self.stop_threads.set()
        finally:
            self.sock.close()

def create_group():
    username = input("Enter your username: ").strip()
    group_name = input("Enter group name: ").strip()
    passkey = input("Enter group passkey: ").strip()

    local_ip = get_local_ip()
    # Start server in a separate thread
    chat_server = ChatServer(local_ip, PORT)
    server_thread = threading.Thread(target=chat_server.start_server, daemon=True)
    server_thread.start()

    # Wait a moment for the server to start
    time.sleep(1)

    # Start client
    chat_client = ChatClient(username, group_name, passkey, local_ip, PORT)
    chat_client.connect_to_server('create')

def join_group():
    username = input("Enter your username: ").strip()
    group_name = input("Enter group name: ").strip()
    passkey = input("Enter group passkey: ").strip()
    server_ip = input("Enter group creator's IP address: ").strip()

    # Start client
    chat_client = ChatClient(username, group_name, passkey, server_ip, PORT)
    chat_client.connect_to_server('join')

def main():
    while True:
        try:
            clear_screen()
            display_banner()
            print(colored("[1] Create a new group", 'green'))
            print(colored("[2] Join an existing group", 'green'))
            print(colored("[3] Exit", 'green'))

            choice = input(colored("Choose an option (1/2/3): ", 'yellow')).strip()

            if choice == '1':
                create_group()
            elif choice == '2':
                join_group()
            elif choice == '3':
                print(colored("Exiting...", 'yellow'))
                sys.exit(0)
            else:
                print(colored("Invalid option. Please try again.", 'red'))
                input("Press Enter to continue...")
        except KeyboardInterrupt:
            print(colored("\nExiting...", 'yellow'))
            sys.exit(0)
        except Exception as e:
            print(colored(f"An error occurred: {e}", 'red'))
            input("Press Enter to continue...")

if __name__ == "__main__":
    main()
