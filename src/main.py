import socket
import threading
import os
import platform
import sys
import time
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.layout import Layout
from rich.text import Text
from rich import box
from pyfiglet import Figlet

console = Console()

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

def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def display_banner():
    """Displays the 'ChatMate' banner."""
    f = Figlet(font='slant')
    banner = f.renderText('ChatMate')
    console.print(Panel(Text(banner, justify="center", style="bold cyan"), style="bold blue"), justify="center")

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
            console.print(f"[bold cyan][*][/bold cyan] Server listening on {self.host}:{self.port}...", style="bold green")
            while True:
                conn, addr = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
        except Exception as e:
            console.print(f"[bold red][-][/bold red] Server error: {e}", style="bold red")
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
                            self.groups[group_name] = {'passkey': passkey, 'participants': [username]}
                            self.clients[username] = conn
                            conn.sendall(f'Group "{group_name}" created successfully. Waiting for participants...'.encode())
                            console.print(f"[bold cyan][+][/bold cyan] Group '{group_name}' created by {username}.", style="bold green")
                elif command == 'join':
                    username, group_name, passkey = args[0].split(' ')
                    with self.lock:
                        if group_name in self.groups and self.groups[group_name]['passkey'] == passkey:
                            self.groups[group_name]['participants'].append(username)
                            self.clients[username] = conn
                            conn.sendall(f'Joined group "{group_name}" successfully.'.encode())
                            self.broadcast_message(group_name, f"[bold green]<{username}> joined the group.[/bold green]", exclude=username)
                            console.print(f"[bold cyan][+][/bold cyan] {username} joined group '{group_name}'.", style="bold green")
                        else:
                            conn.sendall(b'Failed to join group. Check group name and passkey.')
                elif command == 'msg':
                    group_name, message = args[0].split(' ', 1)
                    with self.lock:
                        if group_name in self.groups and username in self.groups[group_name]['participants']:
                            self.broadcast_message(group_name, f"[bold blue]{username}[/bold blue]: {message}")
                        else:
                            conn.sendall(b'You are not in this group.')
                elif command == 'participants':
                    group_name = args[0]
                    with self.lock:
                        participants = self.groups.get(group_name, {}).get('participants', [])
                        participant_list = ', '.join(participants)
                        conn.sendall(f"Participants in {group_name}: {participant_list}".encode())
                elif command == 'pm':
                    group_name, target_user, pm_message = args[0].split(' ', 2)
                    with self.lock:
                        if group_name in self.groups and username in self.groups[group_name]['participants']:
                            target_conn = self.clients.get(target_user)
                            if target_conn:
                                target_conn.sendall(f"[bold magenta][PM from {username}][/bold magenta]: {pm_message}".encode())
                                conn.sendall(f"Private message sent to {target_user}".encode())
                            else:
                                conn.sendall(f"User {target_user} not found.".encode())
                        else:
                            conn.sendall(b'You are not in this group.')
                elif command == 'exit':
                    with self.lock:
                        if group_name and username and username in self.clients:
                            self.groups[group_name]['participants'].remove(username)
                            del self.clients[username]
                            self.broadcast_message(group_name, f"[bold yellow]<{username}> has left the group.[/bold yellow]")
                    break
                else:
                    conn.sendall(b'Unknown command.')
        except Exception as e:
            console.print(f"[bold red][-][/bold red] Error handling client {addr}: {e}", style="bold red")
        finally:
            with self.lock:
                if username and username in self.clients:
                    del self.clients[username]
                if group_name and username in self.groups.get(group_name, {}).get('participants', []):
                    self.groups[group_name]['participants'].remove(username)
            conn.close()
            console.print(f"[bold yellow][-][/bold yellow] Disconnected from {addr}", style="bold yellow")

    def broadcast_message(self, group_name, message, exclude=None):
        participants = self.groups.get(group_name, {}).get('participants', [])
        for participant in participants:
            if participant != exclude:
                participant_conn = self.clients.get(participant)
                if participant_conn:
                    try:
                        participant_conn.sendall(message.encode())
                    except:
                        console.print(f"[bold red][-][/bold red] Failed to send message to {participant}.", style="bold red")

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
            console.print(Panel(response, style="bold green"))
            if 'successfully' in response:
                threading.Thread(target=self.receive_messages, daemon=True).start()
                self.send_messages()
            else:
                self.sock.close()
        except Exception as e:
            console.print(f"[bold red][-][/bold red] Connection error: {e}", style="bold red")

    def receive_messages(self):
        while not self.stop_threads.is_set():
            try:
                message = self.sock.recv(BUFFER_SIZE).decode()
                if message:
                    console.print(f"\r{message}")
            except Exception as e:
                console.print(f"[bold red][-][/bold red] Receive error: {e}", style="bold red")
                self.stop_threads.set()
                break

    def send_messages(self):
        try:
            while not self.stop_threads.is_set():
                message = console.input(f"[bold cyan]{self.username} > [/bold cyan]")
                if message.strip().lower() == '/exit':
                    self.sock.sendall(f'exit'.encode())
                    self.stop_threads.set()
                    break
                elif message.strip().lower() == '/participants':
                    self.sock.sendall(f'participants {self.group_name}'.encode())
                elif message.startswith('/pm '):
                    parts = message.split(' ', 2)
                    if len(parts) >= 3:
                        target_user = parts[1]
                        pm_message = parts[2]
                        self.sock.sendall(f'pm {self.group_name} {target_user} {pm_message}'.encode())
                    else:
                        console.print("[bold red]Invalid private message format. Use /pm username message[/bold red]")
                else:
                    self.sock.sendall(f'msg {self.group_name} {message}'.encode())
        except KeyboardInterrupt:
            self.sock.sendall(f'exit'.encode())
            self.stop_threads.set()
        except Exception as e:
            console.print(f"[bold red][-][/bold red] Send error: {e}", style="bold red")
            self.stop_threads.set()
        finally:
            self.sock.close()

def create_group():
    clear_screen()
    display_banner()
    username = Prompt.ask("[bold cyan]Enter your username[/bold cyan]")
    group_name = Prompt.ask("[bold cyan]Enter group name[/bold cyan]")
    passkey = Prompt.ask("[bold cyan]Enter group passkey[/bold cyan]", password=True)

    local_ip = get_local_ip()
    # Start server in a separate thread
    chat_server = ChatServer(local_ip, PORT)
    server_thread = threading.Thread(target=chat_server.start_server, daemon=True)
    server_thread.start()

    console.print(f"[bold green]Your IP Address is: {local_ip}[/bold green]")
    console.print("[bold yellow]Share this IP with others to let them join your group.[/bold yellow]")
    console.print("[bold magenta]Waiting for participants to join...[/bold magenta]\n")

    # Wait a moment for the server to start
    time.sleep(1)

    # Start client
    chat_client = ChatClient(username, group_name, passkey, local_ip, PORT)
    chat_client.connect_to_server('create')

def join_group():
    clear_screen()
    display_banner()
    username = Prompt.ask("[bold cyan]Enter your username[/bold cyan]")
    group_name = Prompt.ask("[bold cyan]Enter group name[/bold cyan]")
    passkey = Prompt.ask("[bold cyan]Enter group passkey[/bold cyan]", password=True)
    server_ip = Prompt.ask("[bold cyan]Enter group creator's IP address[/bold cyan]")

    # Start client
    chat_client = ChatClient(username, group_name, passkey, server_ip, PORT)
    chat_client.connect_to_server('join')

def main_menu():
    table = Table(title="Main Menu", show_header=False, box=box.ROUNDED)
    table.add_row("[bold green][1][/bold green]", "Create a new group")
    table.add_row("[bold green][2][/bold green]", "Join an existing group")
    table.add_row("[bold green][3][/bold green]", "Exit")
    console.print(table)

def main():
    while True:
        try:
            clear_screen()
            display_banner()
            main_menu()
            choice = Prompt.ask("[bold yellow]Choose an option[/bold yellow]", choices=['1', '2', '3'], default='3')

            if choice == '1':
                create_group()
            elif choice == '2':
                join_group()
            elif choice == '3':
                console.print("[bold yellow]Exiting...[/bold yellow]")
                sys.exit(0)
            else:
                console.print("[bold red]Invalid option. Please try again.[/bold red]")
                console.input("Press Enter to continue...")
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Exiting...[/bold yellow]")
            sys.exit(0)
        except Exception as e:
            console.print(f"[bold red]An error occurred: {e}[/bold red]")
            console.input("Press Enter to continue...")

if __name__ == "__main__":
    main()
