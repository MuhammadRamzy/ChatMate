import socket
import threading
import os
import platform
import shutil
from termcolor import colored
from pyfiglet import Figlet

# Configuration
PORT = 65432  # Port to use for communication
BUFFER_SIZE = 1024  # Buffer size for receiving messages
groups = {}  # Store groups and their participants
clients = {}  # Store connected clients {username: connection}
group_name = None
username = None

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

def handle_client(conn, addr):
    """Handles communication with a client."""
    global groups, clients

    group_name = None
    username = None

    try:
        while True:
            data = conn.recv(BUFFER_SIZE).decode()
            if not data:
                break

            command, *args = data.split(' ')

            if command == 'create':
                username, group_name, passkey = args
                if group_name in groups:
                    conn.sendall(b'Group already exists!')
                else:
                    groups[group_name] = {'passkey': passkey, 'participants': [username]}
                    clients[username] = conn
                    conn.sendall(b'Group created successfully. Waiting for participants...')
                    print(colored(f"[+] Group '{group_name}' created by {username}.", 'cyan'))

            elif command == 'join':
                username, group_name, passkey = args
                if group_name in groups and groups[group_name]['passkey'] == passkey:
                    groups[group_name]['participants'].append(username)
                    clients[username] = conn
                    conn.sendall(b'Joined group successfully.')
                    broadcast_message(group_name, f"<{username}> joined the group.")
                    print(colored(f"[+] {username} joined group '{group_name}'.", 'cyan'))
                else:
                    conn.sendall(b'Failed to join group. Check group name and passkey.')

            elif command == 'msg':
                group_name, message = args[0], ' '.join(args[1:])
                if group_name in groups:
                    broadcast_message(group_name, f"{username}: {message}")

            elif command == 'exit':
                if group_name and username:
                    groups[group_name]['participants'].remove(username)
                    broadcast_message(group_name, f"<{username}> has left the group.")
                break

    except Exception as e:
        print(colored(f"[-] Error handling client {addr}: {e}", 'red'))
    finally:
        if username and username in clients:
            del clients[username]
        conn.close()
        print(colored(f"[-] Disconnected from {addr}", 'yellow'))

def broadcast_message(group_name, message, exclude=None):
    """Broadcasts a message to all participants in a group."""
    for participant in groups[group_name]['participants']:
        if participant != exclude:
            participant_conn = clients.get(participant)
            if participant_conn:
                try:
                    participant_conn.sendall(message.encode())
                except:
                    print(colored(f"[-] Failed to send message to {participant}.", 'red'))

def server(local_ip):
    """Runs a server to listen for client connections."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((local_ip, PORT))
        server_socket.listen()
        print(colored(f"[*] Server listening on {local_ip}:{PORT}...", 'cyan'))
        
        while True:
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()

def client_receive(sock):
    """Listens for messages from the server and prints them."""
    while True:
        try:
            message = sock.recv(BUFFER_SIZE).decode()
            if message:
                print(f"\r{message}\n{username} > ", end='')
        except:
            print("Connection closed.")
            break

def client_send(sock, group_name):
    """Handles sending messages to the server."""
    while True:
        message = input(f"{username} > ")
        if message.strip().lower() == 'exit':
            sock.sendall(f'exit {group_name}'.encode())
            break
        sock.sendall(f'msg {group_name} {message}'.encode())

def create_group():
    """Creates a group and starts a server."""
    global username, group_name
    username = input("Enter your username: ").strip()
    group_name = input("Enter group name: ").strip()
    passkey = input("Enter group passkey: ").strip()
    
    local_ip = get_local_ip()
    server_thread = threading.Thread(target=server, args=(local_ip,), daemon=True)
    server_thread.start()

    # Client side to connect to your own server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((local_ip, PORT))
        sock.sendall(f'create {username} {group_name} {passkey}'.encode())
        print(sock.recv(BUFFER_SIZE).decode())
        
        threading.Thread(target=client_receive, args=(sock,), daemon=True).start()
        client_send(sock, group_name)

def join_group():
    """Joins an existing group."""
    global username, group_name
    username = input("Enter your username: ").strip()
    group_name = input("Enter group name: ").strip()
    passkey = input("Enter group passkey: ").strip()
    creator_ip = input("Enter group creator's IP address: ").strip()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((creator_ip, PORT))
        sock.sendall(f'join {username} {group_name} {passkey}'.encode())
        print(sock.recv(BUFFER_SIZE).decode())
        
        threading.Thread(target=client_receive, args=(sock,), daemon=True).start()
        client_send(sock, group_name)

def main():
    clear_screen()
    display_banner()

    print(colored("[1] Create a new group", 'green'))
    print(colored("[2] Join an existing group", 'green'))

    choice = input(colored("Choose an option (1/2): ", 'yellow')).strip()
    
    if choice == '1':
        create_group()
    elif choice == '2':
        join_group()
    else:
        print(colored("Invalid option. Exiting...", 'red'))

if __name__ == "__main__":
    main()
