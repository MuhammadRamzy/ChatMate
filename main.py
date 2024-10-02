import socket
import threading
import random
import os
import platform
import shutil
from termcolor import colored
from pyfiglet import Figlet

# Configuration
PORT = 65432  # Port to use for communication
BUFFER_SIZE = 1024  # Buffer size for receiving messages

# Store groups and their participants
groups = {}

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

def handle_client(conn, addr):
    """Handles communication with a client."""
    print(colored(f"[+] Connected by {addr}", 'green'))
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
                    conn.sendall(b'Group created successfully. Waiting for participants...')
                    print(colored(f"[+] Group '{group_name}' created by {username}.", 'cyan'))

            elif command == 'join':
                username, group_name, passkey = args
                if group_name in groups and groups[group_name]['passkey'] == passkey:
                    groups[group_name]['participants'].append(username)
                    conn.sendall(b'Joined group successfully.')
                    print(colored(f"[+] {username} joined group '{group_name}'.", 'cyan'))
                    # Notify other participants
                    broadcast_message(group_name, f"{username} has joined the group.", exclude=username)
                else:
                    conn.sendall(b'Failed to join group. Check group name and passkey.')

            elif command == 'msg':
                group_name, message = args[0], ' '.join(args[1:])
                if group_name in groups:
                    broadcast_message(group_name, f"{username}: {message}", exclude=username)

            elif command == 'exit':
                if group_name and username:
                    groups[group_name]['participants'].remove(username)
                    broadcast_message(group_name, f"{username} has left the group.", exclude=username)
                break
            
    except Exception as e:
        print(colored(f"[-] Error handling client {addr}: {e}", 'red'))
    finally:
        conn.close()
        print(colored(f"[-] Disconnected from {addr}", 'yellow'))

def broadcast_message(group_name, message, exclude=None):
    """Broadcasts a message to all participants in a group."""
    for participant in groups[group_name]['participants']:
        if participant != exclude:
            participant_conn = find_connection(participant)
            if participant_conn:
                participant_conn.sendall(message.encode())

def find_connection(username):
    """Finds the connection associated with a username (not implemented here)."""
    # This function can be implemented to maintain a mapping of usernames to connections.
    return None

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

def main():
    clear_screen()
    display_banner()

    local_ip = get_local_ip()
    print(colored(f"[*] Your local IP address is {local_ip}", 'cyan'))

    # Start the server in a separate thread
    server_thread = threading.Thread(target=server, args=(local_ip,), daemon=True)
    server_thread.start()

    try:
        while True:
            command = input(colored("ChatMate > ", 'green')).strip()
            if command.lower() == 'exit':
                print(colored("[*] Exiting the program. Goodbye!", 'cyan'))
                break
            else:
                print(colored("[-] Unknown command. Type 'exit' to leave.", 'yellow'))
    except KeyboardInterrupt:
        print(colored("\n[*] Keyboard interrupt received. Exiting.", 'cyan'))

if __name__ == "__main__":
    main()
