import socket
import threading
from termcolor import colored
import os
import platform
import shutil
from pyfiglet import Figlet
import sys
import time
import random

# Configuration
PORT = 65432  # Port to use for communication

# Dictionary to store active groups {group_name: (passkey, group_clients)}
groups = {}

# Dictionary to store user colors
user_colors = {}

# Predefined colors for users (cycled)
available_colors = ['green', 'cyan', 'yellow', 'magenta', 'blue', 'red']


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


def broadcast_message(group_clients, message):
    """Broadcast a message to all clients in the group."""
    for client_socket in group_clients:
        try:
            client_socket.sendall(message.encode())
        except Exception as e:
            print(colored(f"[-] Error sending message: {e}", 'red'))


def handle_client(conn, addr, group_name, username):
    """Server handler to respond to group chat requests."""
    global groups

    # Assign a unique color for the user
    if username not in user_colors:
        user_colors[username] = random.choice(available_colors)

    color = user_colors[username]

    group_clients = groups[group_name][1]
    broadcast_message(group_clients, colored(f"[{username} joined the chat]", color))

    try:
        while True:
            message = conn.recv(1024)
            if not message:
                break
            decoded_message = message.decode()

            # Broadcast the message to all clients in the group
            broadcast_message(group_clients, colored(f"{username}: {decoded_message}", color))
    except Exception as e:
        print(colored(f"[-] Error handling client {addr}: {e}", 'red'))
    finally:
        conn.close()
        group_clients.remove(conn)
        broadcast_message(group_clients, colored(f"[{username} left the chat]", color))
        print(colored(f"[-] Disconnected from {addr}", 'yellow'))


def server(local_ip, stop_event):
    """Runs a server to listen for group creation and joining."""
    global groups

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        try:
            server_socket.bind((local_ip, PORT))
            server_socket.listen()
            print(colored(f"[*] Server listening on {local_ip}:{PORT}...", 'cyan'))
            server_socket.settimeout(1.0)

            while not stop_event.is_set():
                try:
                    conn, addr = server_socket.accept()
                    data = conn.recv(1024).decode().split(':')

                    if len(data) == 3:  # New group or join request format: action:group_name:passkey
                        action, group_name, passkey = data

                        if action == 'create':
                            if group_name in groups:
                                conn.sendall(b"Group name already exists.")
                                conn.close()
                            else:
                                groups[group_name] = (passkey, [conn])
                                conn.sendall(b"Group created successfully.")
                                print(colored(f"[+] Group '{group_name}' created by {addr}.", 'green'))
                        elif action == 'join':
                            if group_name not in groups:
                                conn.sendall(b"Group does not exist.")
                                conn.close()
                            elif groups[group_name][0] != passkey:
                                conn.sendall(b"Incorrect passkey.")
                                conn.close()
                            else:
                                conn.sendall(b"Joined group successfully.")
                                groups[group_name][1].append(conn)
                                print(colored(f"[+] {addr} joined group '{group_name}'.", 'green'))
                        else:
                            conn.sendall(b"Invalid request.")
                            conn.close()
                    else:
                        conn.sendall(b"Invalid format.")
                        conn.close()
                except socket.timeout:
                    continue
                except Exception as e:
                    print(colored(f"[-] Server error: {e}", 'red'))
        except Exception as e:
            print(colored(f"[-] Failed to start server: {e}", 'red'))
            sys.exit(1)


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


def client(peer_ip, username, group_name, passkey):
    """Client that connects to a chat group."""
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(5.0)
        client_socket.connect((peer_ip, PORT))

        # Send join request to the server
        client_socket.sendall(f"join:{group_name}:{passkey}".encode())
        response = client_socket.recv(1024).decode()

        if "Joined group successfully" not in response:
            print(colored(f"[-] Failed to join group: {response}", 'red'))
            return

        print(colored(f"[+] Joined group '{group_name}' on {peer_ip}", 'green'))

        def receive_messages():
            """Receive messages from the group."""
            try:
                while True:
                    message = client_socket.recv(1024).decode()
                    print(message)
            except:
                pass

        # Start a thread to receive messages
        receive_thread = threading.Thread(target=receive_messages, daemon=True)
        receive_thread.start()

        while True:
            message = input(colored("You > ", 'green')).strip()
            if message.lower() == 'exit':
                client_socket.close()
                break
            else:
                client_socket.sendall(message.encode())

    except socket.timeout:
        print(colored(f"[-] Connection timed out when connecting to {peer_ip}.", 'red'))
    except ConnectionRefusedError:
        print(colored(f"[-] Failed to connect to {peer_ip}. Is the server running?", 'red'))
    except Exception as e:
        print(colored(f"[-] An error occurred: {e}", 'red'))
    finally:
        try:
            client_socket.close()
        except:
            pass


def main():
    clear_screen()
    display_banner()

    local_ip = get_local_ip()
    print(colored(f"[*] Your local IP address is {local_ip}", 'cyan'))

    choice = input(colored("Do you want to (1) create a group or (2) join a group? [1/2]: ", 'yellow')).strip()

    if choice == '1':
        group_name = input(colored("Enter a group name: ", 'yellow')).strip()
        passkey = input(colored("Set a passkey for the group: ", 'yellow')).strip()
        stop_event = threading.Event()

        server_thread = threading.Thread(target=server, args=(local_ip, stop_event), daemon=True)
        server_thread.start()

        print(colored(f"[*] Group '{group_name}' created. Waiting for members to join...", 'cyan'))

        try:
            while True:
                username = input(colored("Enter your name to join the chat: ", 'yellow')).strip()
                if username:
                    break

            client(local_ip, username, group_name, passkey)
        except KeyboardInterrupt:
            print(colored("\n[*] Keyboard interrupt received. Exiting.", 'cyan'))
        finally:
            stop_event.set()
            server_thread.join()

    elif choice == '2':
        peer_ip = input(colored("Enter the group creator's IP address: ", 'yellow')).strip()
        group_name = input(colored("Enter the group name: ", 'yellow')).strip()
        passkey = input(colored("Enter the passkey: ", 'yellow')).strip()

        try:
            while True:
                username = input(colored("Enter your name to join the chat: ", 'yellow')).strip()
                if username:
                    break

            client(peer_ip, username, group_name, passkey)
        except KeyboardInterrupt:
            print(colored("\n[*] Keyboard interrupt received. Exiting.", 'cyan'))
    else:
        print(colored("[-] Invalid option. Exiting.", 'red'))


if __name__ == '__main__':
    main()
