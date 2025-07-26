import socket
import threading
import os
import requests
import tkinter as tk
from tkinter import messagebox, filedialog, Listbox, END
from tkinter.ttk import Progressbar, Style
from cryptography.fernet import Fernet
import miniupnpc
import uuid
import json

# === CONFIG ===
SHARED_FOLDER = "shared"
HOST = '0.0.0.0'
PORT = 5000
DISCOVERY_PORT = 5001
BROADCAST_ADDR = '<broadcast>'
DISCOVERY_INTERVAL = 3  # seconds
KEY_FILE = "secret.key"

# === Key Management ===
def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key

AES_KEY = load_or_create_key()
fernet = Fernet(AES_KEY)

# Ensure shared folder exists
os.makedirs(SHARED_FOLDER, exist_ok=True)

# === Get IPs ===
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def get_public_ip():
    try:
        return requests.get('https://api.ipify.org').text
    except:
        return "Unavailable"

# === UPnP Port Forwarding ===
def add_upnp_port_mapping(internal_port, external_port, protocol='TCP', description='P2P File Sharing'):
    try:
        upnp = miniupnpc.UPnP()
        upnp.discoverdelay = 200
        upnp.discover()
        upnp.selectigd()

        external_ip = upnp.externalipaddress()
        print(f"Found UPnP device. External IP: {external_ip}")

        success = upnp.addportmapping(external_port, protocol, internal_port, external_ip, True, description)
        if success:
            print(f"Successfully added UPnP port mapping: {external_port} -> {internal_port} ({protocol})")
            return True
        else:
            print(f"Failed to add UPnP port mapping: {external_port} -> {internal_port} ({protocol})")
            return False
    except Exception as e:
        print(f"UPnP Error: {e}")
        return False

def remove_upnp_port_mapping(external_port, protocol='TCP'):
    try:
        upnp = miniupnpc.UPnP()
        upnp.discoverdelay = 200
        upnp.discover()
        upnp.selectigd()

        success = upnp.deleteportmapping(external_port, protocol)
        if success:
            print(f"Successfully removed UPnP port mapping for port {external_port}")
            return True
        else:
            print(f"Failed to remove UPnP port mapping for port {external_port}")
            return False
    except Exception as e:
        print(f"UPnP Error during removal: {e}")
        return False

# === Server: Handles incoming file requests ===
def handle_client(conn, addr, log_func):
    log_func(f"[+] Connected by {addr}")
    try:
        challenge = str(uuid.uuid4()).encode()
        encrypted_challenge = fernet.encrypt(challenge)
        conn.sendall(encrypted_challenge)

        response = conn.recv(1024)
        try:
            decrypted_response = fernet.decrypt(response)
            if decrypted_response == challenge:
                conn.sendall(b"AUTH_SUCCESS")
                log_func(f"[+] Authenticated client {addr}")
            else:
                conn.sendall(b"AUTH_FAILED")
                log_func(f"[-] Authentication failed for {addr}")
                conn.close()
                return
        except Exception as e:
            conn.sendall(b"AUTH_FAILED")
            log_func(f"[-] Authentication failed for {addr}: {e}")
            conn.close()
            return

        while True:
            data = conn.recv(1024).decode()
            if not data:
                break

            if data == "LIST":
                files = os.listdir(SHARED_FOLDER)
                conn.send("\n".join(files).encode())

            elif data.startswith("GET"):
                filename = data.split(" ", 1)[1]
                filepath = os.path.join(SHARED_FOLDER, filename)
                if os.path.exists(filepath):
                    filesize = os.path.getsize(filepath)
                    conn.send(f"OK:{filesize}".encode())
                    with open(filepath, "rb") as f:
                        while chunk := f.read(4096):
                            encrypted_chunk = fernet.encrypt(chunk)
                            conn.send(encrypted_chunk + b"::END_CHUNK::")
                    conn.send(b"FILE_DONE")
                else:
                    conn.send(b"ERROR: File not found")

            elif data.startswith("CHAT:"):
                message = data.split("CHAT:", 1)[1]
                log_func(f"[CHAT from {addr[0]}:{addr[1]}] {message}")

            elif data == "QUIT":
                break
    finally:
        conn.close()
        log_func(f"[-] Disconnected {addr}")

def server_thread(log_func):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        log_func(f"[Server] Listening on {get_local_ip()}:{PORT} (LAN)")
        log_func(f"[Server] Attempting UPnP port mapping...")
        if add_upnp_port_mapping(PORT, PORT):
            log_func(f"[Server] UPnP mapping successful. External port {PORT} is open.")
        else:
            log_func(f"[Server] UPnP mapping failed. Manual port forwarding may be required for WAN access.")

        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr, log_func), daemon=True).start()

# === Discovery: Broadcast & Listen ===
def discovery_broadcast(my_ip, my_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    while True:
        message = f"DISCOVER:{my_ip}:{my_port}"
        sock.sendto(message.encode(), (BROADCAST_ADDR, DISCOVERY_PORT))
        threading.Event().wait(DISCOVERY_INTERVAL)

def discovery_listener(add_peer_func, my_ip, my_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', DISCOVERY_PORT))
    while True:
        data, _ = sock.recvfrom(1024)
        msg = data.decode()
        if msg.startswith("DISCOVER:"):
            _, ip, port = msg.split(":")
            # Only add if it's a different IP OR same IP but different port
            if ip != my_ip or (ip == my_ip and int(port) != my_port):
                add_peer_func(f"{ip}:{port}")

# === GUI Client ===
class P2PApp:
    def __init__(self, root):
        self.root = root
        self.root.title("P2P File Sharing")
        self.root.geometry("700x750") # Set a default window size
        self.root.resizable(True, True) # Allow resizing

        # Configure style for ttk widgets
        self.style = Style()
        self.style.theme_use('clam') # 'clam', 'alt', 'default', 'classic'
        self.style.configure('TButton', font=('Arial', 10), padding=5)
        self.style.configure('TLabel', font=('Arial', 10))
        self.style.configure('TEntry', font=('Arial', 10), padding=5)
        self.style.configure('TListbox', font=('Arial', 10), padding=5)

        self.peer_ip = tk.StringVar()
        self.peer_port = tk.StringVar()
        self.conn_socket = None
        self.local_ip = get_local_ip()
        self.public_ip = get_public_ip()
        self.discovered_peers = set()

        # UI Elements
        self.setup_ui()

        # Start background threads
        threading.Thread(target=server_thread, args=(self.log,), daemon=True).start()
        threading.Thread(target=discovery_broadcast, args=(self.local_ip, PORT), daemon=True).start()
        threading.Thread(target=discovery_listener, args=(self.add_peer, self.local_ip, PORT), daemon=True).start()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_ui(self):
        # Main frame for better organization
        main_frame = tk.Frame(self.root, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # IP and Port Info Frame
        ip_info_frame = tk.LabelFrame(main_frame, text="Your Network Info", padx=10, pady=10)
        ip_info_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=5)
        ip_info_frame.columnconfigure(1, weight=1) # Make IP entry expand

        tk.Label(ip_info_frame, text=f"Local IP: {self.local_ip}", fg="blue").grid(row=0, column=0, sticky='w', padx=5, pady=2)
        tk.Button(ip_info_frame, text="Copy", command=self.copy_local_ip).grid(row=0, column=1, sticky='e', padx=5, pady=2)

        tk.Label(ip_info_frame, text=f"Public IP: {self.public_ip}", fg="green").grid(row=1, column=0, sticky='w', padx=5, pady=2)
        tk.Button(ip_info_frame, text="Copy", command=self.copy_public_ip).grid(row=1, column=1, sticky='e', padx=5, pady=2)

        tk.Label(ip_info_frame, text=f"Port: {PORT}", fg="blue").grid(row=2, column=0, sticky='w', padx=5, pady=2)
        tk.Button(ip_info_frame, text="Copy", command=self.copy_port).grid(row=2, column=1, sticky='e', padx=5, pady=2)

        # Manual Connect Frame
        connect_frame = tk.LabelFrame(main_frame, text="Connect to Peer", padx=10, pady=10)
        connect_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5)
        connect_frame.columnconfigure(1, weight=1) # Make entry expand

        tk.Label(connect_frame, text="Peer IP:").grid(row=0, column=0, sticky='w', padx=5, pady=2)
        tk.Entry(connect_frame, textvariable=self.peer_ip, width=20).grid(row=0, column=1, sticky='ew', padx=5, pady=2)
        tk.Label(connect_frame, text="Port:").grid(row=0, column=2, sticky='w', padx=5, pady=2)
        tk.Entry(connect_frame, textvariable=self.peer_port, width=10).grid(row=0, column=3, sticky='ew', padx=5, pady=2)
        tk.Button(connect_frame, text="Connect", command=self.connect_peer).grid(row=0, column=4, padx=5, pady=2)

        # Discovered Peers Frame
        peers_frame = tk.LabelFrame(main_frame, text="LAN Discovered Peers", padx=10, pady=10)
        peers_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=5)
        peers_frame.columnconfigure(0, weight=1) # Make listbox expand

        self.peer_list = Listbox(peers_frame, width=40, height=5, selectmode=tk.SINGLE)
        self.peer_list.grid(row=0, column=0, sticky='ew', padx=5, pady=2)
        tk.Button(peers_frame, text="Connect to Selected", command=self.connect_selected_peer).grid(row=0, column=1, sticky='n', padx=5, pady=2)

        # File List Frame
        files_frame = tk.LabelFrame(main_frame, text="Available Files on Peer", padx=10, pady=10)
        files_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=5)
        files_frame.columnconfigure(0, weight=1) # Make listbox expand

        self.file_list = Listbox(files_frame, width=40, height=8, selectmode=tk.EXTENDED)
        self.file_list.grid(row=0, column=0, sticky='ew', padx=5, pady=2)

        file_buttons_frame = tk.Frame(files_frame)
        file_buttons_frame.grid(row=0, column=1, sticky='n', padx=5, pady=2)
        tk.Button(file_buttons_frame, text="Refresh File List", command=self.show_files).pack(fill=tk.X, pady=2)
        tk.Button(file_buttons_frame, text="Download Selected", command=self.download_file).pack(fill=tk.X, pady=2)

        # Chat Functionality Frame
        chat_frame = tk.LabelFrame(main_frame, text="Chat", padx=10, pady=10)
        chat_frame.grid(row=4, column=0, columnspan=2, sticky="ew", pady=5)
        chat_frame.columnconfigure(0, weight=1) # Make entry expand

        self.chat_entry = tk.Entry(chat_frame, width=60)
        self.chat_entry.grid(row=0, column=0, sticky='ew', padx=5, pady=2)
        tk.Button(chat_frame, text="Send Chat", command=self.send_chat_message).grid(row=0, column=1, padx=5, pady=2)

        # Progress Bar
        progress_frame = tk.Frame(main_frame, padx=10, pady=5)
        progress_frame.grid(row=5, column=0, columnspan=2, sticky="ew", pady=5)
        progress_frame.columnconfigure(1, weight=1) # Make progress bar expand

        self.progress_label = tk.Label(progress_frame, text="Download Progress:")
        self.progress_label.grid(row=0, column=0, sticky='w', padx=5)
        self.progress_bar = Progressbar(progress_frame, orient=tk.HORIZONTAL, length=300, mode='determinate')
        self.progress_bar.grid(row=0, column=1, sticky='ew', padx=5)

        # Log Area Frame
        log_frame = tk.LabelFrame(main_frame, text="Application Log", padx=10, pady=10)
        log_frame.grid(row=6, column=0, columnspan=2, sticky="ew", pady=5)
        log_frame.columnconfigure(0, weight=1) # Make text area expand
        log_frame.rowconfigure(0, weight=1) # Make text area expand

        self.log_box = tk.Text(log_frame, height=10, width=80)
        self.log_box.grid(row=0, column=0, sticky='nsew', padx=5, pady=2)

        # Exit Button
        tk.Button(main_frame, text="Exit Application", command=self.on_closing).grid(row=7, column=0, columnspan=2, pady=10)

        # Configure main_frame columns to expand
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)

    def on_closing(self):
        remove_upnp_port_mapping(PORT)
        if self.conn_socket:
            try:
                self.conn_socket.send(b"QUIT")
                self.conn_socket.close()
            except:
                pass
        self.root.quit()

    def log(self, msg):
        self.log_box.insert(END, msg + "\n")
        self.log_box.see(END)

    def copy_local_ip(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.local_ip)
        messagebox.showinfo("Copied", f"Local IP ({self.local_ip}) copied to clipboard!")

    def copy_public_ip(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.public_ip)
        messagebox.showinfo("Copied", f"Public IP ({self.public_ip}) copied to clipboard!")

    def copy_port(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(str(PORT))
        messagebox.showinfo("Copied", f"Port ({PORT}) copied to clipboard!")

    def add_peer(self, peer):
        if peer not in self.discovered_peers:
            self.discovered_peers.add(peer)
            self.peer_list.insert(END, peer)
            self.log(f"[DISCOVERY] Found peer: {peer}")

    def connect_peer(self):
        ip = self.peer_ip.get()
        port_str = self.peer_port.get()
        if not ip or not port_str:
            messagebox.showerror("Input Error", "IP and Port cannot be empty.")
            return
        try:
            port = int(port_str)
            self._connect(ip, port)
        except ValueError:
            messagebox.showerror("Input Error", "Port must be a number.")

    def connect_selected_peer(self):
        selection = self.peer_list.get(tk.ACTIVE)
        if selection:
            ip, port = selection.split(":")
            self._connect(ip, int(port))

    def _connect(self, ip, port):
        try:
            self.conn_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn_socket.connect((ip, port))
            self.log(f"[+] Connecting to {ip}:{port}...")

            encrypted_challenge = self.conn_socket.recv(1024)
            original_challenge = fernet.decrypt(encrypted_challenge)
            response = fernet.encrypt(original_challenge)
            self.conn_socket.sendall(response)

            auth_status = self.conn_socket.recv(1024).decode()
            if auth_status == "AUTH_SUCCESS":
                self.log(f"[+] Successfully authenticated with {ip}:{port}")
                self.show_files()
            else:
                self.log(f"[-] Authentication failed with {ip}:{port}. Closing connection.")
                self.conn_socket.close()
                self.conn_socket = None
                messagebox.showerror("Authentication Error", "Failed to authenticate. Shared key mismatch?")

        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            if self.conn_socket:
                self.conn_socket.close()
                self.conn_socket = None

    def show_files(self):
        if not self.conn_socket:
            messagebox.showerror("Error", "Not connected to a peer.")
            return
        try:
            self.conn_socket.send(b"LIST")
            data = self.conn_socket.recv(4096).decode()
            self.file_list.delete(0, END)
            for file in data.split("\n"):
                if file:
                    self.file_list.insert(END, file)
        except Exception as e:
            self.log(f"Error fetching file list: {e}")
            self.conn_socket = None # Assume connection is lost

    def download_file(self):
        if not self.conn_socket:
            messagebox.showerror("Error", "Not connected to a peer.")
            return

        selected_indices = self.file_list.curselection()
        if not selected_indices:
            messagebox.showerror("Error", "Please select one or more files to download.")
            return

        selected_files = [self.file_list.get(i) for i in selected_indices]
        save_dir = filedialog.askdirectory()
        if not save_dir:
            return

        for filename in selected_files:
            threading.Thread(target=self._download_thread, args=(filename, save_dir), daemon=True).start()

    def _download_thread(self, filename, save_dir):
        try:
            # Create a new socket for each download to allow parallel transfers
            dl_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_ip, peer_port = self.conn_socket.getpeername()
            dl_socket.connect((peer_ip, peer_port))

            # Re-authenticate for the new socket
            encrypted_challenge = dl_socket.recv(1024)
            original_challenge = fernet.decrypt(encrypted_challenge)
            response = fernet.encrypt(original_challenge)
            dl_socket.sendall(response)
            auth_status = dl_socket.recv(1024).decode()
            if auth_status != "AUTH_SUCCESS":
                self.log(f"Download auth failed for {filename}")
                dl_socket.close()
                return

            dl_socket.send(f"GET {filename}".encode())
            status_header = dl_socket.recv(1024).decode()

            if status_header.startswith("OK:"):
                filesize = int(status_header.split(":")[1])
                save_path = os.path.join(save_dir, filename)
                self.log(f"Downloading {filename} ({filesize} bytes) to {save_path}")

                received_bytes = 0
                with open(save_path, "wb") as f:
                    while received_bytes < filesize:
                        chunk = dl_socket.recv(8192)
                        if not chunk:
                            break
                        
                        if b"::END_CHUNK::" in chunk:
                            parts = chunk.split(b"::END_CHUNK::")
                            for part in parts:
                                if part:
                                    try:
                                        decrypted_chunk = fernet.decrypt(part)
                                        f.write(decrypted_chunk)
                                        received_bytes += len(decrypted_chunk)
                                    except Exception as e:
                                        self.log(f"Decryption error on chunk for {filename}: {e}")
                        else:
                             # This case handles when a chunk does not contain the delimiter
                            try:
                                decrypted_chunk = fernet.decrypt(chunk)
                                f.write(decrypted_chunk)
                                received_bytes += len(decrypted_chunk)
                            except Exception as e:
                                self.log(f"Decryption error on chunk for {filename}: {e}")

                        # Update progress bar on the main thread
                        progress = (received_bytes / filesize) * 100
                        self.root.after(0, self.update_progress, progress)

                self.log(f"[SUCCESS] Downloaded {filename}")
                self.root.after(0, self.update_progress, 0) # Reset progress bar
            else:
                self.log(f"[ERROR] Could not download {filename}: {status_header}")

        except Exception as e:
            self.log(f"Download failed for {filename}: {e}")
        finally:
            dl_socket.close()

    def update_progress(self, value):
        self.progress_bar['value'] = value
        self.root.update_idletasks()

    def send_chat_message(self):
        if not self.conn_socket:
            messagebox.showerror("Error", "Not connected to a peer.")
            return
        message = self.chat_entry.get()
        if message:
            try:
                self.conn_socket.send(f"CHAT:{message}".encode())
                self.log(f"[CHAT to {self.conn_socket.getpeername()[0]}:{self.conn_socket.getpeername()[1]}] {message}")
                self.chat_entry.delete(0, END)
            except Exception as e:
                self.log(f"Error sending chat message: {e}")
                self.conn_socket = None

# === Run the GUI ===
if __name__ == "__main__":
    root = tk.Tk()
    app = P2PApp(root)
    root.mainloop()


