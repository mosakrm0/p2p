import socket
import threading
import os
import requests
import tkinter as tk
from tkinter import messagebox, filedialog, Listbox, END, Scrollbar, Canvas
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
        self.root.title("P2P File Sharing - Enhanced Edition")
        self.root.geometry("900x850")  # Increased default size for better layout
        self.root.minsize(700, 600)    # Set minimum window size
        self.root.resizable(True, True)
        
        # Configure the root window to be responsive
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Create a main canvas for scrolling
        self.canvas = tk.Canvas(root, bg='#ecf0f1')
        self.scrollbar = tk.Scrollbar(root, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        # Create a frame inside the canvas to hold all other widgets
        self.main_container = tk.Frame(self.canvas, bg='#ecf0f1')
        self.canvas.create_window((0, 0), window=self.main_container, anchor="nw")

        # Bind the canvas to the configure event to update the scroll region
        self.main_container.bind("<Configure>", self.on_frame_configure)
        self.canvas.bind("<Configure>", self.on_canvas_configure)

        # Enhanced styling
        self.setup_styles()

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

    def on_frame_configure(self, event):
        """Update the scrollregion of the canvas when the frame size changes"""
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def on_canvas_configure(self, event):
        """Update the canvas's width to fill the window"""
        self.canvas.itemconfig(self.canvas.winfo_children()[0], width=self.canvas.winfo_width())

    def setup_styles(self):
        """Configure enhanced styling for the application"""
        self.style = Style()
        self.style.theme_use('clam')
        
        # Configure enhanced styles
        self.style.configure('Title.TLabel', font=('Arial', 12, 'bold'), foreground='#2c3e50')
        self.style.configure('Info.TLabel', font=('Arial', 10), foreground='#34495e')
        self.style.configure('Success.TLabel', font=('Arial', 10), foreground='#27ae60')
        self.style.configure('Warning.TLabel', font=('Arial', 10), foreground='#e67e22')
        self.style.configure('Enhanced.TButton', font=('Arial', 10, 'bold'), padding=(10, 5))
        self.style.configure('Small.TButton', font=('Arial', 9), padding=(5, 3))
        self.style.configure('Enhanced.TEntry', font=('Arial', 10), padding=5)
        
        # Configure colors
        self.bg_color = '#ecf0f1'
        self.frame_color = '#ffffff'
        self.accent_color = '#3498db'

    def setup_ui(self):
        # Create main container with padding
        # This main_container is now self.main_container, placed inside the canvas
        main_container = self.main_container
        main_container.config(padx=15, pady=15)
        main_container.grid_rowconfigure(6, weight=1)  # Make log area expandable
        main_container.grid_columnconfigure(0, weight=1)

        # Title Header
        title_frame = tk.Frame(main_container, bg=self.bg_color, pady=15)
        title_frame.grid(row=0, column=0, sticky="ew")
        title_frame.grid_columnconfigure(0, weight=1)
        
        title_label = tk.Label(title_frame, text="🔗 P2P File Sharing Network", 
                              font=('Arial', 16, 'bold'), fg='#2c3e50', bg=self.bg_color)
        title_label.grid(row=0, column=0)
        
        subtitle_label = tk.Label(title_frame, text="Secure peer-to-peer file sharing with encryption", 
                                 font=('Arial', 10), fg='#7f8c8d', bg=self.bg_color)
        subtitle_label.grid(row=1, column=0, pady=(5, 0))

        # Network Information Frame
        self.create_network_info_frame(main_container, row=1)

        # Connection Frame
        self.create_connection_frame(main_container, row=2)

        # Discovered Peers Frame
        self.create_peers_frame(main_container, row=3)

        # File Management Frame
        self.create_files_frame(main_container, row=4)

        # Chat and Progress Frame
        self.create_chat_progress_frame(main_container, row=5)

        # Enhanced Log Area with Scrollbar
        self.create_log_frame(main_container, row=6)

        # Control Buttons Frame
        self.create_control_frame(main_container, row=7)

    def create_network_info_frame(self, parent, row):
        """Create enhanced network information display"""
        info_frame = tk.LabelFrame(parent, text="📡 Network Information", 
                                  font=('Arial', 11, 'bold'), fg='#2c3e50',
                                  bg=self.frame_color, padx=15, pady=10)
        info_frame.grid(row=row, column=0, sticky="ew", pady=(0, 10))
        info_frame.grid_columnconfigure(1, weight=1)

        # Local IP
        tk.Label(info_frame, text="Local IP:", font=('Arial', 10, 'bold'), 
                bg=self.frame_color).grid(row=0, column=0, sticky='w', pady=3)
        local_ip_frame = tk.Frame(info_frame, bg=self.frame_color)
        local_ip_frame.grid(row=0, column=1, sticky='ew', padx=(10, 0))
        local_ip_frame.grid_columnconfigure(0, weight=1)
        
        tk.Label(local_ip_frame, text=self.local_ip, font=('Arial', 10), 
                fg='#3498db', bg=self.frame_color).grid(row=0, column=0, sticky='w')
        tk.Button(local_ip_frame, text="📋 Copy", command=self.copy_local_ip,
                 font=('Arial', 8), bg='#ecf0f1', relief='flat', padx=8, pady=2).grid(row=0, column=1, padx=(5, 0))

        # Public IP
        tk.Label(info_frame, text="Public IP:", font=('Arial', 10, 'bold'), 
                bg=self.frame_color).grid(row=1, column=0, sticky='w', pady=3)
        public_ip_frame = tk.Frame(info_frame, bg=self.frame_color)
        public_ip_frame.grid(row=1, column=1, sticky='ew', padx=(10, 0))
        public_ip_frame.grid_columnconfigure(0, weight=1)
        
        tk.Label(public_ip_frame, text=self.public_ip, font=('Arial', 10), 
                fg='#27ae60', bg=self.frame_color).grid(row=0, column=0, sticky='w')
        tk.Button(public_ip_frame, text="📋 Copy", command=self.copy_public_ip,
                 font=('Arial', 8), bg='#ecf0f1', relief='flat', padx=8, pady=2).grid(row=0, column=1, padx=(5, 0))

        # Port
        tk.Label(info_frame, text="Port:", font=('Arial', 10, 'bold'), 
                bg=self.frame_color).grid(row=2, column=0, sticky='w', pady=3)
        port_frame = tk.Frame(info_frame, bg=self.frame_color)
        port_frame.grid(row=2, column=1, sticky='ew', padx=(10, 0))
        port_frame.grid_columnconfigure(0, weight=1)
        
        tk.Label(port_frame, text=str(PORT), font=('Arial', 10), 
                fg='#e74c3c', bg=self.frame_color).grid(row=0, column=0, sticky='w')
        tk.Button(port_frame, text="📋 Copy", command=self.copy_port,
                 font=('Arial', 8), bg='#ecf0f1', relief='flat', padx=8, pady=2).grid(row=0, column=1, padx=(5, 0))

    def create_connection_frame(self, parent, row):
        """Create enhanced manual connection interface"""
        connect_frame = tk.LabelFrame(parent, text="🔌 Manual Connection", 
                                     font=('Arial', 11, 'bold'), fg='#2c3e50',
                                     bg=self.frame_color, padx=15, pady=10)
        connect_frame.grid(row=row, column=0, sticky="ew", pady=(0, 10))
        connect_frame.grid_columnconfigure(1, weight=2)
        connect_frame.grid_columnconfigure(3, weight=1)

        tk.Label(connect_frame, text="Peer IP:", font=('Arial', 10), 
                bg=self.frame_color).grid(row=0, column=0, sticky='w', padx=(0, 5))
        
        ip_entry = tk.Entry(connect_frame, textvariable=self.peer_ip, font=('Arial', 10), 
                           relief='solid', bd=1, bg='#ffffff')
        ip_entry.grid(row=0, column=1, sticky='ew', padx=5, pady=5)
        
        tk.Label(connect_frame, text="Port:", font=('Arial', 10), 
                bg=self.frame_color).grid(row=0, column=2, sticky='w', padx=(10, 5))
        
        port_entry = tk.Entry(connect_frame, textvariable=self.peer_port, font=('Arial', 10), 
                             relief='solid', bd=1, bg='#ffffff', width=8)
        port_entry.grid(row=0, column=3, sticky='ew', padx=5, pady=5)
        
        connect_btn = tk.Button(connect_frame, text="🔗 Connect", command=self.connect_peer,
                               font=('Arial', 10, 'bold'), bg='#3498db', fg='white', 
                               relief='flat', padx=15, pady=5)
        connect_btn.grid(row=0, column=4, padx=(10, 0), pady=5)

    def create_peers_frame(self, parent, row):
        """Create enhanced discovered peers interface"""
        peers_frame = tk.LabelFrame(parent, text="🌐 Discovered Peers (LAN)", 
                                   font=('Arial', 11, 'bold'), fg='#2c3e50',
                                   bg=self.frame_color, padx=15, pady=10)
        peers_frame.grid(row=row, column=0, sticky="ew", pady=(0, 10))
        peers_frame.grid_columnconfigure(0, weight=1)

        # Peers listbox with scrollbar
        peers_list_frame = tk.Frame(peers_frame, bg=self.frame_color)
        peers_list_frame.grid(row=0, column=0, columnspan=2, sticky='ew', pady=(0, 10))
        peers_list_frame.grid_columnconfigure(0, weight=1)

        self.peer_list = Listbox(peers_list_frame, height=4, font=('Arial', 10), 
                                relief='solid', bd=1, bg='#ffffff', selectmode=tk.SINGLE)
        self.peer_list.grid(row=0, column=0, sticky='ew')
        
        peers_scrollbar = Scrollbar(peers_list_frame, orient="vertical", command=self.peer_list.yview)
        peers_scrollbar.grid(row=0, column=1, sticky='ns')
        self.peer_list.config(yscrollcommand=peers_scrollbar.set)

        connect_selected_btn = tk.Button(peers_frame, text="🔗 Connect to Selected", 
                                        command=self.connect_selected_peer,
                                        font=('Arial', 10, 'bold'), bg='#27ae60', fg='white', 
                                        relief='flat', padx=15, pady=5)
        connect_selected_btn.grid(row=1, column=0, pady=(0, 5))

    def create_files_frame(self, parent, row):
        """Create enhanced file management interface"""
        files_frame = tk.LabelFrame(parent, text="📁 File Management", 
                                   font=('Arial', 11, 'bold'), fg='#2c3e50',
                                   bg=self.frame_color, padx=15, pady=10)
        files_frame.grid(row=row, column=0, sticky="ew", pady=(0, 10))
        files_frame.grid_columnconfigure(0, weight=1)

        # Files listbox with scrollbar
        files_list_frame = tk.Frame(files_frame, bg=self.frame_color)
        files_list_frame.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        files_list_frame.grid_columnconfigure(0, weight=1)

        self.file_list = Listbox(files_list_frame, height=6, font=('Arial', 10), 
                                relief='solid', bd=1, bg='#ffffff', selectmode=tk.EXTENDED)
        self.file_list.grid(row=0, column=0, sticky='ew')
        
        files_scrollbar = Scrollbar(files_list_frame, orient="vertical", command=self.file_list.yview)
        files_scrollbar.grid(row=0, column=1, sticky='ns')
        self.file_list.config(yscrollcommand=files_scrollbar.set)

        # File action buttons
        file_buttons_frame = tk.Frame(files_frame, bg=self.frame_color)
        file_buttons_frame.grid(row=1, column=0, sticky='ew')
        
        refresh_btn = tk.Button(file_buttons_frame, text="🔄 Refresh List", command=self.show_files,
                               font=('Arial', 10), bg='#f39c12', fg='white', 
                               relief='flat', padx=12, pady=5)
        refresh_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        download_btn = tk.Button(file_buttons_frame, text="⬇️ Download Selected", command=self.download_file,
                                font=('Arial', 10, 'bold'), bg='#e74c3c', fg='white', 
                                relief='flat', padx=12, pady=5)
        download_btn.pack(side=tk.LEFT)

    def create_chat_progress_frame(self, parent, row):
        """Create enhanced chat and progress interface"""
        chat_progress_frame = tk.Frame(parent, bg=self.bg_color)
        chat_progress_frame.grid(row=row, column=0, sticky="ew", pady=(0, 10))
        chat_progress_frame.grid_columnconfigure(0, weight=1)

        # Chat Frame
        chat_frame = tk.LabelFrame(chat_progress_frame, text="💬 Chat", 
                                  font=('Arial', 11, 'bold'), fg='#2c3e50',
                                  bg=self.frame_color, padx=15, pady=10)
        chat_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        chat_frame.grid_columnconfigure(0, weight=1)

        chat_input_frame = tk.Frame(chat_frame, bg=self.frame_color)
        chat_input_frame.grid(row=0, column=0, sticky='ew')
        chat_input_frame.grid_columnconfigure(0, weight=1)

        self.chat_entry = tk.Entry(chat_input_frame, font=('Arial', 10), 
                                  relief='solid', bd=1, bg='#ffffff')
        self.chat_entry.grid(row=0, column=0, sticky='ew', padx=(0, 10))
        self.chat_entry.bind('<Return>', lambda e: self.send_chat_message())
        
        send_btn = tk.Button(chat_input_frame, text="📤 Send", command=self.send_chat_message,
                            font=('Arial', 10, 'bold'), bg='#9b59b6', fg='white', 
                            relief='flat', padx=15, pady=5)
        send_btn.grid(row=0, column=1)

        # Progress Frame
        progress_frame = tk.LabelFrame(chat_progress_frame, text="📊 Download Progress", 
                                      font=('Arial', 11, 'bold'), fg='#2c3e50',
                                      bg=self.frame_color, padx=15, pady=10)
        progress_frame.grid(row=1, column=0, sticky="ew")
        progress_frame.grid_columnconfigure(0, weight=1)

        self.progress_bar = Progressbar(progress_frame, orient=tk.HORIZONTAL, 
                                       length=400, mode='determinate', style='TProgressbar')
        self.progress_bar.grid(row=0, column=0, sticky='ew', pady=5)

    def create_log_frame(self, parent, row):
        """Create enhanced log area with scrollbar"""
        log_frame = tk.LabelFrame(parent, text="📋 Application Log", 
                                 font=('Arial', 11, 'bold'), fg='#2c3e50',
                                 bg=self.frame_color, padx=15, pady=10)
        log_frame.grid(row=row, column=0, sticky="nsew", pady=(0, 10))
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)

        # Create frame for text widget and scrollbar
        log_text_frame = tk.Frame(log_frame, bg=self.frame_color)
        log_text_frame.grid(row=0, column=0, sticky='nsew')
        log_text_frame.grid_rowconfigure(0, weight=1)
        log_text_frame.grid_columnconfigure(0, weight=1)

        # Text widget with enhanced styling
        self.log_box = tk.Text(log_text_frame, height=12, font=('Consolas', 9), 
                              relief='solid', bd=1, bg='#2c3e50', fg='#ecf0f1',
                              wrap=tk.WORD, padx=10, pady=5)
        self.log_box.grid(row=0, column=0, sticky='nsew')

        # Vertical scrollbar for log
        log_scrollbar = Scrollbar(log_text_frame, orient="vertical", command=self.log_box.yview)
        log_scrollbar.grid(row=0, column=1, sticky='ns')
        self.log_box.config(yscrollcommand=log_scrollbar.set)

        # Horizontal scrollbar for log
        log_h_scrollbar = Scrollbar(log_text_frame, orient="horizontal", command=self.log_box.xview)
        log_h_scrollbar.grid(row=1, column=0, sticky='ew')
        self.log_box.config(xscrollcommand=log_h_scrollbar.set)

        # Configure text tags for colored output
        self.log_box.tag_configure("success", foreground="#27ae60")
        self.log_box.tag_configure("error", foreground="#e74c3c")
        self.log_box.tag_configure("warning", foreground="#f39c12")
        self.log_box.tag_configure("info", foreground="#3498db")
        self.log_box.tag_configure("chat", foreground="#9b59b6")

    def create_control_frame(self, parent, row):
        """Create control buttons frame"""
        control_frame = tk.Frame(parent, bg=self.bg_color, pady=10)
        control_frame.grid(row=row, column=0, sticky="ew")
        
        # Clear log button
        clear_log_btn = tk.Button(control_frame, text="🗑️ Clear Log", command=self.clear_log,
                                 font=('Arial', 10), bg='#95a5a6', fg='white', 
                                 relief='flat', padx=15, pady=5)
        clear_log_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Exit button
        exit_btn = tk.Button(control_frame, text="❌ Exit Application", command=self.on_closing,
                            font=('Arial', 10, 'bold'), bg='#e74c3c', fg='white', 
                            relief='flat', padx=20, pady=5)
        exit_btn.pack(side=tk.RIGHT)

    def clear_log(self):
        """Clear the log area"""
        self.log_box.delete(1.0, END)
        self.log("📋 Log cleared", "info")

    def on_closing(self):
        remove_upnp_port_mapping(PORT)
        if self.conn_socket:
            try:
                self.conn_socket.send(b"QUIT")
                self.conn_socket.close()
            except:
                pass
        self.root.quit()

    def log(self, msg, tag="normal"):
        """Enhanced logging with color coding"""
        timestamp = threading.current_thread().name
        formatted_msg = f"[{timestamp}] {msg}\n"
        
        self.log_box.insert(END, formatted_msg, tag)
        self.log_box.see(END)
        self.root.update_idletasks()

    def copy_local_ip(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.local_ip)
        messagebox.showinfo("✅ Copied", f"Local IP ({self.local_ip}) copied to clipboard!")

    def copy_public_ip(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.public_ip)
        messagebox.showinfo("✅ Copied", f"Public IP ({self.public_ip}) copied to clipboard!")

    def copy_port(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(str(PORT))
        messagebox.showinfo("✅ Copied", f"Port ({PORT}) copied to clipboard!")

    def add_peer(self, peer):
        if peer not in self.discovered_peers:
            self.discovered_peers.add(peer)
            self.peer_list.insert(END, peer)
            self.log(f"🌐 Found peer: {peer}", "success")

    def connect_peer(self):
        ip = self.peer_ip.get()
        port_str = self.peer_port.get()
        if not ip or not port_str:
            messagebox.showerror("❌ Input Error", "IP and Port cannot be empty.")
            return
        try:
            port = int(port_str)
            self._connect(ip, port)
        except ValueError:
            messagebox.showerror("❌ Input Error", "Port must be a number.")

    def connect_selected_peer(self):
        selection = self.peer_list.get(tk.ACTIVE)
        if selection:
            ip, port = selection.split(":")
            self._connect(ip, int(port))

    def _connect(self, ip, port):
        try:
            self.conn_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn_socket.connect((ip, port))
            self.log(f"🔗 Connecting to {ip}:{port}...", "info")

            encrypted_challenge = self.conn_socket.recv(1024)
            original_challenge = fernet.decrypt(encrypted_challenge)
            response = fernet.encrypt(original_challenge)
            self.conn_socket.sendall(response)

            auth_status = self.conn_socket.recv(1024).decode()
            if auth_status == "AUTH_SUCCESS":
                self.log(f"✅ Successfully authenticated with {ip}:{port}", "success")
                self.show_files()
            else:
                self.log(f"❌ Authentication failed with {ip}:{port}. Closing connection.", "error")
                self.conn_socket.close()
                self.conn_socket = None
                messagebox.showerror("❌ Authentication Error", "Failed to authenticate. Shared key mismatch?")

        except Exception as e:
            messagebox.showerror("❌ Connection Error", str(e))
            self.log(f"❌ Connection failed: {str(e)}", "error")
            if self.conn_socket:
                self.conn_socket.close()
                self.conn_socket = None

    def show_files(self):
        if not self.conn_socket:
            messagebox.showerror("❌ Error", "Not connected to a peer.")
            return
        try:
            self.conn_socket.send(b"LIST")
            data = self.conn_socket.recv(4096).decode()
            self.file_list.delete(0, END)
            files = data.split("\n")
            for file in files:
                if file:
                    self.file_list.insert(END, file)
            self.log(f"📁 Retrieved {len([f for f in files if f])} files from peer", "info")
        except Exception as e:
            self.log(f"❌ Error fetching file list: {e}", "error")
            self.conn_socket = None

    def download_file(self):
        if not self.conn_socket:
            messagebox.showerror("❌ Error", "Not connected to a peer.")
            return

        selected_indices = self.file_list.curselection()
        if not selected_indices:
            messagebox.showerror("❌ Error", "Please select one or more files to download.")
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
                self.log(f"❌ Download auth failed for {filename}", "error")
                dl_socket.close()
                return

            dl_socket.send(f"GET {filename}".encode())
            status_header = dl_socket.recv(1024).decode()

            if status_header.startswith("OK:"):
                filesize = int(status_header.split(":")[1])
                save_path = os.path.join(save_dir, filename)
                self.log(f"⬇️ Downloading {filename} ({filesize} bytes) to {save_path}", "info")

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
                                        self.log(f"❌ Decryption error on chunk for {filename}: {e}", "error")
                        else:
                             # This case handles when a chunk does not contain the delimiter
                            try:
                                decrypted_chunk = fernet.decrypt(chunk)
                                f.write(decrypted_chunk)
                                received_bytes += len(decrypted_chunk)
                            except Exception as e:
                                self.log(f"❌ Decryption error on chunk for {filename}: {e}", "error")

                        # Update progress bar on the main thread
                        progress = (received_bytes / filesize) * 100
                        self.root.after(0, self.update_progress, progress)

                self.log(f"✅ Successfully downloaded {filename}", "success")
                self.root.after(0, self.update_progress, 0) # Reset progress bar
            else:
                self.log(f"❌ Could not download {filename}: {status_header}", "error")

        except Exception as e:
            self.log(f"❌ Download failed for {filename}: {e}", "error")
        finally:
            dl_socket.close()

    def update_progress(self, value):
        self.progress_bar['value'] = value
        self.root.update_idletasks()

    def send_chat_message(self):
        if not self.conn_socket:
            messagebox.showerror("❌ Error", "Not connected to a peer.")
            return
        message = self.chat_entry.get()
        if message:
            try:
                self.conn_socket.send(f"CHAT:{message}".encode())
                peer_info = f"{self.conn_socket.getpeername()[0]}:{self.conn_socket.getpeername()[1]}"
                self.log(f"💬 [CHAT to {peer_info}] {message}", "chat")
                self.chat_entry.delete(0, END)
            except Exception as e:
                self.log(f"❌ Error sending chat message: {e}", "error")
                self.conn_socket = None

# === Run the GUI ===
if __name__ == "__main__":
    root = tk.Tk()
    app = P2PApp(root)
    root.mainloop()

