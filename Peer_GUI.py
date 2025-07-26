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
        return requests.get('https://api.ipify.org', timeout=5).text
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
        upnp = miniupnp.UPnP()
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

class P2PApp:
    def __init__(self, root):
        self.root = root
        self.root.title("P2P File Sharing")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        self.root.resizable(True, True)
        
        # Configure main window grid weights
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Enhanced styling
        self.setup_styles()

        # Initialize variables
        self.peer_ip = tk.StringVar()
        self.peer_port = tk.StringVar(value="5000")
        self.local_ip_var = tk.StringVar(value=get_local_ip())
        self.public_ip_var = tk.StringVar(value="Fetching...")
        self.conn_socket = None
        self.discovered_peers = set()

        # Create main container with proper scrolling
        self.setup_scrollable_container()
        
        # Setup UI
        self.setup_ui()

        # Start background threads
        self.start_background_threads()

        # Bind events
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.bind('<Configure>', self.on_window_resize)
        
        # Bind Enter key to chat entry
        self.chat_entry.bind('<Return>', lambda e: self.send_chat_message())

    def setup_scrollable_container(self):
        """Setup main scrollable container with improved responsiveness"""
        # Main container frame
        self.main_frame = tk.Frame(self.root, bg='#ecf0f1')
        self.main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Create canvas and scrollbar for scrolling
        self.canvas = tk.Canvas(self.main_frame, bg='#ecf0f1', highlightthickness=0)
        self.scrollbar = tk.Scrollbar(self.main_frame, orient="vertical", command=self.canvas.yview)
        
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        # Pack scrollbar and canvas
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        self.canvas.grid(row=0, column=0, sticky="nsew")
        
        # Create scrollable frame inside canvas
        self.scrollable_frame = tk.Frame(self.canvas, bg='#ecf0f1')
        self.canvas_window = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        
        # Bind events for responsive scrolling
        self.scrollable_frame.bind("<Configure>", self.on_frame_configure)
        self.canvas.bind("<Configure>", self.on_canvas_configure)
        self.canvas.bind_all("<MouseWheel>", self.on_mousewheel)

    def on_frame_configure(self, event):
        """Update scroll region when frame size changes"""
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def on_canvas_configure(self, event):
        """Update canvas window width to match canvas width"""
        canvas_width = event.width
        self.canvas.itemconfig(self.canvas_window, width=canvas_width)

    def on_mousewheel(self, event):
        """Handle mouse wheel scrolling"""
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    def on_window_resize(self, event):
        """Handle window resize events"""
        if event.widget == self.root:
            # Update canvas scroll region
            self.root.after_idle(self.update_scroll_region)

    def update_scroll_region(self):
        """Update the scroll region of the canvas"""
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def setup_styles(self):
        """Configure enhanced styling"""
        self.style = Style()
        self.style.theme_use('clam')
        
        # Color scheme
        self.colors = {
            'bg': '#ecf0f1',
            'frame_bg': '#ffffff',
            'primary': '#3498db',
            'success': '#2ecc71',
            'warning': '#f39c12',
            'danger': '#e74c3c',
            'secondary': '#95a5a6',
            'dark': '#2c3e50',
            'light': '#bdc3c7'
        }
        
        # Configure ttk styles
        self.style.configure('Title.TLabel', font=('Arial', 12, 'bold'), foreground=self.colors['dark'])
        self.style.configure('Subtitle.TLabel', font=('Arial', 10), foreground=self.colors['secondary'])
        self.style.configure('Info.TLabel', font=('Arial', 9), foreground=self.colors['dark'])

    def setup_ui(self):
        """Setup the main user interface with improved layout"""
        # Configure main scrollable frame
        self.scrollable_frame.grid_columnconfigure(0, weight=1)
        
        # Title section
        self.create_title_section(row=0)
        
        # Network info section
        self.create_network_info_section(row=1)
        
        # Create two-column layout for better space utilization
        self.create_two_column_layout(row=2)
        
        # Chat and progress section
        self.create_chat_progress_section(row=3)
        
        # Log section (expandable)
        self.create_log_section(row=4)
        
        # Control buttons
        self.create_control_section(row=5)

    def create_title_section(self, row):
        """Create enhanced title section"""
        title_frame = tk.Frame(self.scrollable_frame, bg=self.colors['bg'], pady=15)
        title_frame.grid(row=row, column=0, sticky="ew", padx=10, pady=(0, 10))
        title_frame.grid_columnconfigure(0, weight=1)
        
        # Main title
        title_label = tk.Label(title_frame, text="🔗 P2P File Sharing Network", 
                              font=('Arial', 18, 'bold'), fg=self.colors['dark'], 
                              bg=self.colors['bg'])
        title_label.grid(row=0, column=0)
        
        # Subtitle
        subtitle_label = tk.Label(title_frame, text="Secure peer-to-peer file sharing with encryption", 
                                 font=('Arial', 11), fg=self.colors['secondary'], 
                                 bg=self.colors['bg'])
        subtitle_label.grid(row=1, column=0, pady=(5, 0))

    def create_network_info_section(self, row):
        """Create network information section with copy buttons"""
        info_frame = tk.LabelFrame(self.scrollable_frame, text="📡 Network Information", 
                                  font=('Arial', 11, 'bold'), fg=self.colors['dark'],
                                  bg=self.colors['frame_bg'], padx=15, pady=10)
        info_frame.grid(row=row, column=0, sticky="ew", padx=10, pady=(0, 10))
        info_frame.grid_columnconfigure(1, weight=1)

        # Network info rows
        network_info = [
            ("Local IP:", self.local_ip_var, self.colors['primary'], self.copy_local_ip),
            ("Public IP:", self.public_ip_var, self.colors['success'], self.copy_public_ip),
            ("Port:", tk.StringVar(value=str(PORT)), self.colors['danger'], self.copy_port)
        ]
        
        for i, (label_text, var, color, copy_func) in enumerate(network_info):
            # Label
            tk.Label(info_frame, text=label_text, font=('Arial', 10, 'bold'), 
                    bg=self.colors['frame_bg']).grid(row=i, column=0, sticky='w', pady=5)
            
            # Value frame
            value_frame = tk.Frame(info_frame, bg=self.colors['frame_bg'])
            value_frame.grid(row=i, column=1, sticky='ew', padx=(10, 0))
            value_frame.grid_columnconfigure(0, weight=1)
            
            # Value label
            tk.Label(value_frame, textvariable=var, font=('Arial', 10), 
                    fg=color, bg=self.colors['frame_bg']).grid(row=0, column=0, sticky='w')
            
            # Copy button
            tk.Button(value_frame, text="📋", command=copy_func,
                     font=('Arial', 8), bg=self.colors['bg'], relief='flat', 
                     padx=8, pady=2).grid(row=0, column=1, padx=(5, 0))

    def create_two_column_layout(self, row):
        """Create two-column layout for better space utilization"""
        columns_frame = tk.Frame(self.scrollable_frame, bg=self.colors['bg'])
        columns_frame.grid(row=row, column=0, sticky="ew", padx=10, pady=(0, 10))
        columns_frame.grid_columnconfigure(0, weight=1)
        columns_frame.grid_columnconfigure(1, weight=1)
        
        # Left column
        left_column = tk.Frame(columns_frame, bg=self.colors['bg'])
        left_column.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        left_column.grid_columnconfigure(0, weight=1)
        
        # Right column
        right_column = tk.Frame(columns_frame, bg=self.colors['bg'])
        right_column.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        right_column.grid_columnconfigure(0, weight=1)
        
        # Left column content
        self.create_connection_section(left_column, row=0)
        self.create_peers_section(left_column, row=1)
        
        # Right column content
        self.create_files_section(right_column, row=0)

    def create_connection_section(self, parent, row):
        """Create manual connection section"""
        connect_frame = tk.LabelFrame(parent, text="🔌 Manual Connection", 
                                     font=('Arial', 11, 'bold'), fg=self.colors['dark'],
                                     bg=self.colors['frame_bg'], padx=15, pady=10)
        connect_frame.grid(row=row, column=0, sticky="ew", pady=(0, 10))
        connect_frame.grid_columnconfigure(0, weight=1)

        # Input frame
        input_frame = tk.Frame(connect_frame, bg=self.colors['frame_bg'])
        input_frame.grid(row=0, column=0, sticky="ew", pady=5)
        input_frame.grid_columnconfigure(0, weight=2)
        input_frame.grid_columnconfigure(2, weight=1)

        # IP entry
        tk.Label(input_frame, text="IP:", font=('Arial', 10), 
                bg=self.colors['frame_bg']).grid(row=0, column=0, sticky='w')
        ip_entry = tk.Entry(input_frame, textvariable=self.peer_ip, font=('Arial', 10), 
                           relief='solid', bd=1)
        ip_entry.grid(row=1, column=0, sticky='ew', padx=(0, 5), pady=2)
        
        # Port entry
        tk.Label(input_frame, text="Port:", font=('Arial', 10), 
                bg=self.colors['frame_bg']).grid(row=0, column=1, sticky='w', padx=(5, 0))
        port_entry = tk.Entry(input_frame, textvariable=self.peer_port, font=('Arial', 10), 
                             relief='solid', bd=1, width=8)
        port_entry.grid(row=1, column=1, sticky='ew', padx=5, pady=2)
        
        # Connect button
        connect_btn = tk.Button(input_frame, text="🔗 Connect", command=self.connect_peer,
                               font=('Arial', 10, 'bold'), bg=self.colors['primary'], 
                               fg='white', relief='flat', padx=15, pady=8)
        connect_btn.grid(row=1, column=2, padx=(5, 0), pady=2)

    def create_peers_section(self, parent, row):
        """Create discovered peers section"""
        peers_frame = tk.LabelFrame(parent, text="🌐 Discovered Peers", 
                                   font=('Arial', 11, 'bold'), fg=self.colors['dark'],
                                   bg=self.colors['frame_bg'], padx=15, pady=10)
        peers_frame.grid(row=row, column=0, sticky="nsew", pady=(0, 10))
        peers_frame.grid_columnconfigure(0, weight=1)
        peers_frame.grid_rowconfigure(0, weight=1)

        # Peers listbox with scrollbar
        listbox_frame = tk.Frame(peers_frame, bg=self.colors['frame_bg'])
        listbox_frame.grid(row=0, column=0, sticky="nsew", pady=5)
        listbox_frame.grid_columnconfigure(0, weight=1)
        listbox_frame.grid_rowconfigure(0, weight=1)
        
        self.peers_listbox = Listbox(listbox_frame, height=6, font=('Arial', 10), 
                                     bg='white', selectbackground=self.colors['primary'],
                                     selectforeground='white', relief='solid', bd=1)
        self.peers_listbox.grid(row=0, column=0, sticky="nsew")
        
        peers_scrollbar = Scrollbar(listbox_frame, orient="vertical")
        peers_scrollbar.config(command=self.peers_listbox.yview)
        self.peers_listbox.config(yscrollcommand=peers_scrollbar.set)
        peers_scrollbar.grid(row=0, column=1, sticky="ns")

        # Buttons
        buttons_frame = tk.Frame(peers_frame, bg=self.colors['frame_bg'])
        buttons_frame.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        buttons_frame.grid_columnconfigure(0, weight=1)
        buttons_frame.grid_columnconfigure(1, weight=1)

        tk.Button(buttons_frame, text="Connect Selected", command=self.connect_selected_peer,
                  font=('Arial', 9, 'bold'), bg=self.colors['success'], fg='white', 
                  relief='flat', pady=5).grid(row=0, column=0, sticky="ew", padx=(0, 5))
        tk.Button(buttons_frame, text="Clear List", command=self.clear_peers,
                  font=('Arial', 9, 'bold'), bg=self.colors['warning'], fg='white', 
                  relief='flat', pady=5).grid(row=0, column=1, padx=(5, 0))

    def create_files_section(self, parent, row):
        """Create file management section"""
        files_frame = tk.LabelFrame(parent, text="📁 File Management", 
                                   font=('Arial', 11, 'bold'), fg=self.colors['dark'],
                                   bg=self.colors['frame_bg'], padx=15, pady=10)
        files_frame.grid(row=row, column=0, sticky="nsew")
        files_frame.grid_columnconfigure(0, weight=1)
        files_frame.grid_rowconfigure(1, weight=1)

        # Info label
        tk.Label(files_frame, text="Remote Files:", font=('Arial', 10, 'bold'), 
                bg=self.colors['frame_bg']).grid(row=0, column=0, sticky='w', pady=(0, 5))

        # Files listbox with scrollbar
        listbox_frame = tk.Frame(files_frame, bg=self.colors['frame_bg'])
        listbox_frame.grid(row=1, column=0, sticky="nsew", pady=5)
        listbox_frame.grid_columnconfigure(0, weight=1)
        listbox_frame.grid_rowconfigure(0, weight=1)
        
        self.remote_files_listbox = Listbox(listbox_frame, height=8, font=('Arial', 10), 
                                            bg='white', selectbackground=self.colors['primary'],
                                            selectforeground='white', relief='solid', bd=1)
        self.remote_files_listbox.grid(row=0, column=0, sticky="nsew")
        
        files_scrollbar = Scrollbar(listbox_frame, orient="vertical")
        files_scrollbar.config(command=self.remote_files_listbox.yview)
        self.remote_files_listbox.config(yscrollcommand=files_scrollbar.set)
        files_scrollbar.grid(row=0, column=1, sticky="ns")

        # Buttons
        buttons_frame = tk.Frame(files_frame, bg=self.colors['frame_bg'])
        buttons_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        buttons_frame.grid_columnconfigure(0, weight=1)
        buttons_frame.grid_columnconfigure(1, weight=1)

        tk.Button(buttons_frame, text="📋 List Files", command=self.list_remote_files,
                  font=('Arial', 9, 'bold'), bg=self.colors['primary'], fg='white', 
                  relief='flat', pady=5).grid(row=0, column=0, sticky="ew", padx=(0, 5))
        tk.Button(buttons_frame, text="⬇️ Download", command=self.download_selected_file,
                  font=('Arial', 9, 'bold'), bg=self.colors['success'], fg='white', 
                  relief='flat', pady=5).grid(row=0, column=1, padx=(5, 0))

    def create_chat_progress_section(self, row):
        """Create chat and progress section"""
        chat_frame = tk.LabelFrame(self.scrollable_frame, text="💬 Chat & Progress", 
                                  font=('Arial', 11, 'bold'), fg=self.colors['dark'],
                                  bg=self.colors['frame_bg'], padx=15, pady=10)
        chat_frame.grid(row=row, column=0, sticky="ew", padx=10, pady=(0, 10))
        chat_frame.grid_columnconfigure(0, weight=1)

        # Chat input
        chat_input_frame = tk.Frame(chat_frame, bg=self.colors['frame_bg'])
        chat_input_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        chat_input_frame.grid_columnconfigure(0, weight=1)
        
        self.chat_entry = tk.Entry(chat_input_frame, font=('Arial', 10), 
                                  relief='solid', bd=1)
        self.chat_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        tk.Button(chat_input_frame, text="💬 Send", command=self.send_chat_message,
                  font=('Arial', 9, 'bold'), bg=self.colors['primary'], fg='white', 
                  relief='flat', padx=15, pady=5).grid(row=0, column=1)

        # Progress section
        progress_frame = tk.Frame(chat_frame, bg=self.colors['frame_bg'])
        progress_frame.grid(row=1, column=0, sticky="ew")
        progress_frame.grid_columnconfigure(0, weight=1)
        
        tk.Label(progress_frame, text="Transfer Progress:", font=('Arial', 10, 'bold'), 
                bg=self.colors['frame_bg']).grid(row=0, column=0, sticky='w')
        
        progress_container = tk.Frame(progress_frame, bg=self.colors['frame_bg'])
        progress_container.grid(row=1, column=0, sticky="ew", pady=5)
        progress_container.grid_columnconfigure(0, weight=1)
        
        self.progress_bar = Progressbar(progress_container, orient="horizontal", 
                                        length=100, mode="determinate")
        self.progress_bar.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.progress_label = tk.Label(progress_container, text="0%", font=('Arial', 9), 
                                       bg=self.colors['frame_bg'])
        self.progress_label.grid(row=0, column=1)

    def create_log_section(self, row):
        """Create expandable log section"""
        log_frame = tk.LabelFrame(self.scrollable_frame, text="📝 Activity Log", 
                                 font=('Arial', 11, 'bold'), fg=self.colors['dark'],
                                 bg=self.colors['frame_bg'], padx=15, pady=10)
        log_frame.grid(row=row, column=0, sticky="nsew", padx=10, pady=(0, 10))
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(0, weight=1)
        
        # Configure scrollable frame to expand
        self.scrollable_frame.grid_rowconfigure(row, weight=1)

        # Log text with scrollbar
        log_container = tk.Frame(log_frame, bg=self.colors['frame_bg'])
        log_container.grid(row=0, column=0, sticky="nsew")
        log_container.grid_columnconfigure(0, weight=1)
        log_container.grid_rowconfigure(0, weight=1)
        
        self.log_text = tk.Text(log_container, height=12, font=('Consolas', 9), 
                                bg=self.colors['dark'], fg='#ecf0f1', insertbackground='white',
                                selectbackground=self.colors['primary'], relief='solid', bd=1,
                                wrap=tk.WORD)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        
        log_scrollbar = Scrollbar(log_container, orient="vertical")
        log_scrollbar.config(command=self.log_text.yview)
        self.log_text.config(yscrollcommand=log_scrollbar.set)
        log_scrollbar.grid(row=0, column=1, sticky="ns")

    def create_control_section(self, row):
        """Create control buttons section"""
        control_frame = tk.Frame(self.scrollable_frame, bg=self.colors['bg'], pady=10)
        control_frame.grid(row=row, column=0, sticky="ew", padx=10)
        control_frame.grid_columnconfigure(0, weight=1)
        control_frame.grid_columnconfigure(1, weight=1)
        control_frame.grid_columnconfigure(2, weight=1)

        tk.Button(control_frame, text="🔄 Refresh IPs", command=self.refresh_ips,
                  font=('Arial', 10, 'bold'), bg=self.colors['warning'], fg='white', 
                  relief='flat', padx=20, pady=8).grid(row=0, column=0, sticky="ew", padx=5)
        tk.Button(control_frame, text="📂 Open Shared Folder", command=self.open_shared_folder,
                  font=('Arial', 10, 'bold'), bg=self.colors['secondary'], fg='white', 
                  relief='flat', padx=20, pady=8).grid(row=0, column=1, padx=5)
        tk.Button(control_frame, text="❌ Exit", command=self.on_closing,
                  font=('Arial', 10, 'bold'), bg=self.colors['danger'], fg='white', 
                  relief='flat', padx=20, pady=8).grid(row=0, column=2, padx=5)

    def start_background_threads(self):
        """Start all background threads"""
        threading.Thread(target=self._server_thread, args=(self.log,), daemon=True).start()
        threading.Thread(target=self._discovery_broadcast, args=(self.local_ip_var.get(), PORT), daemon=True).start()
        threading.Thread(target=self._discovery_listener, args=(self.add_peer, self.local_ip_var.get(), PORT), daemon=True).start()
        threading.Thread(target=self._fetch_public_ip, daemon=True).start()

    # === Network and threading methods ===
    def _fetch_public_ip(self):
        """Fetch public IP in background"""
        public_ip = get_public_ip()
        self.root.after(0, self.public_ip_var.set, public_ip)

    def _add_upnp_port_mapping_threaded(self, internal_port, external_port, protocol='TCP', description='P2P File Sharing'):
        success = add_upnp_port_mapping(internal_port, external_port, protocol, description)
        if success:
            self.root.after(0, self.log, f"[Server] UPnP mapping successful. External port {external_port} is open.")
        else:
            self.root.after(0, self.log, f"[Server] UPnP mapping failed. Manual port forwarding may be required for WAN access.")

    def _remove_upnp_port_mapping_threaded(self, external_port, protocol='TCP'):
        success = remove_upnp_port_mapping(external_port, protocol)
        if success:
            self.root.after(0, self.log, f"[Server] Successfully removed UPnP port mapping for port {external_port}")
        else:
            self.root.after(0, self.log, f"[Server] Failed to remove UPnP port mapping for port {external_port}")

    def _server_thread(self, log_func):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            log_func(f"[Server] Listening on {self.local_ip_var.get()}:{PORT} (LAN)")
            log_func(f"[Server] Attempting UPnP port mapping...")
            threading.Thread(target=self._add_upnp_port_mapping_threaded, args=(PORT, PORT), daemon=True).start()

            while True:
                conn, addr = s.accept()
                threading.Thread(target=handle_client, args=(conn, addr, log_func), daemon=True).start()

    def _discovery_broadcast(self, my_ip, my_port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            message = f"DISCOVER:{my_ip}:{my_port}"
            sock.sendto(message.encode(), (BROADCAST_ADDR, DISCOVERY_PORT))
            threading.Event().wait(DISCOVERY_INTERVAL)

    def _discovery_listener(self, add_peer_func, my_ip, my_port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', DISCOVERY_PORT))
        while True:
            data, _ = sock.recvfrom(1024)
            msg = data.decode()
            if msg.startswith("DISCOVER:"):
                _, ip, port = msg.split(":")
                if ip != my_ip or (ip == my_ip and int(port) != my_port):
                    add_peer_func(f"{ip}:{port}")

    # === UI Event Handlers ===
    def log(self, message):
        """Add message to log with timestamp"""
        import datetime
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        self.log_text.insert(END, formatted_message + "\n")
        self.log_text.see(END)
        # Keep log size manageable
        if int(self.log_text.index('end-1c').split('.')[0]) > 1000:
            self.log_text.delete(1.0, 100.0)

    def add_peer(self, peer_info):
        """Add discovered peer to list"""
        if peer_info not in self.discovered_peers:
            self.discovered_peers.add(peer_info)
            self.peers_listbox.insert(END, peer_info)
            self.log(f"[Discovery] Discovered peer: {peer_info}")

    def copy_local_ip(self):
        """Copy local IP to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(self.local_ip_var.get())
        self.log(f"[Info] Local IP copied to clipboard")

    def copy_public_ip(self):
        """Copy public IP to clipboard"""
        public_ip = self.public_ip_var.get()
        if public_ip != "Fetching..." and public_ip != "Unavailable":
            self.root.clipboard_clear()
            self.root.clipboard_append(public_ip)
            self.log(f"[Info] Public IP copied to clipboard")
        else:
            self.log("[Info] Public IP not available")

    def copy_port(self):
        """Copy port to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(str(PORT))
        self.log(f"[Info] Port {PORT} copied to clipboard")

    def connect_peer(self):
        """Connect to specified peer"""
        peer_address = self.peer_ip.get().strip()
        peer_port = self.peer_port.get().strip()
        
        if not peer_address or not peer_port:
            messagebox.showerror("Error", "Please enter both IP and Port.")
            return
        
        try:
            port = int(peer_port)
            self.log(f"[Client] Attempting to connect to {peer_address}:{port}...")
            threading.Thread(target=self._connect_peer_threaded, args=(peer_address, port), daemon=True).start()
        except ValueError:
            messagebox.showerror("Error", "Port must be a valid number.")
            self.log("[Client] Invalid port number")
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect to peer: {e}")
            self.log(f"[Client] Connection failed: {e}")

    def _connect_peer_threaded(self, peer_address, port):
        """Connect to peer in background thread"""
        try:
            if self.conn_socket:
                self.conn_socket.close()
            
            self.conn_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn_socket.settimeout(10)  # 10 second timeout
            self.conn_socket.connect((peer_address, port))
            self.root.after(0, self.log, f"[Client] Connected to {peer_address}:{port}")
            self._authenticate_peer_threaded()
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Connection Error", f"Could not connect to peer: {e}")
            self.root.after(0, self.log, f"[Client] Connection failed: {e}")
            self.conn_socket = None

    def _authenticate_peer_threaded(self):
        """Authenticate with peer"""
        try:
            encrypted_challenge = self.conn_socket.recv(1024)
            challenge = fernet.decrypt(encrypted_challenge)
            self.conn_socket.sendall(challenge)
            response = self.conn_socket.recv(1024).decode()
            if response == "AUTH_SUCCESS":
                self.root.after(0, self.log, "[Client] Authentication successful")
            else:
                self.root.after(0, self.log, "[Client] Authentication failed")
                self.conn_socket.close()
                self.conn_socket = None
        except Exception as e:
            self.root.after(0, self.log, f"[Client] Authentication error: {e}")
            if self.conn_socket:
                self.conn_socket.close()
            self.conn_socket = None

    def connect_selected_peer(self):
        """Connect to selected peer from discovery list"""
        selected_index = self.peers_listbox.curselection()
        if not selected_index:
            messagebox.showwarning("Warning", "Please select a peer from the list.")
            return
        
        peer_info = self.peers_listbox.get(selected_index[0])
        try:
            ip, port = peer_info.split(":")
            self.peer_ip.set(ip)
            self.peer_port.set(port)
            self.connect_peer()
        except ValueError:
            messagebox.showerror("Error", "Invalid peer format")
            self.log("[Client] Invalid peer format in discovery list")

    def clear_peers(self):
        """Clear discovered peers list"""
        self.discovered_peers.clear()
        self.peers_listbox.delete(0, END)
        self.log("[Discovery] Cleared discovered peers list")

    def list_remote_files(self):
        """List files on connected peer"""
        if not self.conn_socket:
            messagebox.showerror("Error", "Not connected to any peer.")
            return
        
        threading.Thread(target=self._list_remote_files_threaded, daemon=True).start()

    def _list_remote_files_threaded(self):
        """List remote files in background thread"""
        try:
            self.conn_socket.sendall(b"LIST")
            files_data = self.conn_socket.recv(4096).decode()
            self.root.after(0, self.remote_files_listbox.delete, 0, END)
            if files_data.strip():
                files = [f for f in files_data.split("\n") if f.strip()]
                for f in files:
                    self.root.after(0, self.remote_files_listbox.insert, END, f)
                self.root.after(0, self.log, f"[Client] Listed {len(files)} remote files")
            else:
                self.root.after(0, self.log, "[Client] No remote files found")
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Error", f"Failed to list remote files: {e}")
            self.root.after(0, self.log, f"[Client] Failed to list remote files: {e}")
            if self.conn_socket:
                self.conn_socket.close()
            self.conn_socket = None

    def download_selected_file(self):
        """Download selected file from remote peer"""
        selected_index = self.remote_files_listbox.curselection()
        if not selected_index:
            messagebox.showwarning("Warning", "Please select a file to download.")
            return
        
        filename = self.remote_files_listbox.get(selected_index[0])
        if not self.conn_socket:
            messagebox.showerror("Error", "Not connected to any peer.")
            return

        save_path = filedialog.asksaveasfilename(
            initialfile=filename, 
            defaultextension="", 
            filetypes=[("All files", "*.*")]
        )
        if not save_path:
            return

        threading.Thread(target=self._download_file_threaded, args=(filename, save_path), daemon=True).start()

    def _download_file_threaded(self, filename, save_path):
        """Download file in background thread with progress updates"""
        try:
            self.conn_socket.sendall(f"GET {filename}".encode())
            response = self.conn_socket.recv(1024).decode()

            if response.startswith("OK:"):
                filesize = int(response.split(":")[1])
                self.root.after(0, self.log, f"[Client] Downloading '{filename}' ({filesize:,} bytes)...")
                self.root.after(0, self.progress_bar.configure, {"value": 0})
                self.root.after(0, self.progress_label.config, {"text": "0%"})
                
                downloaded_bytes = 0
                
                with open(save_path, "wb") as f:
                    while downloaded_bytes < filesize:
                        chunk_data = b""
                        while not chunk_data.endswith(b"::END_CHUNK::"):
                            data = self.conn_socket.recv(4096)
                            if not data:
                                break
                            chunk_data += data
                        
                        if not chunk_data:
                            break
                            
                        encrypted_chunk = chunk_data[:-len(b"::END_CHUNK::")]
                        if encrypted_chunk:
                            try:
                                decrypted_chunk = fernet.decrypt(encrypted_chunk)
                                f.write(decrypted_chunk)
                                downloaded_bytes += len(decrypted_chunk)
                                
                                progress = min((downloaded_bytes / filesize) * 100, 100)
                                self.root.after(0, self.progress_bar.configure, {"value": progress})
                                self.root.after(0, self.progress_label.config, {"text": f"{progress:.1f}%"})
                            except Exception as decrypt_error:
                                self.root.after(0, self.log, f"[Client] Decryption error: {decrypt_error}")
                                break

                        # Check for completion signal
                        if b"FILE_DONE" in chunk_data:
                            break

                self.root.after(0, self.log, f"[Client] Download of '{filename}' completed")
                self.root.after(0, messagebox.showinfo, "Download Complete", f"'{filename}' downloaded successfully!")
                self.root.after(0, self.progress_bar.configure, {"value": 100})
                self.root.after(0, self.progress_label.config, {"text": "100%"})
            else:
                self.root.after(0, messagebox.showerror, "Download Error", f"Server error: {response}")
                self.root.after(0, self.log, f"[Client] Download error: {response}")
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Download Error", f"Failed to download file: {e}")
            self.root.after(0, self.log, f"[Client] Failed to download file: {e}")
            if self.conn_socket:
                self.conn_socket.close()
            self.conn_socket = None

    def send_chat_message(self):
        """Send chat message to connected peer"""
        if not self.conn_socket:
            messagebox.showerror("Error", "Not connected to any peer.")
            return
        
        message = self.chat_entry.get().strip()
        if not message:
            return
        
        threading.Thread(target=self._send_chat_message_threaded, args=(message,), daemon=True).start()

    def _send_chat_message_threaded(self, message):
        """Send chat message in background thread"""
        try:
            self.conn_socket.sendall(f"CHAT:{message}".encode())
            self.root.after(0, self.log, f"[Me] {message}")
            self.root.after(0, self.chat_entry.delete, 0, END)
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Error", f"Failed to send message: {e}")
            self.root.after(0, self.log, f"[Client] Failed to send chat message: {e}")
            if self.conn_socket:
                self.conn_socket.close()
            self.conn_socket = None

    def refresh_ips(self):
        """Refresh IP addresses"""
        self.log("[Info] Refreshing IP addresses...")
        old_local_ip = self.local_ip_var.get()
        new_local_ip = get_local_ip()
        self.local_ip_var.set(new_local_ip)
        
        if old_local_ip != new_local_ip:
            self.log(f"[Info] Local IP changed: {old_local_ip} -> {new_local_ip}")
        
        self.public_ip_var.set("Fetching...")
        threading.Thread(target=self._fetch_public_ip, daemon=True).start()

    def open_shared_folder(self):
        """Open the shared folder in file explorer"""
        import subprocess
        import platform
        
        try:
            if platform.system() == "Windows":
                subprocess.Popen(f'explorer "{os.path.abspath(SHARED_FOLDER)}"')
            elif platform.system() == "Darwin":  # macOS
                subprocess.Popen(["open", os.path.abspath(SHARED_FOLDER)])
            else:  # Linux
                subprocess.Popen(["xdg-open", os.path.abspath(SHARED_FOLDER)])
            self.log(f"[Info] Opened shared folder: {os.path.abspath(SHARED_FOLDER)}")
        except Exception as e:
            self.log(f"[Error] Failed to open shared folder: {e}")
            messagebox.showerror("Error", f"Failed to open shared folder: {e}")

    def on_closing(self):
        """Handle application closing"""
        self.log("[Info] Shutting down...")
        
        # Close connection if active
        if self.conn_socket:
            try:
                self.conn_socket.sendall(b"QUIT")
                self.conn_socket.close()
            except:
                pass
        
        # Remove UPnP mapping
        threading.Thread(target=self._remove_upnp_port_mapping_threaded, args=(PORT,), daemon=True).start()
        
        # Give threads a moment to cleanup
        self.root.after(1000, self.root.destroy)

if __name__ == "__main__":
    root = tk.Tk()
    app = P2PApp(root)
    root.mainloop()
