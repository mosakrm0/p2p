import socket
import threading
import os
import requests
import tkinter as tk
from tkinter import messagebox, filedialog, Listbox, END, Scrollbar, Canvas, simpledialog
from tkinter.ttk import Progressbar, Style
from cryptography.fernet import Fernet
import miniupnpc
import uuid
import json
import hashlib
import base64
import datetime
import subprocess
import platform
import queue
import time

# === CONFIG ===
SHARED_FOLDER = "shared"
HOST = '0.0.0.0'
PORT = 5000
DISCOVERY_PORT = 5001
BROADCAST_ADDR = '<broadcast>'
DISCOVERY_INTERVAL = 3  # seconds
KEY_FILE = "secret.key"
CHUNK_SIZE = 8192  # Increased chunk size for better performance
MAX_LOG_LINES = 500  # Limit log size
CONNECTION_TIMEOUT = 15  # Connection timeout in seconds

# === Key Management ===
def load_or_create_key():
    """Load existing key or create default key"""
    if os.path.exists(KEY_FILE):
        try:
            with open(KEY_FILE, "rb") as key_file:
                key = key_file.read()
                # Validate key
                Fernet(key)
                return key
        except Exception:
            # Invalid key file, create new default
            pass
    
    # Use a default shared key for demo purposes
    default_key = b'ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg='
    try:
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(default_key)
    except Exception as e:
        print(f"Warning: Could not save key file: {e}")
    return default_key

def reset_key():
    """Generate a new random key"""
    key = Fernet.generate_key()
    try:
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    except Exception as e:
        print(f"Warning: Could not save key file: {e}")
    return key

def set_custom_key(key_string):
    """Set a custom key from string"""
    try:
        if len(key_string) == 44 and key_string.endswith('='):
            # Looks like a base64 encoded key
            key_bytes = key_string.encode()
        else:
            # Generate key from string using secure hash
            hash_digest = hashlib.sha256(key_string.encode('utf-8')).digest()
            key_bytes = base64.urlsafe_b64encode(hash_digest)
        
        # Test if key is valid
        test_fernet = Fernet(key_bytes)
        test_fernet.encrypt(b"test")
        
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key_bytes)
        return key_bytes
    except Exception as e:
        raise ValueError(f"Invalid key: {e}")

# Initialize encryption
try:
    AES_KEY = load_or_create_key()
    fernet = Fernet(AES_KEY)
except Exception as e:
    print(f"Critical error initializing encryption: {e}")
    exit(1)

# Ensure shared folder exists
try:
    os.makedirs(SHARED_FOLDER, exist_ok=True)
except Exception as e:
    print(f"Error creating shared folder: {e}")

# === Utility Functions ===
def get_local_ip():
    """Get local IP address with fallback"""
    try:
        # Try to connect to a remote address to determine local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

def get_public_ip():
    """Get public IP address with timeout and fallback"""
    try:
        response = requests.get('https://api.ipify.org', timeout=5)
        response.raise_for_status()
        return response.text.strip()
    except requests.RequestException:
        try:
            # Fallback to alternative service
            response = requests.get('https://httpbin.org/ip', timeout=5)
            response.raise_for_status()
            return response.json().get('origin', 'Unavailable')
        except Exception:
            return "Unavailable"

def is_port_available(port, host='localhost'):
    """Check if a port is available"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            return result != 0
    except Exception:
        return False

# === UPnP Port Forwarding ===
def add_upnp_port_mapping(internal_port, external_port, protocol='TCP', description='P2P File Sharing'):
    """Add UPnP port mapping with better error handling"""
    try:
        upnp = miniupnpc.UPnP()
        upnp.discoverdelay = 200
        
        devices_found = upnp.discover()
        if devices_found == 0:
            return False, "No UPnP devices found"
        
        upnp.selectigd()
        external_ip = upnp.externalipaddress()
        
        if not external_ip:
            return False, "Could not get external IP"
        
        # Check if mapping already exists
        existing_mapping = upnp.getspecificportmapping(external_port, protocol)
        if existing_mapping:
            return True, f"Port mapping already exists for {external_port}"
        
        success = upnp.addportmapping(external_port, protocol, 
                                    get_local_ip(), internal_port, 
                                    True, description)
        if success:
            return True, f"Successfully mapped {external_port} -> {internal_port} ({protocol})"
        else:
            return False, f"Failed to add port mapping"
            
    except Exception as e:
        return False, f"UPnP Error: {e}"

def remove_upnp_port_mapping(external_port, protocol='TCP'):
    """Remove UPnP port mapping with better error handling"""
    try:
        upnp = miniupnpc.UPnP()
        upnp.discoverdelay = 200
        
        devices_found = upnp.discover()
        if devices_found == 0:
            return False, "No UPnP devices found"
        
        upnp.selectigd()
        success = upnp.deleteportmapping(external_port, protocol)
        
        if success:
            return True, f"Successfully removed port mapping for {external_port}"
        else:
            return False, f"Failed to remove port mapping for {external_port}"
            
    except Exception as e:
        return False, f"UPnP Error: {e}"

# === Server: Handles incoming file requests ===
def handle_client(conn, addr, log_queue, get_current_fernet):
    """Handle client connections with improved error handling and security"""
    client_id = f"{addr[0]}:{addr[1]}"
    
    try:
        conn.settimeout(CONNECTION_TIMEOUT)
        log_queue.put(f"[+] Connected by {client_id}")
        
        # Get current fernet instance
        current_fernet = get_current_fernet()
        
        # Authentication challenge
        challenge = str(uuid.uuid4()).encode()
        encrypted_challenge = current_fernet.encrypt(challenge)
        conn.sendall(len(encrypted_challenge).to_bytes(4, byteorder='big'))
        conn.sendall(encrypted_challenge)

        # Receive response
        response_length = int.from_bytes(conn.recv(4), byteorder='big')
        if response_length > 1024:  # Sanity check
            raise ValueError("Response too large")
        
        response = conn.recv(response_length)
        
        try:
            decrypted_response = current_fernet.decrypt(response)
            if decrypted_response == challenge:
                conn.sendall(b"AUTH_SUCCESS")
                log_queue.put(f"[+] ✅ Authenticated client {client_id}")
            else:
                conn.sendall(b"AUTH_FAILED")
                log_queue.put(f"[-] ❌ Authentication failed for {client_id} - Challenge mismatch")
                return
        except Exception:
            conn.sendall(b"AUTH_FAILED")
            log_queue.put(f"[-] ❌ Authentication failed for {client_id} - Wrong encryption key")
            return

        # Handle client requests
        while True:
            try:
                data = conn.recv(1024).decode('utf-8')
                if not data:
                    break

                if data == "LIST":
                    handle_list_request(conn, log_queue, client_id)
                elif data.startswith("GET "):
                    filename = data.split(" ", 1)[1]
                    handle_get_request(conn, filename, current_fernet, log_queue, client_id)
                elif data.startswith("CHAT:"):
                    message = data.split("CHAT:", 1)[1]
                    log_queue.put(f"[CHAT from {client_id}] {message}")
                elif data == "QUIT":
                    break
                else:
                    log_queue.put(f"[Server] Unknown command from {client_id}: {data}")
                    
            except socket.timeout:
                log_queue.put(f"[Server] Timeout for client {client_id}")
                break
            except Exception as e:
                log_queue.put(f"[Server] Error handling request from {client_id}: {e}")
                break
                
    except Exception as e:
        log_queue.put(f"[Server] Error with client {client_id}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
        log_queue.put(f"[-] Disconnected {client_id}")

def handle_list_request(conn, log_queue, client_id):
    """Handle file list request"""
    try:
        files = []
        for filename in os.listdir(SHARED_FOLDER):
            filepath = os.path.join(SHARED_FOLDER, filename)
            if os.path.isfile(filepath):
                size = os.path.getsize(filepath)
                files.append(f"{filename} ({size:,} bytes)")
        
        files_data = "\n".join(files).encode('utf-8')
        conn.sendall(len(files_data).to_bytes(4, byteorder='big'))
        conn.sendall(files_data)
        log_queue.put(f"[Server] Sent file list to {client_id} ({len(files)} files)")
        
    except Exception as e:
        error_msg = f"ERROR: {str(e)}".encode('utf-8')
        conn.sendall(len(error_msg).to_bytes(4, byteorder='big'))
        conn.sendall(error_msg)
        log_queue.put(f"[Server] Error listing files for {client_id}: {e}")

def handle_get_request(conn, filename, current_fernet, log_queue, client_id):
    """Handle file download request with improved streaming"""
    try:
        # Sanitize filename to prevent directory traversal
        filename = os.path.basename(filename)
        filepath = os.path.join(SHARED_FOLDER, filename)
        
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            error_msg = b"ERROR: File not found"
            conn.sendall(len(error_msg).to_bytes(4, byteorder='big'))
            conn.sendall(error_msg)
            return

        filesize = os.path.getsize(filepath)
        response = f"OK:{filesize}".encode('utf-8')
        conn.sendall(len(response).to_bytes(4, byteorder='big'))
        conn.sendall(response)
        
        log_queue.put(f"[Server] Sending '{filename}' to {client_id} ({filesize:,} bytes)")
        
        # Send file in encrypted chunks
        bytes_sent = 0
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                encrypted_chunk = current_fernet.encrypt(chunk)
                chunk_size = len(encrypted_chunk).to_bytes(4, byteorder='big')
                
                conn.sendall(chunk_size)
                conn.sendall(encrypted_chunk)
                bytes_sent += len(chunk)
                
                # Send progress periodically
                if bytes_sent % (CHUNK_SIZE * 10) == 0:
                    progress = (bytes_sent / filesize) * 100
                    log_queue.put(f"[Server] Transfer progress to {client_id}: {progress:.1f}%")
        
        # Send completion signal
        conn.sendall(b'\x00\x00\x00\x00')  # 0-length chunk indicates end
        log_queue.put(f"[Server] Transfer of '{filename}' to {client_id} completed")
        
    except Exception as e:
        log_queue.put(f"[Server] Error sending file to {client_id}: {e}")
        try:
            error_msg = f"ERROR: {str(e)}".encode('utf-8')
            conn.sendall(len(error_msg).to_bytes(4, byteorder='big'))
            conn.sendall(error_msg)
        except Exception:
            pass

class P2PApp:
    def __init__(self, root):
        self.root = root
        self.root.title("P2P File Sharing v2.0")
        self.root.geometry("1200x800")
        self.root.minsize(900, 700)
        self.root.resizable(True, True)
        
        # Configure main window grid weights
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Thread-safe logging queue
        self.log_queue = queue.Queue()
        
        # Enhanced styling
        self.setup_styles()

        # Initialize variables
        self.peer_ip = tk.StringVar()
        self.peer_port = tk.StringVar(value=str(PORT))
        self.local_ip_var = tk.StringVar(value=get_local_ip())
        self.public_ip_var = tk.StringVar(value="Fetching...")
        self.current_key_var = tk.StringVar(value=AES_KEY.decode())
        self.conn_socket = None
        self.discovered_peers = set()
        self.server_thread = None
        self.is_shutting_down = False
        
        # Keep reference to current fernet for server threads
        self.current_fernet = fernet

        # Create main container with proper scrolling
        self.setup_scrollable_container()
        
        # Setup UI
        self.setup_ui()

        # Start background threads and services
        self.start_background_threads()

        # Bind events
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.bind('<Configure>', self.on_window_resize)
        
        # Bind Enter key to chat entry and connection
        self.chat_entry.bind('<Return>', lambda e: self.send_chat_message())
        
        # Start log processing
        self.process_log_queue()

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
        """Handle mouse wheel scrolling with cross-platform support"""
        if platform.system() == "Windows":
            delta = int(-1 * (event.delta / 120))
        else:
            delta = int(-1 * event.delta)
        self.canvas.yview_scroll(delta, "units")

    def on_window_resize(self, event):
        """Handle window resize events"""
        if event.widget == self.root:
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
        
        # Security section
        self.create_security_section(row=2)
        
        # Create two-column layout for better space utilization
        self.create_two_column_layout(row=3)
        
        # Chat and progress section
        self.create_chat_progress_section(row=4)
        
        # Log section (expandable)
        self.create_log_section(row=5)
        
        # Control buttons
        self.create_control_section(row=6)

    def create_title_section(self, row):
        """Create enhanced title section"""
        title_frame = tk.Frame(self.scrollable_frame, bg=self.colors['bg'], pady=15)
        title_frame.grid(row=row, column=0, sticky="ew", padx=10, pady=(0, 10))
        title_frame.grid_columnconfigure(0, weight=1)
        
        # Main title
        title_label = tk.Label(title_frame, text="🔗 P2P File Sharing Network v2.0", 
                              font=('Arial', 18, 'bold'), fg=self.colors['dark'], 
                              bg=self.colors['bg'])
        title_label.grid(row=0, column=0)
        
        # Subtitle
        subtitle_label = tk.Label(title_frame, text="Secure peer-to-peer file sharing with end-to-end encryption", 
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

    def create_security_section(self, row):
        """Create security/encryption key management section"""
        security_frame = tk.LabelFrame(self.scrollable_frame, text="🔐 Security Settings", 
                                      font=('Arial', 11, 'bold'), fg=self.colors['dark'],
                                      bg=self.colors['frame_bg'], padx=15, pady=10)
        security_frame.grid(row=row, column=0, sticky="ew", padx=10, pady=(0, 10))
        security_frame.grid_columnconfigure(0, weight=1)

        # Key display
        key_display_frame = tk.Frame(security_frame, bg=self.colors['frame_bg'])
        key_display_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        key_display_frame.grid_columnconfigure(1, weight=1)
        
        tk.Label(key_display_frame, text="Current Key:", font=('Arial', 10, 'bold'), 
                bg=self.colors['frame_bg']).grid(row=0, column=0, sticky='w')
        
        key_entry = tk.Entry(key_display_frame, textvariable=self.current_key_var, 
                            font=('Consolas', 9), state='readonly', 
                            bg='#f8f9fa', relief='solid', bd=1)
        key_entry.grid(row=0, column=1, sticky='ew', padx=(10, 5))
        
        tk.Button(key_display_frame, text="📋", command=self.copy_key,
                 font=('Arial', 8), bg=self.colors['bg'], relief='flat', 
                 padx=8, pady=2).grid(row=0, column=2)

        # Key management buttons
        buttons_frame = tk.Frame(security_frame, bg=self.colors['frame_bg'])
        buttons_frame.grid(row=1, column=0, sticky="ew")
        for i in range(3):
            buttons_frame.grid_columnconfigure(i, weight=1)

        tk.Button(buttons_frame, text="🔑 Set Custom Key", command=self.set_custom_key,
                  font=('Arial', 9, 'bold'), bg=self.colors['primary'], fg='white', 
                  relief='flat', pady=5).grid(row=0, column=0, sticky="ew", padx=(0, 5))
        tk.Button(buttons_frame, text="🎲 Generate New", command=self.generate_new_key,
                  font=('Arial', 9, 'bold'), bg=self.colors['warning'], fg='white', 
                  relief='flat', pady=5).grid(row=0, column=1, padx=5)
        tk.Button(buttons_frame, text="🔄 Use Default", command=self.use_default_key,
                  font=('Arial', 9, 'bold'), bg=self.colors['success'], fg='white', 
                  relief='flat', pady=5).grid(row=0, column=2, padx=(5, 0))

        # Info label
        info_label = tk.Label(security_frame, 
                             text="⚠️ All peers must use the same encryption key to communicate securely", 
                             font=('Arial', 9), fg=self.colors['warning'], 
                             bg=self.colors['frame_bg'])
        info_label.grid(row=2, column=0, pady=(10, 0))

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
        tk.Label(input_frame, text="IP Address:", font=('Arial', 10), 
                bg=self.colors['frame_bg']).grid(row=0, column=0, sticky='w')
        ip_entry = tk.Entry(input_frame, textvariable=self.peer_ip, font=('Arial', 10), 
                           relief='solid', bd=1)
        ip_entry.grid(row=1, column=0, sticky='ew', padx=(0, 5), pady=2)
        ip_entry.bind('<Return>', lambda e: self.connect_peer())
        
        # Port entry
        tk.Label(input_frame, text="Port:", font=('Arial', 10), 
                bg=self.colors['frame_bg']).grid(row=0, column=1, sticky='w', padx=(5, 0))
        port_entry = tk.Entry(input_frame, textvariable=self.peer_port, font=('Arial', 10), 
                             relief='solid', bd=1, width=8)
        port_entry.grid(row=1, column=1, sticky='ew', padx=5, pady=2)
        port_entry.bind('<Return>', lambda e: self.connect_peer())
        
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

        tk.Button(buttons_frame, text="🔗 Connect Selected", command=self.connect_selected_peer,
                  font=('Arial', 9, 'bold'), bg=self.colors['success'], fg='white', 
                  relief='flat', pady=5).grid(row=0, column=0, sticky="ew", padx=(0, 5))
        tk.Button(buttons_frame, text="🗑️ Clear List", command=self.clear_peers,
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
        chat_frame = tk.LabelFrame(self.scrollable_frame, text="💬 Chat & Transfer Progress", 
                                  font=('Arial', 11, 'bold'), fg=self.colors['dark'],
                                  bg=self.colors['frame_bg'], padx=15, pady=10)
        chat_frame.grid(row=row, column=0, sticky="ew", padx=10, pady=(0, 10))
        chat_frame.grid_columnconfigure(0, weight=1)

        # Chat input
        chat_input_frame = tk.Frame(chat_frame, bg=self.colors['frame_bg'])
        chat_input_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        chat_input_frame.grid_columnconfigure(0, weight=1)
        
        tk.Label(chat_input_frame, text="Send Message:", font=('Arial', 10, 'bold'), 
                bg=self.colors['frame_bg']).grid(row=0, column=0, sticky='w')
        
        chat_entry_frame = tk.Frame(chat_input_frame, bg=self.colors['frame_bg'])
        chat_entry_frame.grid(row=1, column=0, sticky="ew", pady=(5, 0))
        chat_entry_frame.grid_columnconfigure(0, weight=1)
        
        self.chat_entry = tk.Entry(chat_entry_frame, font=('Arial', 10), 
                                  relief='solid', bd=1)
        self.chat_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        tk.Button(chat_entry_frame, text="💬 Send", command=self.send_chat_message,
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
        self.progress_label = tk.Label(progress_container, text="Ready", font=('Arial', 9), 
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

        # Log controls
        log_controls = tk.Frame(log_frame, bg=self.colors['frame_bg'])
        log_controls.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        log_controls.grid_columnconfigure(0, weight=1)
        
        tk.Button(log_controls, text="🗑️ Clear Log", command=self.clear_log,
                  font=('Arial', 8), bg=self.colors['secondary'], fg='white', 
                  relief='flat', padx=10, pady=3).grid(row=0, column=1)

        # Log text with scrollbar
        log_container = tk.Frame(log_frame, bg=self.colors['frame_bg'])
        log_container.grid(row=1, column=0, sticky="nsew")
        log_container.grid_columnconfigure(0, weight=1)
        log_container.grid_rowconfigure(0, weight=1)
        
        self.log_text = tk.Text(log_container, height=12, font=('Consolas', 9), 
                                bg=self.colors['dark'], fg='#ecf0f1', insertbackground='white',
                                selectbackground=self.colors['primary'], relief='solid', bd=1,
                                wrap=tk.WORD, state='disabled')
        self.log_text.grid(row=0, column=0, sticky="nsew")
        
        log_scrollbar = Scrollbar(log_container, orient="vertical")
        log_scrollbar.config(command=self.log_text.yview)
        self.log_text.config(yscrollcommand=log_scrollbar.set)
        log_scrollbar.grid(row=0, column=1, sticky="ns")

    def create_control_section(self, row):
        """Create control buttons section"""
        control_frame = tk.Frame(self.scrollable_frame, bg=self.colors['bg'], pady=10)
        control_frame.grid(row=row, column=0, sticky="ew", padx=10)
        for i in range(4):
            control_frame.grid_columnconfigure(i, weight=1)

        tk.Button(control_frame, text="🔄 Refresh Network", command=self.refresh_network,
                  font=('Arial', 10, 'bold'), bg=self.colors['warning'], fg='white', 
                  relief='flat', padx=20, pady=8).grid(row=0, column=0, sticky="ew", padx=5)
        tk.Button(control_frame, text="📂 Open Shared Folder", command=self.open_shared_folder,
                  font=('Arial', 10, 'bold'), bg=self.colors['secondary'], fg='white', 
                  relief='flat', padx=20, pady=8).grid(row=0, column=1, padx=5)
        tk.Button(control_frame, text="💾 Export Settings", command=self.export_settings,
                  font=('Arial', 10, 'bold'), bg=self.colors['primary'], fg='white', 
                  relief='flat', padx=20, pady=8).grid(row=0, column=2, padx=5)
        tk.Button(control_frame, text="❌ Exit", command=self.on_closing,
                  font=('Arial', 10, 'bold'), bg=self.colors['danger'], fg='white', 
                  relief='flat', padx=20, pady=8).grid(row=0, column=3, padx=5)

    # === Thread-safe logging ===
    def process_log_queue(self):
        """Process log messages from queue (thread-safe)"""
        try:
            while True:
                message = self.log_queue.get_nowait()
                self._add_log_message(message)
        except queue.Empty:
            pass
        finally:
            if not self.is_shutting_down:
                self.root.after(100, self.process_log_queue)
    
    def _add_log_message(self, message):
        """Add message to log widget"""
        try:
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            formatted_message = f"[{timestamp}] {message}\n"
            
            self.log_text.config(state='normal')
            self.log_text.insert(END, formatted_message)
            self.log_text.see(END)
            
            # Keep log size manageable
            lines = int(self.log_text.index('end-1c').split('.')[0])
            if lines > MAX_LOG_LINES:
                self.log_text.delete(1.0, f"{lines - MAX_LOG_LINES}.0")
            
            self.log_text.config(state='disabled')
        except Exception as e:
            print(f"Error adding log message: {e}")

    def log(self, message):
        """Thread-safe logging method"""
        self.log_queue.put(message)

    def clear_log(self):
        """Clear the log display"""
        try:
            self.log_text.config(state='normal')
            self.log_text.delete(1.0, END)
            self.log_text.config(state='disabled')
            self.log("Log cleared")
        except Exception as e:
            print(f"Error clearing log: {e}")

    # === Background thread management ===
    def start_background_threads(self):
        """Start all background threads with proper error handling"""
        try:
            # Server thread
            self.server_thread = threading.Thread(
                target=self._server_thread, 
                args=(self.log_queue,), 
                daemon=True, 
                name="ServerThread"
            )
            self.server_thread.start()
            
            # Discovery threads
            threading.Thread(
                target=self._discovery_broadcast, 
                args=(self.local_ip_var.get(), PORT), 
                daemon=True, 
                name="DiscoveryBroadcast"
            ).start()
            
            threading.Thread(
                target=self._discovery_listener, 
                args=(self.add_peer, self.local_ip_var.get(), PORT), 
                daemon=True, 
                name="DiscoveryListener"
            ).start()
            
            # Public IP fetch
            threading.Thread(
                target=self._fetch_public_ip, 
                daemon=True, 
                name="PublicIPFetch"
            ).start()
            
            self.log("Background services started successfully")
            
        except Exception as e:
            self.log(f"Error starting background threads: {e}")
            messagebox.showerror("Startup Error", f"Failed to start services: {e}")

    def get_current_fernet(self):
        """Get current fernet instance for server threads"""
        return self.current_fernet

    # === Network methods ===
    def _fetch_public_ip(self):
        """Fetch public IP in background"""
        try:
            public_ip = get_public_ip()
            self.root.after(0, self.public_ip_var.set, public_ip)
            if public_ip != "Unavailable":
                self.log_queue.put(f"[Network] Public IP: {public_ip}")
        except Exception as e:
            self.log_queue.put(f"[Network] Failed to fetch public IP: {e}")

    def _server_thread(self, log_queue):
        """Main server thread with improved error handling"""
        server_socket = None
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((HOST, PORT))
            server_socket.listen(5)
            
            local_ip = self.local_ip_var.get()
            log_queue.put(f"[Server] Listening on {local_ip}:{PORT}")
            
            # Try UPnP port mapping
            threading.Thread(
                target=self._setup_upnp_mapping, 
                args=(log_queue,), 
                daemon=True
            ).start()

            while not self.is_shutting_down:
                try:
                    server_socket.settimeout(1.0)  # Allow periodic checks for shutdown
                    conn, addr = server_socket.accept()
                    
                    if not self.is_shutting_down:
                        client_thread = threading.Thread(
                            target=handle_client, 
                            args=(conn, addr, log_queue, self.get_current_fernet), 
                            daemon=True,
                            name=f"Client-{addr[0]}:{addr[1]}"
                        )
                        client_thread.start()
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    if not self.is_shutting_down:
                        log_queue.put(f"[Server] Error accepting connection: {e}")
                        
        except Exception as e:
            log_queue.put(f"[Server] Critical error: {e}")
        finally:
            if server_socket:
                try:
                    server_socket.close()
                except Exception:
                    pass
            log_queue.put("[Server] Server thread stopped")

    def _setup_upnp_mapping(self, log_queue):
        """Setup UPnP port mapping in background"""
        try:
            log_queue.put("[Server] Attempting UPnP port mapping...")
            success, message = add_upnp_port_mapping(PORT, PORT)
            if success:
                log_queue.put(f"[Server] UPnP: {message}")
            else:
                log_queue.put(f"[Server] UPnP failed: {message}")
        except Exception as e:
            log_queue.put(f"[Server] UPnP setup error: {e}")

    def _discovery_broadcast(self, my_ip, my_port):
        """Broadcast discovery messages"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(1.0)
            
            message = f"DISCOVER:{my_ip}:{my_port}".encode('utf-8')
            
            while not self.is_shutting_down:
                try:
                    sock.sendto(message, (BROADCAST_ADDR, DISCOVERY_PORT))
                    time.sleep(DISCOVERY_INTERVAL)
                except Exception as e:
                    if not self.is_shutting_down:
                        self.log_queue.put(f"[Discovery] Broadcast error: {e}")
                    time.sleep(DISCOVERY_INTERVAL)
                    
        except Exception as e:
            self.log_queue.put(f"[Discovery] Broadcast setup error: {e}")
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _discovery_listener(self, add_peer_func, my_ip, my_port):
        """Listen for discovery messages"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('', DISCOVERY_PORT))
            sock.settimeout(1.0)
            
            while not self.is_shutting_down:
                try:
                    data, addr = sock.recvfrom(1024)
                    msg = data.decode('utf-8')
                    
                    if msg.startswith("DISCOVER:"):
                        parts = msg.split(":")
                        if len(parts) == 3:
                            _, ip, port = parts
                            # Don't add self
                            if ip != my_ip or int(port) != my_port:
                                peer_info = f"{ip}:{port}"
                                self.root.after(0, add_peer_func, peer_info)
                                
                except socket.timeout:
                    continue
                except Exception as e:
                    if not self.is_shutting_down:
                        self.log_queue.put(f"[Discovery] Listener error: {e}")
                        
        except Exception as e:
            self.log_queue.put(f"[Discovery] Listener setup error: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    # === Security management methods ===
    def copy_key(self):
        """Copy current encryption key to clipboard"""
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.current_key_var.get())
            self.log("[Security] Encryption key copied to clipboard")
        except Exception as e:
            self.log(f"[Security] Failed to copy key: {e}")

    def set_custom_key(self):
        """Set a custom encryption key"""
        key_input = simpledialog.askstring(
            "Custom Encryption Key", 
            "Enter your custom encryption key:\n\n" +
            "• Can be any text (will be securely hashed)\n" +
            "• Or a 44-character base64 key\n" +
            "• Share the same key with other peers\n\n" +
            "Key:",
            show='*'
        )
        
        if key_input and key_input.strip():
            try:
                global fernet, AES_KEY
                AES_KEY = set_custom_key(key_input.strip())
                fernet = Fernet(AES_KEY)
                self.current_fernet = fernet
                self.current_key_var.set(AES_KEY.decode())
                self.log("[Security] ✅ Custom encryption key set successfully")
                messagebox.showinfo("Success", 
                    "Custom key set successfully!\n\n" +
                    "Share this exact key with other peers:\n" +
                    f"{AES_KEY.decode()}")
            except ValueError as e:
                messagebox.showerror("Invalid Key", f"Failed to set key:\n{e}")
                self.log(f"[Security] ❌ Failed to set custom key: {e}")
            except Exception as e:
                messagebox.showerror("Error", f"Unexpected error:\n{e}")
                self.log(f"[Security] ❌ Unexpected error setting key: {e}")

    def generate_new_key(self):
        """Generate a new random encryption key"""
        if messagebox.askyesno("Generate New Key", 
                              "Generate a new random encryption key?\n\n" +
                              "⚠️ You'll need to share this key with other peers.\n" +
                              "⚠️ Existing connections will be broken.\n\n" +
                              "Continue?"):
            try:
                global fernet, AES_KEY
                AES_KEY = reset_key()
                fernet = Fernet(AES_KEY)
                self.current_fernet = fernet
                self.current_key_var.set(AES_KEY.decode())
                self.log("[Security] ✅ New random encryption key generated")
                
                # Disconnect existing connections
                self._disconnect_peer()
                
                messagebox.showinfo("New Key Generated", 
                    "New encryption key generated!\n\n" +
                    "Copy and share this key with other peers:\n" +
                    f"{AES_KEY.decode()}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate key:\n{e}")
                self.log(f"[Security] ❌ Failed to generate new key: {e}")

    def use_default_key(self):
        """Reset to default shared key"""
        if messagebox.askyesno("Use Default Key", 
                              "Reset to the default shared encryption key?\n\n" +
                              "This will allow connection with fresh instances\n" +
                              "that haven't customized their keys.\n\n" +
                              "Continue?"):
            try:
                global fernet, AES_KEY
                default_key = b'ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg='
                with open(KEY_FILE, "wb") as key_file:
                    key_file.write(default_key)
                AES_KEY = default_key
                fernet = Fernet(AES_KEY)
                self.current_fernet = fernet
                self.current_key_var.set(AES_KEY.decode())
                self.log("[Security] ✅ Reset to default shared encryption key")
                
                # Disconnect existing connections
                self._disconnect_peer()
                
                messagebox.showinfo("Default Key Set", 
                    "Default encryption key restored!\n\n" +
                    "This should work with other fresh instances.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to set default key:\n{e}")
                self.log(f"[Security] ❌ Failed to set default key: {e}")

    # === UI event handlers ===
    def add_peer(self, peer_info):
        """Add discovered peer to list (thread-safe)"""
        try:
            if peer_info not in self.discovered_peers:
                self.discovered_peers.add(peer_info)
                self.peers_listbox.insert(END, peer_info)
                self.log(f"[Discovery] 🌐 Found peer: {peer_info}")
        except Exception as e:
            self.log(f"[Discovery] Error adding peer: {e}")

    def copy_local_ip(self):
        """Copy local IP to clipboard"""
        try:
            ip = self.local_ip_var.get()
            self.root.clipboard_clear()
            self.root.clipboard_append(ip)
            self.log(f"[Info] 📋 Local IP copied: {ip}")
        except Exception as e:
            self.log(f"[Info] Failed to copy local IP: {e}")

    def copy_public_ip(self):
        """Copy public IP to clipboard"""
        try:
            public_ip = self.public_ip_var.get()
            if public_ip not in ["Fetching...", "Unavailable"]:
                self.root.clipboard_clear()
                self.root.clipboard_append(public_ip)
                self.log(f"[Info] 📋 Public IP copied: {public_ip}")
            else:
                self.log("[Info] ❌ Public IP not available")
                messagebox.showwarning("Not Available", "Public IP is not available")
        except Exception as e:
            self.log(f"[Info] Failed to copy public IP: {e}")

    def copy_port(self):
        """Copy port to clipboard"""
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(str(PORT))
            self.log(f"[Info] 📋 Port copied: {PORT}")
        except Exception as e:
            self.log(f"[Info] Failed to copy port: {e}")

    def connect_peer(self):
        """Connect to specified peer"""
        peer_address = self.peer_ip.get().strip()
        peer_port = self.peer_port.get().strip()
        
        if not peer_address:
            messagebox.showerror("Missing Information", "Please enter an IP address.")
            return
        
        if not peer_port:
            peer_port = str(PORT)  # Use default port
            self.peer_port.set(peer_port)
        
        try:
            port = int(peer_port)
            if port < 1 or port > 65535:
                raise ValueError("Port must be between 1 and 65535")
                
            self.log(f"[Client] 🔗 Connecting to {peer_address}:{port}...")
            threading.Thread(
                target=self._connect_peer_threaded, 
                args=(peer_address, port), 
                daemon=True,
                name=f"Connect-{peer_address}:{port}"
            ).start()
        except ValueError as e:
            messagebox.showerror("Invalid Port", f"Invalid port number: {e}")
            self.log(f"[Client] ❌ Invalid port: {e}")

    def _connect_peer_threaded(self, peer_address, port):
        """Connect to peer in background thread"""
        try:
            # Close existing connection
            self._disconnect_peer()
            
            self.conn_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn_socket.settimeout(CONNECTION_TIMEOUT)
            
            self.root.after(0, self.progress_label.config, {"text": "Connecting..."})
            self.conn_socket.connect((peer_address, port))
            
            self.log_queue.put(f"[Client] ✅ Connected to {peer_address}:{port}")
            
            # Authenticate
            if self._authenticate_peer():
                self.root.after(0, self.progress_label.config, {"text": "Connected"})
                self.log_queue.put(f"[Client] 🤝 Ready to transfer files")
            else:
                self._disconnect_peer()
                
        except socket.timeout:
            self.log_queue.put(f"[Client] ⏰ Connection timeout to {peer_address}:{port}")
            self.root.after(0, messagebox.showerror, "Connection Timeout", 
                           f"Connection to {peer_address}:{port} timed out.\n\n" +
                           "Check if the peer is online and port is accessible.")
            self._disconnect_peer()
        except ConnectionRefusedError:
            self.log_queue.put(f"[Client] 🚫 Connection refused by {peer_address}:{port}")
            self.root.after(0, messagebox.showerror, "Connection Refused", 
                           f"Connection refused by {peer_address}:{port}.\n\n" +
                           "The peer may not be running or port is blocked.")
            self._disconnect_peer()
        except Exception as e:
            self.log_queue.put(f"[Client] ❌ Connection failed: {e}")
            self.root.after(0, messagebox.showerror, "Connection Error", 
                           f"Could not connect to {peer_address}:{port}:\n{e}")
            self._disconnect_peer()

    def _authenticate_peer(self):
        """Authenticate with peer using challenge-response"""
        try:
            if not self.conn_socket:
                return False
            
            # Receive challenge
            challenge_length = int.from_bytes(self.conn_socket.recv(4), byteorder='big')
            if challenge_length > 1024:
                raise ValueError("Challenge too large")
            
            encrypted_challenge = self.conn_socket.recv(challenge_length)
            if not encrypted_challenge:
                raise Exception("No challenge received")
            
            # Decrypt and respond
            try:
                challenge = self.current_fernet.decrypt(encrypted_challenge)
                response = self.current_fernet.encrypt(challenge)
                
                self.conn_socket.sendall(len(response).to_bytes(4, byteorder='big'))
                self.conn_socket.sendall(response)
                
                # Get result
                result = self.conn_socket.recv(1024).decode('utf-8')
                
                if result == "AUTH_SUCCESS":
                    self.log_queue.put("[Client] ✅ Authentication successful")
                    return True
                else:
                    self.log_queue.put("[Client] ❌ Authentication failed - Server rejected")
                    self.root.after(0, messagebox.showerror, "Authentication Failed", 
                                   "Server rejected authentication.\n\n" +
                                   "Possible causes:\n" +
                                   "• Different encryption keys\n" +
                                   "• Network error\n" +
                                   "• Server issue")
                    return False
                    
            except Exception as decrypt_error:
                self.log_queue.put(f"[Client] ❌ Authentication failed - Wrong key: {decrypt_error}")
                self.root.after(0, messagebox.showerror, "Authentication Failed", 
                               "Authentication failed - Wrong encryption key!\n\n" +
                               "Solutions:\n" +
                               "1. Use the same custom key on both peers\n" +
                               "2. Both use 'Use Default' key\n" +
                               "3. Share the same generated key")
                return False
                
        except Exception as e:
            self.log_queue.put(f"[Client] ❌ Authentication error: {e}")
            self.root.after(0, messagebox.showerror, "Authentication Error", 
                           f"Authentication process failed:\n{e}")
            return False

    def _disconnect_peer(self):
        """Safely disconnect from peer"""
        if self.conn_socket:
            try:
                self.conn_socket.sendall(b"QUIT")
                self.conn_socket.close()
            except Exception:
                pass
            finally:
                self.conn_socket = None
                self.root.after(0, self.progress_label.config, {"text": "Disconnected"})

    def connect_selected_peer(self):
        """Connect to selected peer from discovery list"""
        try:
            selected_index = self.peers_listbox.curselection()
            if not selected_index:
                messagebox.showwarning("No Selection", "Please select a peer from the list.")
                return
            
            peer_info = self.peers_listbox.get(selected_index[0])
            ip, port = peer_info.split(":")
            self.peer_ip.set(ip)
            self.peer_port.set(port)
            self.log(f"[Client] Selected peer: {peer_info}")
            self.connect_peer()
        except ValueError:
            messagebox.showerror("Invalid Peer", "Invalid peer format in list.")
            self.log("[Client] ❌ Invalid peer format in discovery list")
        except Exception as e:
            messagebox.showerror("Selection Error", f"Error selecting peer: {e}")
            self.log(f"[Client] ❌ Error selecting peer: {e}")

    def clear_peers(self):
        """Clear discovered peers list"""
        try:
            self.discovered_peers.clear()
            self.peers_listbox.delete(0, END)
            self.log("[Discovery] 🗑️ Cleared discovered peers list")
        except Exception as e:
            self.log(f"[Discovery] Error clearing peers: {e}")

    def list_remote_files(self):
        """List files on connected peer"""
        if not self.conn_socket:
            messagebox.showerror("Not Connected", "Please connect to a peer first.")
            return
        
        self.log("[Client] 📋 Requesting file list...")
        threading.Thread(
            target=self._list_remote_files_threaded, 
            daemon=True,
            name="ListFiles"
        ).start()

    def _list_remote_files_threaded(self):
        """List remote files in background thread"""
        try:
            if not self.conn_socket:
                return
            
            self.conn_socket.sendall(b"LIST")
            
            # Receive response length
            response_length = int.from_bytes(self.conn_socket.recv(4), byteorder='big')
            if response_length > 10240:  # Sanity check for file list size
                raise ValueError("Response too large")
            
            # Receive file list
            files_data = self.conn_socket.recv(response_length).decode('utf-8')
            
            self.root.after(0, self.remote_files_listbox.delete, 0, END)
            
            if files_data.strip():
                if files_data.startswith("ERROR:"):
                    error_msg = files_data.replace("ERROR:", "").strip()
                    self.log_queue.put(f"[Client] ❌ Server error: {error_msg}")
                    self.root.after(0, messagebox.showerror, "Server Error", f"Server error: {error_msg}")
                else:
                    files = [f.strip() for f in files_data.split("\n") if f.strip()]
                    for f in files:
                        self.root.after(0, self.remote_files_listbox.insert, END, f)
                    self.log_queue.put(f"[Client] 📋 Listed {len(files)} remote files")
            else:
                self.log_queue.put("[Client] 📂 No remote files found")
                
        except Exception as e:
            self.log_queue.put(f"[Client] ❌ Failed to list remote files: {e}")
            self.root.after(0, messagebox.showerror, "List Error", f"Failed to list files: {e}")
            self._disconnect_peer()

    def download_selected_file(self):
        """Download selected file from remote peer"""
        try:
            selected_index = self.remote_files_listbox.curselection()
            if not selected_index:
                messagebox.showwarning("No Selection", "Please select a file to download.")
                return
            
            file_info = self.remote_files_listbox.get(selected_index[0])
            # Extract filename (remove size info if present)
            filename = file_info.split(" (")[0] if " (" in file_info else file_info
            
            if not self.conn_socket:
                messagebox.showerror("Not Connected", "Please connect to a peer first.")
                return

            # Choose save location
            save_path = filedialog.asksaveasfilename(
                title="Save File As",
                initialfile=filename,
                defaultextension="",
                filetypes=[("All files", "*.*")]
            )
            
            if not save_path:
                return

            self.log(f"[Client] 📥 Starting download: {filename}")
            threading.Thread(
                target=self._download_file_threaded, 
                args=(filename, save_path), 
                daemon=True,
                name=f"Download-{filename}"
            ).start()
            
        except Exception as e:
            messagebox.showerror("Download Error", f"Error starting download: {e}")
            self.log(f"[Client] ❌ Error starting download: {e}")

    def _download_file_threaded(self, filename, save_path):
        """Download file in background thread with progress updates"""
        try:
            if not self.conn_socket:
                return
            
            # Send download request
            request = f"GET {filename}"
            self.conn_socket.sendall(request.encode('utf-8'))
            
            # Receive response length
            response_length = int.from_bytes(self.conn_socket.recv(4), byteorder='big')
            response = self.conn_socket.recv(response_length).decode('utf-8')

            if response.startswith("ERROR:"):
                error_msg = response.replace("ERROR:", "").strip()
                self.log_queue.put(f"[Client] ❌ Download error: {error_msg}")
                self.root.after(0, messagebox.showerror, "Download Error", f"Server error: {error_msg}")
                return
            
            if not response.startswith("OK:"):
                self.log_queue.put(f"[Client] ❌ Unexpected response: {response}")
                return
            
            # Parse file size
            filesize = int(response.split(":")[1])
            self.log_queue.put(f"[Client] 📥 Downloading '{filename}' ({filesize:,} bytes)")
            
            # Initialize progress
            self.root.after(0, self.progress_bar.configure, {"value": 0})
            self.root.after(0, self.progress_label.config, {"text": "0%"})
            
            downloaded_bytes = 0
            start_time = time.time()
            
            with open(save_path, "wb") as f:
                while downloaded_bytes < filesize:
                    # Receive chunk size
                    chunk_size_bytes = self.conn_socket.recv(4)
                    if len(chunk_size_bytes) != 4:
                        break
                    
                    chunk_size = int.from_bytes(chunk_size_bytes, byteorder='big')
                    
                    # Check for end signal
                    if chunk_size == 0:
                        break
                    
                    # Receive encrypted chunk
                    encrypted_chunk = b""
                    while len(encrypted_chunk) < chunk_size:
                        data = self.conn_socket.recv(chunk_size - len(encrypted_chunk))
                        if not data:
                            raise Exception("Connection lost during transfer")
                        encrypted_chunk += data
                    
                    # Decrypt and write
                    try:
                        decrypted_chunk = self.current_fernet.decrypt(encrypted_chunk)
                        f.write(decrypted_chunk)
                        downloaded_bytes += len(decrypted_chunk)
                        
                        # Update progress
                        progress = min((downloaded_bytes / filesize) * 100, 100)
                        elapsed = time.time() - start_time
                        speed = downloaded_bytes / elapsed if elapsed > 0 else 0
                        
                        progress_text = f"{progress:.1f}% ({speed/1024:.1f} KB/s)"
                        self.root.after(0, self.progress_bar.configure, {"value": progress})
                        self.root.after(0, self.progress_label.config, {"text": progress_text})
                        
                    except Exception as decrypt_error:
                        self.log_queue.put(f"[Client] ❌ Decryption error: {decrypt_error}")
                        raise Exception("File decryption failed - data corruption or wrong key")

            # Verify download completion
            if downloaded_bytes == filesize:
                elapsed = time.time() - start_time
                avg_speed = downloaded_bytes / elapsed if elapsed > 0 else 0
                
                self.log_queue.put(f"[Client] ✅ Download completed: '{filename}' ({avg_speed/1024:.1f} KB/s avg)")
                self.root.after(0, messagebox.showinfo, "Download Complete", 
                               f"'{filename}' downloaded successfully!\n\n" +
                               f"Size: {filesize:,} bytes\n" +
                               f"Time: {elapsed:.1f}s\n" +
                               f"Speed: {avg_speed/1024:.1f} KB/s")
                self.root.after(0, self.progress_bar.configure, {"value": 100})
                self.root.after(0, self.progress_label.config, {"text": "Complete"})
            else:
                raise Exception(f"Incomplete download: {downloaded_bytes}/{filesize} bytes")
                
        except Exception as e:
            self.log_queue.put(f"[Client] ❌ Download failed: {e}")
            self.root.after(0, messagebox.showerror, "Download Failed", f"Download failed: {e}")
            self.root.after(0, self.progress_label.config, {"text": "Failed"})
            
            # Clean up partial file
            try:
                if os.path.exists(save_path):
                    os.remove(save_path)
            except Exception:
                pass
            
            self._disconnect_peer()

    def send_chat_message(self):
        """Send chat message to connected peer"""
        if not self.conn_socket:
            messagebox.showerror("Not Connected", "Please connect to a peer first.")
            return
        
        message = self.chat_entry.get().strip()
        if not message:
            return
        
        # Clear entry immediately for better UX
        self.chat_entry.delete(0, END)
        
        threading.Thread(
            target=self._send_chat_message_threaded, 
            args=(message,), 
            daemon=True,
            name="SendChat"
        ).start()

    def _send_chat_message_threaded(self, message):
        """Send chat message in background thread"""
        try:
            if not self.conn_socket:
                return
            
            chat_data = f"CHAT:{message}"
            self.conn_socket.sendall(chat_data.encode('utf-8'))
            self.log_queue.put(f"[Me] 💬 {message}")
            
        except Exception as e:
            self.log_queue.put(f"[Client] ❌ Failed to send message: {e}")
            self.root.after(0, messagebox.showerror, "Message Error", f"Failed to send message: {e}")
            self._disconnect_peer()

    def refresh_network(self):
        """Refresh network information and clear discovery"""
        try:
            self.log("[Info] 🔄 Refreshing network information...")
            
            # Update local IP
            old_local_ip = self.local_ip_var.get()
            new_local_ip = get_local_ip()
            self.local_ip_var.set(new_local_ip)
            
            if old_local_ip != new_local_ip:
                self.log(f"[Info] 📍 Local IP changed: {old_local_ip} → {new_local_ip}")
            
            # Refresh public IP
            self.public_ip_var.set("Fetching...")
            threading.Thread(target=self._fetch_public_ip, daemon=True).start()
            
            # Clear peer discovery
            self.clear_peers()
            
            self.log("[Info] ✅ Network refresh completed")
            
        except Exception as e:
            self.log(f"[Info] ❌ Network refresh failed: {e}")
            messagebox.showerror("Refresh Error", f"Failed to refresh network: {e}")

    def open_shared_folder(self):
        """Open the shared folder in file explorer"""
        try:
            shared_path = os.path.abspath(SHARED_FOLDER)
            
            if platform.system() == "Windows":
                subprocess.Popen(f'explorer "{shared_path}"')
            elif platform.system() == "Darwin":  # macOS
                subprocess.Popen(["open", shared_path])
            else:  # Linux and others
                subprocess.Popen(["xdg-open", shared_path])
                
            self.log(f"[Info] 📂 Opened shared folder: {shared_path}")
            
        except Exception as e:
            self.log(f"[Error] ❌ Failed to open shared folder: {e}")
            messagebox.showerror("Folder Error", 
                               f"Failed to open shared folder: {e}\n\n" +
                               f"Path: {os.path.abspath(SHARED_FOLDER)}")

    def export_settings(self):
        """Export current settings to a file"""
        try:
            settings = {
                "encryption_key": self.current_key_var.get(),
                "local_ip": self.local_ip_var.get(),
                "public_ip": self.public_ip_var.get(),
                "port": PORT,
                "timestamp": datetime.datetime.now().isoformat(),
                "version": "2.0"
            }
            
            save_path = filedialog.asksaveasfilename(
                title="Export Settings",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                initialfile=f"p2p_settings_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            
            if save_path:
                with open(save_path, 'w') as f:
                    json.dump(settings, f, indent=2)
                
                self.log(f"[Info] 💾 Settings exported to: {save_path}")
                messagebox.showinfo("Export Complete", f"Settings exported successfully to:\n{save_path}")
                
        except Exception as e:
            self.log(f"[Error] ❌ Failed to export settings: {e}")
            messagebox.showerror("Export Error", f"Failed to export settings: {e}")

    def on_closing(self):
        """Handle application closing with proper cleanup"""
        try:
            self.log("[Info] 🔄 Shutting down application...")
            self.is_shutting_down = True
            
            # Close peer connection
            self._disconnect_peer()
            
            # Remove UPnP mapping in background
            threading.Thread(
                target=self._cleanup_upnp, 
                daemon=True
            ).start()
            
            # Give threads time to cleanup
            self.root.after(2000, self._force_exit)
            
        except Exception as e:
            print(f"Error during shutdown: {e}")
            self.root.destroy()

    def _cleanup_upnp(self):
        """Clean up UPnP port mapping"""
        try:
            success, message = remove_upnp_port_mapping(PORT)
            if success:
                self.log_queue.put(f"[Server] 🔌 UPnP cleanup: {message}")
            else:
                self.log_queue.put(f"[Server] ⚠️ UPnP cleanup failed: {message}")
        except Exception as e:
            self.log_queue.put(f"[Server] ❌ UPnP cleanup error: {e}")

    def _force_exit(self):
        """Force application exit"""
        try:
            self.root.destroy()
        except Exception:
            pass

# === Main Application Entry Point ===
def main():
    """Main application entry point with error handling"""
    try:
        # Check port availability
        if not is_port_available(PORT):
            print(f"Warning: Port {PORT} may already be in use")
        
        # Create and run application
        root = tk.Tk()
        app = P2PApp(root)
        
        # Center window on screen
        root.update_idletasks()
        x = (root.winfo_screenwidth() // 2) - (root.winfo_width() // 2)
        y = (root.winfo_screenheight() // 2) - (root.winfo_height() // 2)
        root.geometry(f"+{x}+{y}")
        
        root.mainloop()
        
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
    except Exception as e:
        print(f"Critical error starting application: {e}")
        messagebox.showerror("Startup Error", f"Failed to start P2P File Sharing:\n{e}")
    finally:
        print("Application terminated")

if __name__ == "__main__":
    main()
