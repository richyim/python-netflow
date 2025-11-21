import tkinter as tk
from tkinter import messagebox, ttk
import socket
import struct
import time
import threading
import queue
import datetime
import sys
import subprocess
import os
import csv # Import the csv module

# --- Configuration ---
NETFLOW_COLLECTOR_IP = "127.0.0.1"
NETFLOW_COLLECTOR_PORT = 2055
MAX_UDP_PACKET_SIZE = 65535 # Max theoretical UDP packet size
CSV_MAX_ENTRIES_PER_FILE = 200 # Changed from 1000 to 50
AUTO_CLOSE_MESSAGE_DURATION_MS = 10000 # 10 seconds for auto-closing messages

# --- Well-Known IP Protocol Names ---
IP_PROTOCOL_NAMES = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    3: "GGP",
    4: "IPinIP",
    6: "TCP",
    8: "EGP",
    9: "IGP",
    11: "NVP-II",
    17: "UDP",
    41: "Ipv6",
    43: "IPv6-Route",
    44: "IPv6-Frag",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    59: "IPv6-NoNxt",
    60: "IPv6-Opt",
    88: "EIGRP",
    89: "OSPF",
    103: "PIM",
    112: "VRRP",
    132: "SCTP",
    179: "BGP",
    # Add more as needed
}

# --- Well-Known ICMP Type Names ---
ICMP_TYPE_NAMES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    5: "Redirect",
    8: "Echo Request",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
    15: "Information Request (Deprecated)",
    16: "Information Reply (Deprecated)",
    17: "Address Mask Request (Deprecated)",
    18: "Address Mask Reply (Deprecated)",
    # Add more as needed based on RFC 792 and IANA assignments
}


# --- NetFlow v9 Information Element (IE) Definitions ---
# This dictionary maps IE type numbers to their name, expected struct format (if fixed),
# and a decoding function. For variable length fields, format is None.
IE_TYPES = {
    1: {"name": "IN_BYTES", "format": "!I", "decode": lambda x: str(x)},
    2: {"name": "IN_PKTS", "format": "!I", "decode": lambda x: str(x)},
    4: {"name": "PROTOCOL", "format": "!B", "decode": lambda x: IP_PROTOCOL_NAMES.get(x, str(x))},
    5: {"name": "SRC_TOS", "format": "!B", "decode": lambda x: f"DSCP: {x >> 2}"},
    7: {"name": "SRC_PORT", "format": "!H", "decode": lambda x: str(x)},
    8: {"name": "IPV4_SRC_ADDR", "format": "!I", "decode": lambda x: socket.inet_ntoa(struct.pack("!I", x))},
    11: {"name": "DST_PORT", "format": "!H", "decode": lambda x: str(x)},
    12: {"name": "IPV4_DST_ADDR", "format": "!I", "decode": lambda x: socket.inet_ntoa(struct.pack("!I", x))},
    15: {"name": "IPV4_NEXT_HOP", "format": "!I", "decode": lambda x: socket.inet_ntoa(struct.pack("!I", x))},
    82: {"name": "IF_NAME", "format": None, "decode": lambda x: x.decode('utf-8', errors='ignore').strip('\0')},
    # NEW: ICMP Type and Code
    176: {"name": "ICMP_TYPE", "format": "!B", "decode": lambda x: ICMP_TYPE_NAMES.get(x, str(x))},
    177: {"name": "ICMP_CODE", "format": "!B", "decode": lambda x: str(x)},
    # Add more IE types here if you need to decode them
}

# Global storage for templates and raw/decoded data
# templates_cache: {(source_id, template_id): [(field_type, field_length), ...]}
templates_cache = {}
raw_packet_queue = queue.Queue()
decoded_flow_queue = queue.Queue()

# --- UDP Listener Thread ---
class NetFlowListener(threading.Thread):
    def __init__(self, ip, port, raw_queue, decoded_queue):
        super().__init__()
        self.ip = ip
        self.port = port
        self.raw_queue = raw_queue
        self.decoded_queue = decoded_queue
        self.running = False
        self.sock = None

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.bind((self.ip, self.port))
            self.sock.settimeout(1.0) # Timeout to allow checking self.running flag
            self.running = True
            print(f"NetFlow listener started on {self.ip}:{self.port}")

            while self.running:
                try:
                    data, addr = self.sock.recvfrom(MAX_UDP_PACKET_SIZE)
                    self.raw_queue.put((data, addr, datetime.datetime.now()))
                    self.process_netflow_packet(data, addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Error receiving NetFlow packet: {e}")
            
        except OSError as e:
            print(f"Failed to bind socket on {self.ip}:{self.port}: {e}")
            self.raw_queue.put((f"ERROR: Failed to bind socket on {self.ip}:{self.port}: {e}".encode(), ("N/A", "N/A"), datetime.datetime.now()))
            self.running = False # Stop if binding fails
        finally:
            if self.sock:
                self.sock.close()
            print("NetFlow listener stopped.")

    def stop(self):
        self.running = False
        # The socket timeout helps the thread exit gracefully when self.running becomes False

    def process_netflow_packet(self, data, addr):
        try:
            # NetFlow v9 Header (20 bytes: version, count, sys_uptime, unix_secs, sequence_number, source_id)
            if len(data) < 20:
                return

            header_data = data[:20]
            version, count, sys_uptime, unix_secs, sequence_number, source_id = struct.unpack("!HHIIII", header_data)

            if version != 9:
                return # Silently ignore non-v9 packets

            offset = 20 # Start of first FlowSet

            packet_decoded_flows = []

            while offset < len(data):
                if offset + 4 > len(data): # Check if there's enough data for flowset header
                    break

                flowset_header = data[offset : offset + 4]
                flowset_id, flowset_length = struct.unpack("!HH", flowset_header)
                
                # Ensure flowset_length is reasonable and within packet bounds
                if flowset_length < 4 or offset + flowset_length > len(data):
                    break # Stop processing this packet

                flowset_data = data[offset + 4 : offset + flowset_length]
                current_flowset_offset = 0

                if flowset_id == 0:  # Template FlowSet (ID 0)
                    while current_flowset_offset < len(flowset_data):
                        if current_flowset_offset + 4 > len(flowset_data):
                            break

                        template_record_header = flowset_data[current_flowset_offset : current_flowset_offset + 4]
                        template_id, field_count = struct.unpack("!HH", template_record_header)
                        current_flowset_offset += 4

                        fields = []
                        for _ in range(field_count):
                            if current_flowset_offset + 4 > len(flowset_data):
                                break # Break from field parsing, try next record/flowset

                            field_specifier = flowset_data[current_flowset_offset : current_flowset_offset + 4]
                            field_type, field_length = struct.unpack("!HH", field_specifier)
                            fields.append((field_type, field_length))
                            current_flowset_offset += 4
                        
                        if len(fields) == field_count: # Only store if all fields were parsed successfully
                            templates_cache[(source_id, template_id)] = fields
                        else:
                            pass

                elif flowset_id > 255: # Data FlowSet (ID > 255)
                    template_key = (source_id, flowset_id)
                    if template_key not in templates_cache:
                        offset += flowset_length # Skip this flowset
                        continue

                    template_fields = templates_cache[template_key]
                    
                    while current_flowset_offset < len(flowset_data):
                        flow_record = {}
                        
                        expected_record_length = sum(fl for ft, fl in template_fields)
                        if current_flowset_offset + expected_record_length > len(flowset_data):
                            current_flowset_offset = len(flowset_data) # Move to end of flowset data
                            break

                        for field_type, field_length in template_fields:
                            if current_flowset_offset + field_length > len(flowset_data):
                                break

                            field_value_raw = flowset_data[current_flowset_offset : current_flowset_offset + field_length]
                            
                            ie_info = IE_TYPES.get(field_type)
                            if ie_info:
                                field_name = ie_info["name"]
                                decode_func = ie_info["decode"]
                                
                                if ie_info["format"]: # Fixed format field
                                    try:
                                        if len(field_value_raw) == struct.calcsize(ie_info["format"]):
                                            decoded_value = decode_func(struct.unpack(ie_info["format"], field_value_raw)[0])
                                        else:
                                            decoded_value = f"RAW: {field_value_raw.hex()} (len mismatch {len(field_value_raw)} vs {struct.calcsize(ie_info['format'])})"
                                    except struct.error:
                                        decoded_value = f"RAW: {field_value_raw.hex()} (struct error)"
                                else: # Variable length field (like IF_NAME)
                                    decoded_value = decode_func(field_value_raw)
                                
                                flow_record[field_name] = decoded_value
                            else:
                                flow_record[f"UNKNOWN_FIELD_{field_type}"] = field_value_raw.hex()
                            
                            current_flowset_offset += field_length
                        
                        if flow_record: # Only add if successfully parsed some fields
                            packet_decoded_flows.append(flow_record)
                
                offset += flowset_length # Move to next FlowSet

            if packet_decoded_flows:
                self.decoded_queue.put({"timestamp": datetime.datetime.now(), "source_addr": addr[0], "flows": packet_decoded_flows})

        except struct.error as e:
            print(f"Struct unpacking error in NetFlow packet from {addr}: {e}. Raw data: {data.hex()}")
        except Exception as e:
            print(f"General error processing NetFlow packet from {addr}: {e}. Raw data: {data.hex()}")


# --- CSV Writer Class ---
class NetFlowCSVWriter:
    def __init__(self, headers, max_entries_per_file=1000, output_dir=".", message_callback=None, quit_app_callback=None):
        self.headers = headers
        self.max_entries_per_file = max_entries_per_file
        self.output_dir = output_dir
        self.message_callback = message_callback # Store the callback for messages
        self.quit_app_callback = quit_app_callback # Store the callback for quitting
        os.makedirs(self.output_dir, exist_ok=True) # Ensure output directory exists

        self.current_file = None
        self.csv_writer = None
        self.entry_count = 0
        self.current_file_path = None

        self._open_new_file_internal(is_initial_open=True) # Open the first file on initialization

    def _generate_filename(self):
        """Generates a timestamped filename like DDMon-HH-MM-SS.csv."""
        # Changed "%H:%M:%S" to "%H-%M-%S" to avoid invalid characters in Windows filenames
        timestamp_str = datetime.datetime.now().strftime("%d%b-%H-%M-%S")
        return os.path.join(self.output_dir, f"{timestamp_str}.csv")

    def _open_new_file_internal(self, is_initial_open=False, reason_message=None):
        """Internal method to close current file and open a new one.
           Can be called for rotation or manual cut.
        """
        # Show message *before* closing the old file, so we can refer to its name
        if not is_initial_open and self.current_file_path and self.message_callback:
            if reason_message:
                self.message_callback("CSV File Event", reason_message, self.quit_app_callback)
            else:
                self.message_callback("CSV File Rotation", f"CSV file '{os.path.basename(self.current_file_path)}' reached {self.max_entries_per_file} entries. Starting a new file.", self.quit_app_callback)

        self.close() # Close any existing file

        self.current_file_path = self._generate_filename()
        try:
            # Use newline='' for csv.writer to prevent extra blank rows
            self.current_file = open(self.current_file_path, 'w', newline='', encoding='utf-8')
            self.csv_writer = csv.writer(self.current_file)
            self.csv_writer.writerow(self.headers) # Write headers as the first row
            self.entry_count = 0
            print(f"Started new CSV file: {self.current_file_path}")
        except IOError as e:
            print(f"Error opening new CSV file {self.current_file_path}: {e}")
            self.current_file = None
            self.csv_writer = None

    def write_flow(self, flow_data_values):
        """Writes a single flow record to the CSV file, rotating if needed."""
        if self.csv_writer is None:
            # Attempt to re-open if it failed previously or was never opened
            self._open_new_file_internal()
            if self.csv_writer is None: # If still failed, cannot write
                return

        if self.entry_count >= self.max_entries_per_file:
            self._open_new_file_internal() # This will trigger the message via the callback
            if self.csv_writer is None: # If re-opening failed
                return

        try:
            self.csv_writer.writerow(flow_data_values)
            self.entry_count += 1
        except Exception as e:
            print(f"Error writing to CSV file {self.current_file_path}: {e}")

    def cut_and_save(self):
        """Forces the current file to close and a new one to open."""
        message = ""
        if self.current_file_path and self.current_file and not self.current_file.closed:
            message = f"Manually cutting and saving current CSV file '{os.path.basename(self.current_file_path)}'. Starting a new file."
        else:
            message = "No active CSV file to cut. Starting a new file."
        
        self._open_new_file_internal(reason_message=message)

    def close(self):
        """Closes the current CSV file if it's open."""
        if self.current_file and not self.current_file.closed:
            self.current_file.close()
            print(f"Closed CSV file: {self.current_file_path}")
        self.current_file = None
        self.csv_writer = None


# --- Tkinter GUI ---
class NetFlowGUI:
    def __init__(self, master):
        self.master = master
        master.title("NetFlow v9 Receiver")
        master.geometry("450x280")

        self.listener = None
        self.raw_queue = raw_packet_queue
        self.decoded_queue = decoded_flow_queue

        self.create_widgets()
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing) # Handle main window close event
        self.master.after(100, self.check_queues) # Start checking queues periodically

        self.logs_window = None
        self.decoded_window = None

    def create_widgets(self):
        self.status_label = tk.Label(self.master, text="Listener Stopped", fg="red", font=("Arial", 12, "bold"))
        self.status_label.pack(pady=10)

        self.start_button = tk.Button(self.master, text="Start Listener", command=self.start_listener, width=20, height=2)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(self.master, text="Stop Listener", command=self.stop_listener, width=20, height=2, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        self.open_logs_button = tk.Button(self.master, text="Open Raw Logs", command=self.open_logs_window, width=20, height=2)
        self.open_logs_button.pack(pady=5)

        self.open_decoded_button = tk.Button(self.master, text="Open Decoded NetFlow", command=self.open_decoded_window, width=20, height=2)
        self.open_decoded_button.pack(pady=5)

    def start_listener(self):
        if not self.listener or not self.listener.is_alive():
            self.listener = NetFlowListener(NETFLOW_COLLECTOR_IP, NETFLOW_COLLECTOR_PORT, self.raw_queue, self.decoded_queue)
            self.listener.start()
            self.status_label.config(text=f"Listening on {NETFLOW_COLLECTOR_IP}:{NETFLOW_COLLECTOR_PORT}", fg="green")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
        else:
            messagebox.showinfo("Info", "Listener is already running.")

    def stop_listener(self):
        if self.listener and self.listener.is_alive():
            self.listener.stop()
            self.listener.join(timeout=2) # Wait for thread to finish
            self.status_label.config(text="Listener Stopped", fg="red")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
        else:
            messagebox.showinfo("Info", "Listener is not running.")

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit the application?"):
            self.quit_application()

    def quit_application(self):
        """Gracefully shuts down the entire application."""
        self.stop_listener()
        # Close child windows if they are open
        if self.logs_window and self.logs_window.winfo_exists():
            self.logs_window.destroy()
        if self.decoded_window and self.decoded_window.winfo_exists():
            self.decoded_window.destroy() # This will now call the overridden destroy and close CSV writer
        self.master.destroy()
        sys.exit(0) # Ensure the process exits completely

    def check_queues(self):
        # Process raw packets
        while not self.raw_queue.empty():
            data, addr, timestamp = self.raw_queue.get()
            if self.logs_window and self.logs_window.winfo_exists():
                self.logs_window.update_logs(data, addr, timestamp)
        
        # Process decoded flows
        while not self.decoded_queue.empty():
            decoded_info = self.decoded_queue.get()
            if self.decoded_window and self.decoded_window.winfo_exists():
                self.decoded_window.update_decoded_flows(decoded_info)

        self.master.after(100, self.check_queues) # Check again after 100ms

    def open_logs_window(self):
        if self.logs_window is None or not self.logs_window.winfo_exists():
            self.logs_window = LogsWindow(self.master, self.quit_application)
        self.logs_window.lift() # Bring to front

    def open_decoded_window(self):
        if self.decoded_window is None or not self.decoded_window.winfo_exists():
            self.decoded_window = DecodedNetFlowWindow(self.master, self.quit_application)
        self.decoded_window.lift() # Bring to front


class LogsWindow(tk.Toplevel):
    def __init__(self, master, quit_callback):
        super().__init__(master)
        self.title("Raw NetFlow Logs")
        self.geometry("700x500")
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.quit_callback = quit_callback

        self.log_text = tk.Text(self, wrap="word", state="disabled", font=("Courier New", 10))
        self.log_text.pack(expand=True, fill="both", padx=10, pady=10)

        self.scrollbar = tk.Scrollbar(self.log_text, command=self.log_text.yview)
        self.log_text.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y")

        quit_button = tk.Button(self, text="Quit", command=self.quit_callback, fg="black", height=2)
        quit_button.pack(pady=5)

    def update_logs(self, data, addr, timestamp):
        self.log_text.config(state="normal")
        if isinstance(data, bytes):
            log_entry = f"--- Packet from {addr[0]}:{addr[1]} at {timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')} ---\n"
            log_entry += data.hex() + "\n\n"
        else: # For error messages from listener
            log_entry = f"--- Listener Message at {timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')} ---\n"
            log_entry += data.decode('utf-8') + "\n\n"
        self.log_text.insert("end", log_entry)
        self.log_text.see("end") # Scroll to bottom
        self.log_text.config(state="disabled")


class DecodedNetFlowWindow(tk.Toplevel):
    def __init__(self, master, quit_callback):
        super().__init__(master)
        self.title("Decoded NetFlow")
        self.geometry("1700x650") # Wider for new columns and button
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.quit_callback = quit_callback

        # Define columns dynamically, including new ICMP fields
        self.columns = [
            "Timestamp", "Source IP", "Destination IP", "Next Hop", "Interface Name",
            "DSCP", "Protocol", "Bytes", "Packets", "Source Port", "Destination Port",
            "ICMP Type", "ICMP Code", "ICMP Description" # New columns
        ]
        self.tree = ttk.Treeview(self, columns=self.columns, show="headings")
        
        for col in self.columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120, anchor="w") # Default width

        # Adjust specific column widths
        self.tree.column("Timestamp", width=180)
        self.tree.column("Source IP", width=120)
        self.tree.column("Destination IP", width=120)
        self.tree.column("Next Hop", width=120)
        self.tree.column("Interface Name", width=120)
        self.tree.column("DSCP", width=80)
        self.tree.column("Protocol", width=100)
        self.tree.column("Bytes", width=100)
        self.tree.column("Packets", width=100)
        self.tree.column("Source Port", width=100)
        self.tree.column("Destination Port", width=100)
        self.tree.column("ICMP Type", width=120) # New
        self.tree.column("ICMP Code", width=100) # New
        self.tree.column("ICMP Description", width=150) # New

        self.tree.pack(expand=True, fill="both", padx=10, pady=5)

        # Add scrollbars
        vsb = ttk.Scrollbar(self.tree, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(self.tree, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")

        # Frame for buttons
        button_frame = tk.Frame(self)
        button_frame.pack(pady=5)

        self.cut_and_save_button = tk.Button(button_frame, text="Cut and Save CSV", command=self.cut_and_save_flows, fg="blue", height=2)
        self.cut_and_save_button.pack(side="left", padx=10)

        # New button for clearing displayed entries
        self.clear_display_button = tk.Button(button_frame, text="Clear Displayed Entries", command=self.clear_displayed_entries, fg="green", height=2)
        self.clear_display_button.pack(side="left", padx=10)

        quit_button = tk.Button(button_frame, text="Quit Application", command=self.quit_callback, fg="red", height=2)
        quit_button.pack(side="right", padx=10)

        # Initialize CSV writer, passing the new message_callback and quit_callback
        self.csv_writer = NetFlowCSVWriter(
            self.columns, 
            max_entries_per_file=CSV_MAX_ENTRIES_PER_FILE, 
            message_callback=self.show_auto_closing_message, # Pass the new callback here
            quit_app_callback=self.quit_callback # Pass the application-wide quit callback
        )

    def show_auto_closing_message(self, title, message, quit_app_callback, duration_ms=AUTO_CLOSE_MESSAGE_DURATION_MS):
        """Displays a non-blocking, auto-closing message box with a quit button."""
        msg_box = tk.Toplevel(self)
        msg_box.title(title)
        msg_box.geometry("400x150") # Adjusted size to accommodate the button
        msg_box.transient(self) # Make it appear on top of the parent window
        msg_box.grab_set() # Make it modal to its parent, but not blocking the mainloop
        msg_box.resizable(False, False)

        label = tk.Label(msg_box, text=message, wraplength=380, justify="center", font=("Arial", 10))
        label.pack(expand=True, fill="both", padx=10, pady=10)

        # Add the Quit Application button to the message box
        quit_btn = tk.Button(msg_box, text="Quit Application", command=lambda: [msg_box.destroy(), quit_app_callback()], fg="red")
        quit_btn.pack(pady=5)

        # Center the message box relative to its parent
        self.update_idletasks() # Ensure parent window's geometry is updated
        parent_x = self.winfo_x()
        parent_y = self.winfo_y()
        parent_width = self.winfo_width()
        parent_height = self.winfo_height()

        msg_box_width = msg_box.winfo_reqwidth()
        msg_box_height = msg_box.winfo_reqheight()

        x = parent_x + (parent_width // 2) - (msg_box_width // 2)
        y = parent_y + (parent_height // 2) - (msg_box_height // 2)
        msg_box.geometry(f"+{x}+{y}")

        msg_box.after(duration_ms, msg_box.destroy) # Auto-close after duration

    def update_decoded_flows(self, decoded_info):
        timestamp = decoded_info["timestamp"].strftime('%Y-%m-%d %H:%M:%S.%f')

        for flow_record in decoded_info["flows"]:
            # Extract values for the defined columns, providing defaults if not present
            src_ip = flow_record.get("IPV4_SRC_ADDR", "N/A")
            dst_ip = flow_record.get("IPV4_DST_ADDR", "N/A")
            next_hop = flow_record.get("IPV4_NEXT_HOP", "N/A")
            if_name = flow_record.get("IF_NAME", "N/A")
            
            dscp_full = flow_record.get("SRC_TOS", "N/A")
            dscp = dscp_full.split(': ')[1] if dscp_full.startswith("DSCP: ") else dscp_full

            protocol = flow_record.get("PROTOCOL", "N/A")
            bytes_count = flow_record.get("IN_BYTES", "N/A")
            packets_count = flow_record.get("IN_PKTS", "N/A")
            src_port = flow_record.get("SRC_PORT", "N/A")
            dst_port = flow_record.get("DST_PORT", "N/A")

            # NEW: ICMP Type and Code extraction
            # Get from flow_record first, will be "N/A" if not present
            icmp_type = flow_record.get("ICMP_TYPE", "N/A")
            icmp_code = flow_record.get("ICMP_CODE", "N/A")

            icmp_description = "N/A" # Default description

            # Construct a description if we have at least an ICMP type or code
            if icmp_type != "N/A" or icmp_code != "N/A":
                if icmp_type == "Echo Request" and icmp_code == "0":
                    icmp_description = "Echo Request (Ping)"
                elif icmp_type == "Echo Reply" and icmp_code == "0":
                    icmp_description = "Echo Reply (Ping)"
                elif icmp_type != "N/A" and icmp_code != "N/A":
                    icmp_description = f"{icmp_type} (Code: {icmp_code})"
                elif icmp_type != "N/A": # Only type is known
                    icmp_description = icmp_type
                elif icmp_code != "N/A": # Only code is known
                    icmp_description = f"Code: {icmp_code}"
                else:
                    icmp_description = "Other ICMP" # Fallback if both are present but don't match specific cases


            values_for_display = (
                timestamp, src_ip, dst_ip, next_hop, if_name, dscp, protocol,
                bytes_count, packets_count, src_port, dst_port,
                icmp_type, icmp_code, icmp_description # New fields
            )
            
            # Write to CSV
            self.csv_writer.write_flow(values_for_display)

            # Insert into Treeview at the beginning
            self.tree.insert("", 0, values=values_for_display)
            
            # Limit number of rows in GUI to prevent excessive memory use
            if len(self.tree.get_children()) > 1000: # Keep max 1000 rows in display
                # Remove the oldest row, which is now at the end
                self.tree.delete(self.tree.get_children()[-1])

    def clear_displayed_entries(self):
        """Clears all entries from the Treeview display without affecting CSV writing."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        print("Displayed NetFlow entries cleared.")

    def cut_and_save_flows(self):
        """Handler for the 'Cut and Save CSV' button."""
        self.csv_writer.cut_and_save()

    def destroy(self):
        """Overrides Toplevel destroy to ensure CSV writer is closed."""
        self.csv_writer.close()
        super().destroy()


if __name__ == "__main__":
    # --- Self-backgrounding logic ---
    if "--detached" not in sys.argv:
        script_path = os.path.abspath(__file__)
        command = [sys.executable, script_path, "--detached"]

        if sys.platform == "win32":
            creationflags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            subprocess.Popen(command, creationflags=creationflags, close_fds=True)
        else: # Unix-like systems (Linux, macOS)
            with open(os.devnull, 'w') as devnull:
                subprocess.Popen(command, stdout=devnull, stderr=devnull,
                                 start_new_session=True, close_fds=True)
        
        print("NetFlow Receiver GUI launched in the background.")
        sys.exit(0) # Ensure the process exits completely

    # If we reach here, it means this process was launched with --detached
    # and should proceed with normal GUI initialization.
    root = tk.Tk()
    app = NetFlowGUI(root)
    root.mainloop()
