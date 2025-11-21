import tkinter as tk
from tkinter import ttk, messagebox
import socket
import struct
import time
import random
import sys
import subprocess
import os

# --- NetFlow v9 Configuration ---
NETFLOW_COLLECTOR_IP = "127.0.0.1"
NETFLOW_COLLECTOR_PORT = 2055  # Common NetFlow UDP port
TEMPLATE_ID = 257  # Template IDs must be > 255
IFNAME_MAX_LEN = 16  # Max length for interface name string in bytes

# List of IP Protocol numbers that typically do NOT use source/destination ports
PORTLESS_PROTOCOLS = {1, 2, 47, 50, 51, 58, 88, 89}  # ICMP, IGMP, GRE, ESP, AH, ICMPv6, EIGRP, OSPF

# Base NetFlow fields that are always included
BASE_NETFLOW_FIELDS = [
    (82, IFNAME_MAX_LEN, "IF_NAME"),
    (5, 1, "SRC_TOS"),
    (1, 4, "IN_BYTES"),
    (2, 4, "IN_PKTS"),
    (15, 4, "IPV4_NEXT_HOP"),
    (8, 4, "IPV4_SRC_ADDR"),
    (12, 4, "IPV4_DST_ADDR"),
    (4, 1, "PROTOCOL"),
]

# CORRECTED: ICMP Type and Code field types and lengths
# These must match the IE_TYPES defined in your NetFlow collector
ICMP_TYPE_FIELD = (176, 1, "ICMP_TYPE")  # Changed from 34 to 176
ICMP_CODE_FIELD = (177, 1, "ICMP_CODE")  # Changed from 35 to 177

# Valid ICMP types and codes for echo request, echo reply, and time exceeded
VALID_ICMP_ENTRIES = [
    {"type": 0, "code": 0},   # Echo Reply
    {"type": 8, "code": 0},   # Echo Request
    {"type": 11, "code": 0},  # Time Exceeded - Time to Live exceeded in Transit
]

def send_netflow_v9_raw_packet(ifname, force_icmp=False):
    try:
        # Determine protocol
        if force_icmp:
            protocol_val = 1  # ICMP
        else:
            protocol_val = random.randint(0, 255)

        dscp_val = random.randint(0, 63)
        bytes_val = random.randint(100, 1000000)
        packets_val = random.randint(1, 1000)

        include_ports = protocol_val not in PORTLESS_PROTOCOLS

        src_port_val = 0
        dst_port_val = 0
        if include_ports:
            src_port_val = random.randint(0, 65535)
            dst_port_val = random.randint(0, 65535)

        # For ICMP protocol, generate valid ICMP type and code for realistic entries
        icmp_type_val = None
        icmp_code_val = None
        if protocol_val == 1:
            icmp_entry = random.choice(VALID_ICMP_ENTRIES)
            icmp_type_val = icmp_entry["type"]
            icmp_code_val = icmp_entry["code"]

        current_netflow_fields_definition = list(BASE_NETFLOW_FIELDS)
        if include_ports:
            current_netflow_fields_definition.append((7, 2, "SRC_PORT"))
            current_netflow_fields_definition.append((11, 2, "DST_PORT"))
        if protocol_val == 1:
            current_netflow_fields_definition.append(ICMP_TYPE_FIELD)
            current_netflow_fields_definition.append(ICMP_CODE_FIELD)

        sys_uptime_ms = 10000
        unix_secs = int(time.time())
        sequence_number = 1
        source_id = 12345

        netflow_header = struct.pack(
            "!HHIIII",
            9,
            2,
            sys_uptime_ms,
            unix_secs,
            sequence_number,
            source_id
        )

        template_fields_packed = b""
        for field_type, field_length, _ in current_netflow_fields_definition:
            template_fields_packed += struct.pack("!HH", field_type, field_length)

        template_record_header = struct.pack(
            "!HH",
            TEMPLATE_ID,
            len(current_netflow_fields_definition)
        )

        template_record = template_record_header + template_fields_packed

        template_flowset_length = 4 + len(template_record)
        template_flowset_header = struct.pack("!HH", 0, template_flowset_length)
        template_flowset = template_flowset_header + template_record

        src_ip_octets = [random.randint(1, 254) for _ in range(4)]
        src_ip = ".".join(map(str, src_ip_octets))
        next_hop_ip = "{}.{}.{}.254".format(src_ip_octets[0], src_ip_octets[1], src_ip_octets[2])
        dst_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))

        padded_ifname = ifname.encode('utf-8')[:IFNAME_MAX_LEN].ljust(IFNAME_MAX_LEN, b'\0')
        dscp_byte = struct.pack("!B", dscp_val << 2)
        bytes_packed = struct.pack("!I", bytes_val)
        packets_packed = struct.pack("!I", packets_val)
        next_hop_packed = socket.inet_aton(next_hop_ip)
        src_ip_packed = socket.inet_aton(src_ip)
        dst_ip_packed = socket.inet_aton(dst_ip)
        protocol_byte = struct.pack("!B", protocol_val)

        data_record = (
            padded_ifname + dscp_byte + bytes_packed + packets_packed +
            next_hop_packed + src_ip_packed + dst_ip_packed + protocol_byte
        )

        if include_ports:
            src_port_packed = struct.pack("!H", src_port_val)
            dst_port_packed = struct.pack("!H", dst_port_val)
            data_record += src_port_packed + dst_port_packed

        if protocol_val == 1:
            icmp_type_packed = struct.pack("!B", icmp_type_val)
            icmp_code_packed = struct.pack("!B", icmp_code_val)
            data_record += icmp_type_packed + icmp_code_packed

        data_flowset_length = 4 + len(data_record)
        data_flowset_header = struct.pack("!HH", TEMPLATE_ID, data_flowset_length)
        data_flowset = data_flowset_header + data_record

        netflow_packet_payload = netflow_header + template_flowset + data_flowset

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(netflow_packet_payload, (NETFLOW_COLLECTOR_IP, NETFLOW_COLLECTOR_PORT))
        sock.close()

        record = {
            "IF_NAME": ifname,
            "SRC_TOS": dscp_val,
            "IN_BYTES": bytes_val,
            "IN_PKTS": packets_val,
            "IPV4_NEXT_HOP": next_hop_ip,
            "IPV4_SRC_ADDR": src_ip,
            "IPV4_DST_ADDR": dst_ip,
            "PROTOCOL": protocol_val,
            "SRC_PORT": src_port_val if include_ports else "N/A",
            "DST_PORT": dst_port_val if include_ports else "N/A",
            "ICMP_TYPE": icmp_type_val if protocol_val == 1 else "N/A",
            "ICMP_CODE": icmp_code_val if protocol_val == 1 else "N/A"
        }
        return True, record

    except Exception as e:
        return False, str(e)

def quit_application():
    if messagebox.askokcancel("Quit Application", "Do you want to quit the NetFlow Sender application?"):
        sys.exit(0)

class NetFlowSenderApp:
    def __init__(self, master):
        self.master = master
        master.title("NetFlow v9 Raw Sender")
        master.geometry("900x450")
        master.protocol("WM_DELETE_WINDOW", quit_application)

        self.notebook = ttk.Notebook(master)
        self.notebook.pack(fill="both", expand=True)

        self.tab1 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab1, text="Send NetFlow")

        self.tab2 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab2, text="Sent NetFlow Entries")

        # Tab 1 widgets
        ttk.Label(self.tab1, text="Interface Name (ifname):").pack(pady=10)
        self.entry_ifname = ttk.Entry(self.tab1, width=30)
        self.entry_ifname.insert(0, "eth0")
        self.entry_ifname.pack(pady=5)

        self.send_button = ttk.Button(self.tab1, text="Send NetFlow Entry", command=self.start_sending)
        self.send_button.pack(pady=10)

        quit_button_tab1 = ttk.Button(self.tab1, text="Quit", command=quit_application)
        quit_button_tab1.pack(pady=10)

        # Tab 2 widgets
        columns = ["IF_NAME", "SRC_TOS", "IN_BYTES", "IN_PKTS", "IPV4_NEXT_HOP",
                   "IPV4_SRC_ADDR", "IPV4_DST_ADDR", "PROTOCOL", "SRC_PORT", "DST_PORT",
                   "ICMP_TYPE", "ICMP_CODE"]
        self.tree = ttk.Treeview(self.tab2, columns=columns, show="headings", height=15)
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=80, anchor="center")
        self.tree.pack(side="left", fill="both", expand=True)

        scrollbar_y = ttk.Scrollbar(self.tab2, orient="vertical", command=self.tree.yview)
        scrollbar_y.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar_y.set)

        scrollbar_x = ttk.Scrollbar(self.tab2, orient="horizontal", command=self.tree.xview)
        scrollbar_x.pack(side="bottom", fill="x")
        self.tree.configure(xscrollcommand=scrollbar_x.set)

        quit_button_tab2 = ttk.Button(self.tab2, text="Quit", command=quit_application)
        quit_button_tab2.pack(pady=10)

        self.sending = False
        self.send_interval_ms = 200  # 5 flows per second
        self.flow_count = 0  # To track flows sent for ICMP forcing

    def start_sending(self):
        ifname = self.entry_ifname.get().strip()
        if not ifname:
            messagebox.showerror("Input Error", "Interface Name must be filled.")
            return
        self.ifname = ifname
        self.notebook.select(self.tab2)
        if not self.sending:
            self.sending = True
            self.flow_count = 0
            self.send_netflow_loop()

    def send_netflow_loop(self):
        if not self.sending:
            return
        self.flow_count += 1
        # Force ICMP on every 10th flow
        force_icmp = (self.flow_count % 10 == 0)
        success, result = send_netflow_v9_raw_packet(self.ifname, force_icmp=force_icmp)
        if success:
            values = [result.get(col, "") for col in self.tree["columns"]]
            self.tree.insert("", 0, values=values)
        else:
            messagebox.showerror("Send Error", "Failed to send NetFlow packet: " + result)
            self.sending = False
            return
        self.master.after(self.send_interval_ms, self.send_netflow_loop)

    def show_about_window(self):
        about_text = (
            "NetFlow will be sent to {}:{}"
            "You need a NetFlow collector listening on this address and port to see the data."
            "This version manually constructs the raw NetFlow v9 packet."
            "Next Hop IP is derived from Source IP."
            "DSCP, Protocol, Bytes, Packets, and Ports are randomly generated."
            "Ports are omitted for protocols that do not use them (e.g., ICMP, OSPF)."
            "At least 1 ICMP flow is generated per 10 flows, with random valid ICMP Type and Code for echo request, echo reply, or time exceeded."
        ).format(NETFLOW_COLLECTOR_IP, NETFLOW_COLLECTOR_PORT)
        messagebox.showinfo("About NetFlow Sender", about_text)

if __name__ == "__main__":
    if "--detached" not in sys.argv:
        script_path = os.path.abspath(__file__)
        command = [sys.executable, script_path, "--detached"]

        if sys.platform == "win32":
            creationflags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            subprocess.Popen(command, creationflags=creationflags, close_fds=True)
        else:
            with open(os.devnull, 'w') as devnull:
                subprocess.Popen(command, stdout=devnull, stderr=devnull,
                                 start_new_session=True, close_fds=True)

        print("NetFlow Sender GUI launched in the background.")
        sys.exit(0)

    root = tk.Tk()
    app = NetFlowSenderApp(root)
    root.mainloop()
