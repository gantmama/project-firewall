import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

# === Global Variables ===
firewall_rules = []
log_file = "firewall_log.txt"


# === Packet Rule Matching ===
def check_rules(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OTHER"
        port = packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else None)

        for rule in firewall_rules:
            if rule['ip'] and rule['ip'] not in (ip_src, ip_dst):
                continue
            if rule['port'] and rule['port'] != port:
                continue
            if rule['proto'] and rule['proto'] != proto:
                continue
            return rule['action']
    return "ALLOW"


# === Logging Function ===
def log_packet(packet, reason="BLOCKED"):
    with open(log_file, "a") as f:
        log = f"{datetime.now()} | {packet.summary()} | {reason}\n"
        f.write(log)
        gui_log(log)


# === GUI Log Viewer ===
def gui_log(msg):
    log_display.configure(state='normal')
    log_display.insert(tk.END, msg)
    log_display.see(tk.END)
    log_display.configure(state='disabled')


# === Scapy Packet Sniffing Handler ===
def packet_handler(packet):
    action = check_rules(packet)
    if action == "BLOCK":
        log_packet(packet)
    else:
        log_msg = f"{datetime.now()} | {packet.summary()} | ALLOWED\n"
        gui_log(log_msg)


# === Threaded Sniff Function ===
def start_sniffing():
    sniff(filter="ip", prn=packet_handler, store=0)


# === Rule Addition ===
def add_rule_gui():
    ip = ip_entry.get().strip()
    port = port_entry.get().strip()
    proto = proto_entry.get().strip().upper()
    action = action_var.get().upper()

    try:
        port = int(port) if port else None
    except ValueError:
        messagebox.showerror("Error", "Port must be an integer!")
        return

    rule = {'ip': ip if ip else None, 'port': port, 'proto': proto if proto else None, 'action': action}
    firewall_rules.append(rule)
    rule_list.insert(tk.END, f"{action} - IP: {ip or 'ANY'}, Port: {port or 'ANY'}, Proto: {proto or 'ANY'}")


# === GUI Setup ===
app = tk.Tk()
app.title("Python Personal Firewall")
app.geometry("700x500")

# Rule Frame
tk.Label(app, text="IP:").grid(row=0, column=0)
tk.Label(app, text="Port:").grid(row=1, column=0)
tk.Label(app, text="Protocol:").grid(row=2, column=0)

ip_entry = tk.Entry(app)
port_entry = tk.Entry(app)
proto_entry = tk.Entry(app)

ip_entry.grid(row=0, column=1)
port_entry.grid(row=1, column=1)
proto_entry.grid(row=2, column=1)

action_var = tk.StringVar(value="BLOCK")
tk.Radiobutton(app, text="Block", variable=action_var, value="BLOCK").grid(row=3, column=0)
tk.Radiobutton(app, text="Allow", variable=action_var, value="ALLOW").grid(row=3, column=1)

tk.Button(app, text="Add Rule", command=add_rule_gui).grid(row=4, column=0, columnspan=2)

# Rule Listbox
tk.Label(app, text="Active Rules:").grid(row=5, column=0, sticky="w")
rule_list = tk.Listbox(app, height=5, width=80)
rule_list.grid(row=6, column=0, columnspan=3)

# Log Display
tk.Label(app, text="Packet Logs:").grid(row=7, column=0, sticky="w")
log_display = scrolledtext.ScrolledText(app, width=85, height=10, state='disabled')
log_display.grid(row=8, column=0, columnspan=3)

# Start Sniffing in Background
sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
sniffer_thread.start()

app.mainloop()
