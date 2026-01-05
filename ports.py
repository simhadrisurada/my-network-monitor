import psutil
import socket
import tkinter as tk
from tkinter import ttk, messagebox
import time
import threading
import csv # For exporting

REFRESH_INTERVAL = 2000  
last_io_state = {} 
known_pids = set() 
dns_cache = {} 
dns_queue = set()
search_timer = None
is_frozen = False 

def format_speed(bytes_per_sec):
    if bytes_per_sec < 1024: return f"{bytes_per_sec:.1f} B/s"
    elif bytes_per_sec < 1024**2: return f"{bytes_per_sec/1024:.1f} KB/s"
    else: return f"{bytes_per_sec/1024**2:.1f} MB/s"

# --- NEW FEATURE: EXPORT ---
def export_to_csv():
    """Saves the current visible table data to a CSV file."""
    try:
        filename = f"network_log_{int(time.time())}.csv"
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["PROTO", "LOCAL", "REMOTE", "STATE", "PID", "PROCESS", "DOWN", "UP"])
            for row_id in tree.get_children():
                writer.writerow(tree.item(row_id)['values'])
        messagebox.showinfo("Export Success", f"Saved as {filename}")
    except Exception as e:
        messagebox.showerror("Export Error", str(e))

def copy_cell_value(event):
    region = tree.identify_region(event.x, event.y)
    if region == "cell":
        column = tree.identify_column(event.x)
        item_id = tree.identify_row(event.y)
        column_index = int(column[1:]) - 1 
        selected_value = str(tree.item(item_id)['values'][column_index])
        root.clipboard_clear()
        root.clipboard_append(selected_value)
        status_label.config(text=f"📋 COPIED: {selected_value}", foreground="#0078d7")
        root.after(2000, lambda: status_label.config(text="System Live", foreground="green"))

def toggle_freeze():
    global is_frozen
    is_frozen = not is_frozen
    freeze_btn.config(text="▶ RESUME" if is_frozen else "⏸ FREEZE VIEW", 
                      bg="#ff9900" if is_frozen else "#f0f0f0")

def resolve_dns_thread(ip):
    try:
        domain = socket.getfqdn(ip)
        dns_cache[ip] = domain
    except:
        dns_cache[ip] = ip
    if ip in dns_queue: dns_queue.remove(ip)

def get_domain_fast(ip):
    if ip in ["-", "0.0.0.0", "127.0.0.1", "*", "::"]: return ip
    if ip in dns_cache: return dns_cache[ip]
    if ip not in dns_queue:
        dns_queue.add(ip)
        threading.Thread(target=resolve_dns_thread, args=(ip,), daemon=True).start()
    return ip

def stop_selected_process():
    selected_item = tree.selection()
    if not selected_item: return
    val = tree.item(selected_item)['values']
    pid, name = val[4], val[5]
    if messagebox.askyesno("Kill Process", f"Stop {name} (PID: {pid})?"):
        try:
            psutil.Process(int(pid)).terminate()
            load_connections()
        except Exception as e:
            messagebox.showerror("Error", str(e))

def on_search_change(*args):
    global search_timer
    if search_timer: root.after_cancel(search_timer)
    search_timer = root.after(300, load_connections)

def load_connections():
    global last_io_state, known_pids, is_frozen
    if is_frozen: return 
    filter_text = filter_var.get().lower()
    current_time = time.time()
    selected_pid = None
    selection = tree.selection()
    if selection: selected_pid = tree.item(selection[0])['values'][4]

    try:
        connections = psutil.net_connections(kind='inet')
    except: return

    for row in tree.get_children(): tree.delete(row)

    for conn in connections:
        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
        raw_r_ip = conn.raddr.ip if conn.raddr else "-"
        domain = get_domain_fast(raw_r_ip)
        r_port = conn.raddr.port if conn.raddr else ""
        raddr = f"{domain}:{r_port}" if r_port else domain
        state = conn.status if conn.status else "NONE"
        pid = conn.pid if conn.pid else "-"
        process_name = "?"
        dspeed, uspeed = 0, 0

        if conn.pid:
            try:
                p = psutil.Process(conn.pid)
                process_name = p.name()
                io = p.io_counters()
                if conn.pid in last_io_state:
                    prev_r, prev_w, prev_t = last_io_state[conn.pid]
                    diff = current_time - prev_t
                    if diff > 0:
                        dspeed = (io.read_bytes - prev_r) / diff
                        uspeed = (io.write_bytes - prev_w) / diff
                last_io_state[conn.pid] = (io.read_bytes, io.write_bytes, current_time)
            except: process_name = "System/Protected"

        row_data = (proto, laddr, raddr, state, pid, process_name, format_speed(dspeed), format_speed(uspeed))
        if not filter_text or any(filter_text in str(x).lower() for x in row_data):
            tags = []
            if dspeed > 1024*1024: tags.append("heavy")
            elif pid != "-" and pid not in known_pids: tags.append("new")
            new_item = tree.insert("", "end", values=row_data, tags=tags)
            if str(pid) == str(selected_pid): tree.selection_set(new_item)
        if pid != "-": known_pids.add(pid)

    tree.tag_configure("heavy", background="#ffcccc")
    tree.tag_configure("new", background="#ccffcc")

# ---------------- GUI ---------------- #
root = tk.Tk()
root.title("Advanced Network Monitor Pro")
root.geometry("1200x750")

# Control Panel
ctrl_frame = ttk.Frame(root)
ctrl_frame.pack(fill=tk.X, padx=10, pady=5)

status_label = ttk.Label(ctrl_frame, text="System Live", foreground="green", font=("Arial", 10, "bold"))
status_label.pack(side=tk.LEFT, padx=10)

freeze_btn = tk.Button(ctrl_frame, text="⏸ FREEZE VIEW", command=toggle_freeze)
freeze_btn.pack(side=tk.RIGHT, padx=5)

tk.Button(ctrl_frame, text="💾 EXPORT CSV", command=export_to_csv, bg="#f0f0f0").pack(side=tk.RIGHT, padx=5)

# Filter
filter_var = tk.StringVar()
filter_var.trace_add("write", on_search_change)
ttk.Entry(root, textvariable=filter_var).pack(fill=tk.X, padx=10, pady=5)

# Table
cols = ("PROTO", "LOCAL", "REMOTE (Domain)", "STATE", "PID", "PROCESS", "DOWN", "UP")
tree = ttk.Treeview(root, columns=cols, show="headings", selectmode="browse")
for c in cols:
    tree.heading(c, text=c)
    tree.column(c, width=140, anchor="center")
tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
tree.bind("<Double-1>", copy_cell_value)

# Bottom
tk.Button(root, text="🛑 TERMINATE PROCESS", command=stop_selected_process, 
          bg="#cc0000", fg="white", font=("Arial", 11, "bold"), pady=10).pack(fill=tk.X, padx=10, pady=10)

load_connections()
def auto_refresh():
    load_connections()
    root.after(REFRESH_INTERVAL, auto_refresh)
auto_refresh()
root.mainloop()