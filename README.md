# Advanced Network Monitor Pro

A **Python-based GUI network monitoring tool** built with **Tkinter** and **psutil**. It provides real-time visibility into active TCP/UDP connections, associated processes, data transfer speeds, and allows basic process control.

---

## ✨ Features

* 🔍 **Live Network Monitoring**

  * Displays all active TCP & UDP connections
  * Shows local address, remote address (with domain resolution), connection state, PID, and process name

* 🌐 **Fast DNS Resolution**

  * Resolves remote IPs to domains asynchronously
  * Uses caching to keep the UI responsive

* 🚀 **Per‑Process Speed Tracking**

  * Real-time **download** and **upload** speed calculation
  * Highlights heavy bandwidth usage automatically

* 🆕 **New Connection Detection**

  * Newly seen processes are visually highlighted

* ❄ **Freeze / Resume View**

  * Pause updates to inspect connections safely

* 🔎 **Instant Search & Filter**

  * Filter by protocol, IP, domain, PID, process name, or state

* 🛑 **Terminate Processes**

  * Kill selected processes directly from the UI

* 💾 **Export to CSV**

  * Save the currently visible table data to a CSV file

* 📋 **Quick Copy**

  * Double‑click any cell to copy its value to clipboard

---

## 🖥️ Screens Overview

| Column  | Description                                  |
| ------- | -------------------------------------------- |
| PROTO   | TCP or UDP                                   |
| LOCAL   | Local IP and port                            |
| REMOTE  | Remote IP or resolved domain                 |
| STATE   | Connection state (ESTABLISHED, LISTEN, etc.) |
| PID     | Process ID                                   |
| PROCESS | Process name                                 |
| DOWN    | Download speed                               |
| UP      | Upload speed                                 |

---

## 🧰 Requirements

* Python **3.8+**
* Windows / Linux / macOS (Admin/root may be required)

### Required Libraries

```bash
pip install psutil
```

(Tkinter is included with standard Python installations)

---

## ▶️ How to Run

```bash
python network_monitor.py
```

> ⚠️ **Note:** Some system processes and connections may require **administrator/root privileges** to display or terminate.

---

## ⌨️ Controls & Shortcuts

* **Double‑click** → Copy cell value
* **Freeze View** → Pause live updates
* **Resume** → Continue monitoring
* **Search Bar** → Filter connections instantly
* **Terminate Process** → Kill selected PID

---

## 📁 CSV Export

* Exports only **currently visible (filtered)** rows
* File format:

```csv
PROTO,LOCAL,REMOTE,STATE,PID,PROCESS,DOWN,UP
```

* Filename example:

```
network_log_1700000000.csv
```

---

## 🔐 Permissions & Safety

* Killing system or protected processes may fail
* Network statistics are **best‑effort estimates**, not packet‑level analysis
* Tool is intended for **monitoring & diagnostics**, not intrusion

---

## 🛠️ Known Limitations

* Per‑process I/O is **disk + network combined** (OS limitation)
* DNS resolution depends on system resolver
* UDP connections may show limited state information

---

## 📌 Future Enhancements (Ideas)

* Firewall rule creation
* Process grouping by application
* Tray mode / background monitoring
* Packet‑level capture (via WinPcap / libpcap)
* Dark mode UI

---

## 📜 License

This project is released for **educational and personal use**.

Use responsibly.

---

## 👤 Author

Developed by **Kumar** 🚀

Feel free to extend or customize this tool for your own network diagnostics.
