# 🕵️‍♂️ Simple Packet Sniffer with Tkinter GUI

A beginner-friendly **Python-based packet sniffer** with a **graphical interface built using Tkinter**. It captures live network packets using `Scapy`, displays real-time traffic, protocol statistics, and saves the output to a `.pcap` file.

---

## 🧰 Features

- 🖥️ **Tkinter-based GUI** for easy interaction
- 🔍 Real-time packet sniffing (TCP, UDP, ICMP)
- 📊 Live display of:
  - Source & destination IP addresses
  - Protocol type
  - Payload content (first 80 characters if present)
- 🧮 Protocol count (TCP/UDP/ICMP)
- 💾 Save captured packets to `captured.pcap`
- 🧵 Runs sniffing in a **background thread** so GUI stays responsive

---

## ✅ Requirements

- Python 3.6+
- `scapy`
- (Optional) Admin/root privileges for full access to network interfaces

---

## 🛠 Installation

```bash
pip install scapy
