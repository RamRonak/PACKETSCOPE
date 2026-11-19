# PACKETSCOPE &mdash; User Manual & Demonstration Guide

Welcome to **PACKETSCOPE (Network Traffic Analyzer & Protocol Inspector)**. This guide provides step-by-step instructions for running the application, performing live captures, analyzing PCAPs, inspecting packet headers, generating reports, and utilizing the educational module.

---

## 1. Quick Start

### 1.1 Prerequisites
- Python 3.10+ installed
- Virtual environment (recommended)
- Web browser (Chrome, Firefox, Edge, Safari)

### 1.2 Running the Application
From the project root directory, launch PacketScope:
```bash
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 2. Navigating the Interface

### 2.1 Home Page (`/`)
- **System Capabilities Banner:** Displays current host capture environment (Npcap status, interface count).
- **Core Action Buttons:** Direct shortcuts to "Start Monitoring", "Analyze PCAP", and "Learn Networking".
- **Bundled Sample Captures:** 1-click launchers for exploring TCP handshakes, DNS queries, HTTP traffic, and ping flows.

### 2.2 Main Dashboard (`/dashboard`)
- **Interface Selection:** Choose an active network interface (e.g. Wi-Fi, Ethernet, Loopback) or "All Interfaces".
- **Protocol Filter:** Restrict live sniffing to TCP, UDP, ICMP, or DNS.
- **Start / Stop Capture:** Click "Start Capture" to begin capturing. The live status indicator will turn green and begin tracking elapsed time and packet rate.
- **Live Statistics Cards:** Displays total packets, TCP, UDP, ICMP, DNS, and HTTP counts.
- **Traffic Analytics Charts:**
  - Protocol breakdown doughnut chart
  - Time-series activity graph
  - Top source and destination IP bars
  - Packet size distribution histogram
- **Live Packet Stream:** Real-time table updating as packets arrive. Clicking any packet opens a quick dissection modal.

### 2.3 Packet Inspector (`/inspector`)
- **Session Selector:** Switch between different historical captures or imported PCAPs.
- **Multi-Field Filter Bar:** Filter packet rows by protocol, IP address, port number, or keyword query.
- **Layer-by-Layer Dissection Accordion:**
  - **Ethernet II:** Source and Destination MACs, EtherType.
  - **IPv4:** TTL, IP addresses, identification, fragment flags, header length.
  - **TCP:** Sequence numbers, ACKs, window size, detailed flag breakdown (`[SYN, ACK]`).
  - **UDP / ICMP / DNS:** Message types, codes, DNS query names, resolver answers.
- **Raw Hex Dump Viewer:** Monospace Wireshark-style split view showing byte offsets, hex representations, and sanitized ASCII previews.
- **Copy JSON:** Exports the complete packet dictionary to your clipboard.

### 2.4 Protocol Analysis Guide (`/protocols`)
- Comprehensive technical reference for TCP, UDP, ICMP, DNS, HTTP/HTTPS, and ARP.
- Visual ASCII header diagrams illustrating exact bit layouts.
- Breakdown of all 8 TCP control flags with hex codes and network roles.

### 2.5 PCAP File Analysis (`/pcap`)
- **Drag-and-Drop Zone:** Drag any `.pcap`, `.pcapng`, or `.cap` file directly into the browser.
- **Sample Captures:** Instant 1-click analysis of pre-bundled captures (`sample_mixed_network.pcap`, `sample_tcp_handshake.pcap`, etc.).
- **Summary Preview:** Shows packet count, volume, duration, and the first 10 recorded packets with direct buttons to launch the Dashboard or Inspector.

### 2.6 Capture History & Reports (`/history`)
- Historical log of all sessions saved in the SQLite database.
- Export options:
  - **CSV Export:** Standard tabular export of all packet headers.
  - **PDF Cybersecurity Report:** ReportLab-generated executive document with branding, charts summaries, top endpoints, and sample packet logs.
  - **PCAP Download:** Download the raw binary packet capture file.

### 2.7 "Learn Networking" Module (`/education`)
- 10 foundational cybersecurity lessons covering packets, sniffing, IP/MAC addressing, ports, TCP/UDP, ICMP, DNS, and the 7-layer OSI model.
- **Interactive Knowledge Quiz:** 5 multiple-choice questions with automated grading and detailed explanations.

---

## 3. Ethical and Safe Monitoring Policy

PacketScope is developed strictly for education and authorized network administration:
1. Only capture traffic on networks and devices you own or have explicit written permission to monitor.
2. The application includes strict built-in privacy safeguards that redact passwords, bearer tokens, and session cookies from application previews.
3. No man-in-the-middle (MITM), packet injection, or traffic manipulation tools are included.
