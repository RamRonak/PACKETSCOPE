# PACKETSCOPE
### Network Traffic Analyzer & Protocol Inspector

> **"Capture. Analyze. Understand Your Network."**

![PacketScope Logo](frontend/static/images/logo.svg)

**PACKETSCOPE** is a complete, professional, Python-based network packet capture and protocol analysis platform. Designed for cybersecurity students, network engineers, and security analysts, PacketScope provides real-time traffic monitoring, deep layer-by-layer header inspection, offline PCAP forensics, interactive Chart.js analytics, and automated PDF/CSV cybersecurity report generation.

---

## 1. Technology Stack

- **Backend:** Python 3 (3.10+), Flask 3.1, Scapy 2.8, ReportLab 5.1 (PDF Generation), Werkzeug, Standard Socket library.
- **Frontend:** HTML5, CSS3, JavaScript (Vanilla ES6+), Bootstrap 5.3 (Dark Theme), Bootstrap Icons, Chart.js 4.4.
- **Data Storage:** SQLite 3 with optimized relational schema, B-Tree indexes, and cascade deletion.
- **File Support:** Standard PCAP / PCAPNG offline capture support via Scapy `rdpcap` and `wrpcap`.
- **Operating System Support:** Windows, Linux, and macOS.

---

## 2. Key Features

### 🌐 Real-Time & Authorized Packet Capture
- Cross-platform network interface detection (Wi-Fi, Ethernet, Loopback, Virtual adapters).
- Protocol filtering: TCP, UDP, ICMP (Ping), DNS (Port 53), or all IP traffic.
- Background worker thread with queue bounds (`MAX_CAPTURE_PACKETS = 5000`) preventing memory exhaustion.
- Automatic fallback to educational live simulation and PCAP replay when native host pcap drivers (e.g. Npcap on Windows) are not installed or lack elevated permissions.

### 🔬 Deep Header Dissection & Packet Inspector
- **Ethernet Layer:** Source MAC, Destination MAC, EtherType, VLAN 802.1Q tags.
- **IPv4 / IPv6 Layer:** Source/Destination IP, Version, Header Length (IHL), Total Length, Identification, Flags (DF, MF), TTL, Protocol number, Header Checksum.
- **TCP Layer:** Source/Destination Port, Sequence Number, Acknowledgment Number, Window Size, Data Offset, Checksum, and all 8 TCP control flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWR`).
- **UDP Layer:** Source/Destination Port, Length, Checksum.
- **ICMP Layer:** Type (Echo Request, Echo Reply, Destination Unreachable, TTL Exceeded), Code, Checksum, Sequence ID.
- **DNS Layer:** Transaction ID, QR Flag, OpCode, Question Count, Answer Count, Query Name (A, AAAA, MX, CNAME), and Resolved IP Addresses.
- **ARP Layer:** Hardware Type, Protocol Type, Opcode (Request who-has / Reply is-at), Sender/Target MAC and IP.
- **HTTP Layer:** Verb methods (GET, POST), Host, User-Agent, URI path, and status codes.
- **Wireshark-Style Hex Dump:** Monospace split view showing byte offsets, hex representations, and sanitized ASCII previews.

### 📊 Interactive Traffic Analytics (Chart.js)
- **Protocol Distribution:** Doughnut chart breaking down TCP, UDP, ICMP, DNS, HTTP, and other protocols.
- **Traffic Over Time:** Smooth line chart illustrating packet arrival frequency across time bins.
- **Top Endpoints:** Horizontal bar charts of top 5 source and top 5 destination IP addresses.
- **Packet Size Histogram:** Bar chart categorizing packet sizes (<64B, 64-128B, 129-512B, 513-1024B, 1025-1518B, >1518B).

### 📁 Offline PCAP Analysis & Sample Library
- Drag-and-drop file upload with strict validation (`.pcap`, `.pcapng`, `.cap` under 50MB).
- Pre-bundled 1-click educational sample captures:
  - `sample_mixed_network.pcap` (Comprehensive capture: ARP, DNS, TCP, HTTP, UDP, ICMP)
  - `sample_tcp_handshake.pcap` (SYN, SYN-ACK, ACK, Data, FIN-ACK sequence)
  - `sample_http_web.pcap` (Cleartext HTTP request and 200 OK HTML response)
  - `sample_dns_queries.pcap` (DNS queries for google.com, packetscope.net and resolver answers)
  - `sample_icmp_ping.pcap` (Echo requests and replies with sequence numbers)

### 📄 Export & Report Generation
- **PDF Cybersecurity Report:** High-resolution ReportLab document with PacketScope branding, session metadata, protocol tables, top endpoints, and packet sample logs.
- **CSV Export:** Complete tabular export of packet records.
- **PCAP Export:** Export capture sessions to standard PCAP format compatible with Wireshark.

### 🎓 "Learn Networking" Educational Module
- 10 foundational lessons explaining: What is a packet?, Packet sniffing, IP addresses, MAC addresses, Port numbers, TCP, UDP, ICMP, DNS, and the 7-Layer OSI model.
- Visual packet structure diagrams.
- Interactive 5-question knowledge quiz with instant scoring and explanations.

---

## 3. UI/UX Design System

PacketScope features a premium cybersecurity theme:
- **Palette:** Dark navy (`#060911`, `#0b1120`, `#0f172a`) with neon blue (`#00f0ff`) and cyan (`#38bdf8`) accents.
- **Status Indicators:** Pulsing neon green (`#00e676`) for active capture, amber (`#f59e0b`) for alerts, and red (`#ef4444`) for errors.
- **Typography:** Modern clean sans-serif (`Inter`) paired with technical monospace (`JetBrains Mono`).
- **Responsive Layout:** Optimized for desktop workstations, laptops, and tablets.

---

## 4. Project Directory Structure

```
PACKETSCOPE/
├── app.py                     # Flask application entry point and factory
├── config.py                  # Global application configuration and limits
├── requirements.txt           # Python package dependencies
├── README.md                  # Main project documentation
│
├── backend/
│   ├── capture/
│   │   ├── sniffer.py         # Thread-safe live capture engine
│   │   └── interfaces.py      # Network interface detection
│   ├── analysis/
│   │   ├── packet_parser.py   # Layer-by-layer header dissection
│   │   ├── protocol_detector.py # Protocol mapping and signatures
│   │   └── statistics.py      # Traffic metrics and Chart.js aggregation
│   ├── services/
│   │   ├── capture_service.py # Orchestrator linking capture & DB
│   │   ├── pcap_service.py    # Offline PCAP upload & processing
│   │   └── export_service.py  # ReportLab PDF & CSV report generation
│   ├── routes/
│   │   ├── api.py             # REST API endpoints (/api/...)
│   │   └── views.py           # Web application template views
│   └── security/
│       └── validators.py      # Input validation & payload sanitization
│
├── frontend/
│   ├── templates/
│   │   ├── base.html          # Base layout with navbar, footer, status pill
│   │   ├── index.html         # Landing page & feature showcase
│   │   ├── dashboard.html     # Main dashboard & live packet stream
│   │   ├── inspector.html     # Deep packet inspection & hex viewer
│   │   ├── protocols.html     # Protocol analysis reference guide
│   │   ├── pcap_analysis.html # Drag-and-drop PCAP upload
│   │   ├── history.html       # Session history & report center
│   │   └── education.html     # "Learn Networking" module & quiz
│   └── static/
│       ├── css/style.css      # Dark cybersecurity stylesheet
│       ├── js/
│       │   ├── main.js        # Global app telemetry & toast utilities
│       │   ├── dashboard.js   # Live capture polling & Chart.js charts
│       │   ├── inspector.js   # Accordion dissection & hex renderer
│       │   └── pcap.js        # Drag-and-drop upload & sample loader
│       └── images/
│           └── logo.svg       # Vector reticle logo
│
├── database/
│   ├── models.py              # SQLite database manager & schemas
│   └── init_db.py             # Database initialization script
│
├── sample_pcaps/              # Pre-bundled PCAP files
│   ├── generate_samples.py    # Generator script using Scapy
│   ├── sample_mixed_network.pcap
│   ├── sample_tcp_handshake.pcap
│   ├── sample_http_web.pcap
│   ├── sample_dns_queries.pcap
│   └── sample_icmp_ping.pcap
│
├── reports/                   # Destination folder for generated PDF reports
├── uploads/                   # Destination folder for uploaded PCAPs
│
├── tests/
│   ├── test_parser.py         # Packet parsing & layer accuracy tests
│   ├── test_sniffer.py        # Sniffer lifecycle & interface tests
│   ├── test_security.py       # Validation, traversal & sanitization tests
│   ├── test_pcap.py           # PCAP, CSV & PDF export tests
│   └── run_all_tests.py       # Test runner & throughput benchmark
│
└── docs/
    ├── ARCHITECTURE.md        # Technical architecture documentation
    ├── API_DOCUMENTATION.md   # REST API specification
    └── USER_GUIDE.md          # User manual & walkthrough
```

---

## 5. Installation and Setup

### 1. Clone or Open Workspace
```bash
cd PacketScope
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Initialize the Database
```bash
python database/init_db.py
```

### 4. Generate Bundled Sample PCAPs
```bash
python sample_pcaps/generate_samples.py
```

### 5. Launch the Application
```bash
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 6. Verification & Test Results

Run the complete test suite and performance benchmark:
```bash
python tests/run_all_tests.py
```

### Actual Benchmark & Test Results:
```
=================================================================
 [TEST SUITE] RUNNING PACKETSCOPE COMPREHENSIVE TEST SUITE
=================================================================
test_arp_parsing ............................................ OK
test_ethernet_ip_tcp_parsing ................................ OK
test_icmp_ping_parsing ...................................... OK
test_sensitive_payload_sanitization ......................... OK
test_udp_dns_parsing ........................................ OK
test_csv_export ............................................. OK
test_pcap_parsing_and_database_storage ...................... OK
test_pdf_report_generation .................................. OK
test_allowed_extensions ..................................... OK
test_filter_input_validation ................................ OK
test_path_traversal_prevention .............................. OK
test_payload_credential_masking ............................. OK
test_network_interface_detection ............................ OK
test_sniffer_start_and_stop_lifecycle ....................... OK
test_system_capabilities .................................... OK

Ran 15 tests in 1.756s &bull; OK

=================================================================
 [BENCHMARK] PACKETSCOPE PERFORMANCE BENCHMARKS
=================================================================
 [+] Processed 1,000 synthetic multi-layer packets in 2.8167 seconds.
 [+] Parsing Throughput: 355.02 packets/second

[*] Benchmarking Flask API endpoint latency:
 [+] Home Page              (/                 ) Status: 200 | Latency:  39.08 ms
 [+] Main Dashboard         (/dashboard        ) Status: 200 | Latency:  24.46 ms
 [+] Packet Inspector       (/inspector        ) Status: 200 | Latency:   8.68 ms
 [+] Protocol Analysis      (/protocols        ) Status: 200 | Latency:   4.37 ms
 [+] Networking Education   (/education        ) Status: 200 | Latency:   6.60 ms
 [+] Interfaces API         (/api/interfaces   ) Status: 200 | Latency:   9.62 ms
 [+] Sessions History API   (/api/sessions     ) Status: 200 | Latency:   3.50 ms

=================================================================
 [RESULT] ALL 15 TESTS PASSED SUCCESSFULLY.
=================================================================
```

---

## 7. Security, Privacy & Ethical Monitoring

PacketScope strictly implements educational and safe network monitoring standards:
- **Authorized Scope:** Capture is restricted to network interfaces the user owns or has permission to monitor.
- **No Active Exploitation:** PacketScope contains no packet injection, packet tampering, ARP spoofing, or man-in-the-middle (MITM) capabilities.
- **Privacy Safeguards:** Application payloads are sanitized to mask passwords, session cookies, and authentication tokens before storage or display.
- **No TLS Decryption:** Encrypted TLS/HTTPS streams are identified by protocol header signatures only and are never decrypted.
- **Input Validation:** Strict regex filtering and filename sanitization prevent directory traversal and injection attacks.

---

## 8. License & Attribution
Developed for educational network analysis and cybersecurity demonstration. Built with Python, Flask, Scapy, and Chart.js.
