# PACKETSCOPE &mdash; System Architecture & Technical Design

## 1. Architectural Overview

**PACKETSCOPE** is built with a modular, decoupled architecture adhering to separation of concerns between packet capture, protocol parsing, statistical aggregation, database persistence, and presentation.

```
                           +----------------------------------------+
                           |       Browser (HTML5/CSS3/JS)          |
                           |  Bootstrap 5, Chart.js, Custom Theme   |
                           +-------------------+--------------------+
                                               |
                                     HTTP REST / JSON / Polling
                                               |
                           +-------------------v--------------------+
                           |             Flask Backend              |
                           |  (Blueprints: views_bp & api_bp)      |
                           +---------+--------------------+---------+
                                     |                    |
        +----------------------------+                    +----------------------------+
        |                                                                              |
+-------v-------------------------+                            +-----------------------v--------+
|      Capture Subsystem          |                            |       Analysis Subsystem       |
| - SnifferEngine (Thread-safe)   |                            | - PacketParser (Layer Dissect) |
| - Interface Detector (Cross-OS) |                            | - ProtocolDetector (Signatures)|
| - Rate Limiter & Buffer Bounds  |                            | - StatisticsAnalyzer (Chart.js)|
+-----------------+---------------+                            +-----------------------+--------+
                  |                                                                    |
                  +---------------------------+----------------------------------------+
                                              |
                                   +----------v----------+
                                   |   SQLite Database   |
                                   |  (packetscope.db)   |
                                   |  6 Tables + Indexes |
                                   +---------------------+
```

---

## 2. Component Design

### 2.1 Capture Engine (`backend/capture/sniffer.py`)
- **Threading Model:** Runs asynchronously in a dedicated background worker daemon thread (`threading.Thread(daemon=True)`).
- **Buffer Safety:** Caps internal packet queues at `Config.MAX_CAPTURE_PACKETS = 5000` to prevent memory exhaustion (DoS).
- **Graceful Fallbacks:** On Windows platforms where native WinPcap/Npcap drivers may not be pre-installed, detects missing `wpcap.dll` and smoothly switches into simulated live stream / offline PCAP replay mode while clearly communicating driver status to the user.

### 2.2 Packet Parsing Subsystem (`backend/analysis/packet_parser.py`)
- Dissects packets into an extensible structured dictionary across all network layers:
  - **Data Link Layer:** Ethernet II (Source MAC, Destination MAC, EtherType, VLAN 802.1Q).
  - **Network Layer:** IPv4 (Source IP, Destination IP, Version, Header Length, Total Length, Identification, Flags DF/MF, TTL, Protocol, Checksum), IPv6, and ARP.
  - **Transport Layer:** TCP (Source/Destination Ports, Seq/Ack Numbers, Data Offset, Flags [SYN, ACK, FIN, RST, PSH, URG, ECE, CWR], Window Size, Checksums), UDP (Ports, Length, Checksums), ICMP (Type, Code, Checksum, Sequence, Echo Identifier).
  - **Application Layer:** DNS (Query names, Query types A/AAAA/MX/TXT, Resolver answers, QR flags, OpCode), HTTP (Methods GET/POST, Host, Path, Headers, Status codes), HTTPS/TLS signatures.
- **Payload Sanitization:** Cleartext payload bytes are sliced to 128 bytes, sanitized for control characters, and scrubbed with regular expressions to mask authorization tokens, session cookies, and passwords.

### 2.3 Traffic Analytics Engine (`backend/analysis/statistics.py`)
- Computes aggregated counters in $O(N)$ single-pass time complexity:
  - Protocol breakdown counts and percentages.
  - Time-sliced packet frequency timeline.
  - Top 5 source IP addresses and top 5 destination IP addresses.
  - Packet size distribution histogram (<64B, 64-128B, 129-512B, 513-1024B, 1025-1518B, >1518B).
  - Average packet size and capture packet rate (packets/sec).

### 2.4 Data Persistence (`database/models.py`)
Implemented using standard Python `sqlite3` with foreign keys and optimized B-Tree indexes:
- `users`: Analyst credentials and roles.
- `capture_sessions`: Session metadata, interface, filter, duration, status.
- `packet_metadata`: Individual packet layer records, timestamps, IPs, ports, flags, payload preview.
- `protocol_statistics`: Aggregated protocol counts per session.
- `network_interfaces`: Cached list of physical and virtual host interfaces.
- `export_history`: Audit trail of generated CSV, PDF, and PCAP reports.

---

## 3. Security Architecture
1. **No MITM / No Injection:** PacketScope is designed strictly for passive, authorized traffic monitoring. No ARP poisoning, man-in-the-middle, or raw packet injection is implemented.
2. **Path Traversal Protection:** Filenames uploaded to the PCAP service are sanitized using `werkzeug.utils.secure_filename`.
3. **Execution Prevention:** Uploaded PCAP files are strictly parsed as passive binary packet metadata via Scapy and are never executed as system scripts.
4. **Input Validation:** Query parameters (protocol, IP, port, search terms) are validated against strict regex whitelists to prevent SQL and command injection.
5. **Payload Masking:** Passwords and tokens in application payloads are redacted before being stored or displayed in the UI.
