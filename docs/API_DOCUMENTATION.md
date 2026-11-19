# PACKETSCOPE &mdash; REST API Specification

The PacketScope backend exposes a clean REST API under the `/api` prefix for programmatic control, telemetry polling, and reporting.

---

## 1. Network Interfaces & System Capabilities

### `GET /api/interfaces`
Lists all detected host network interfaces and inspects driver capabilities.

**Sample Response (`200 OK`):**
```json
{
  "success": true,
  "capabilities": {
    "os": "win32",
    "pcap_driver_installed": false,
    "scapy_l3_socket": "<L3WinSocket: a native Layer 3 (IPv4) raw socket under Windows>",
    "offline_pcap_supported": true,
    "safe_mode": true,
    "message": "Npcap/WinPcap not detected. Raw socket / PCAP analysis mode active."
  },
  "interfaces": [
    {
      "id": "Wi-Fi",
      "name": "Wi-Fi",
      "description": "Intel(R) Wi-Fi 6 AX203",
      "ip_address": "10.152.203.69",
      "mac_address": "e8:bf:b8:04:95:4d",
      "guid": "{893BE2CE-23A7-413E-B3A0-C4BB0A8C7DB0}",
      "is_up": true,
      "is_loopback": false,
      "pcap_available": false
    }
  ]
}
```

---

## 2. Capture Control

### `POST /api/capture/start`
Starts a new packet capture session in a background thread.

**Request Payload:**
```json
{
  "interface": "all",
  "filter": "ALL",
  "session_name": "Lab Demo 1"
}
```

**Sample Response (`200 OK`):**
```json
{
  "success": true,
  "session_id": 1,
  "mode": "simulated_live",
  "message": "Live generator mode active"
}
```

### `POST /api/capture/stop`
Terminates the active capture session and commits records to SQLite.

**Sample Response (`200 OK`):**
```json
{
  "success": true,
  "session_id": 1,
  "packet_count": 48,
  "message": "Capture stopped successfully"
}
```

### `GET /api/capture/status`
Returns live state of the capture worker.

**Sample Response (`200 OK`):**
```json
{
  "is_running": true,
  "is_paused": false,
  "session_id": 1,
  "interface": "all",
  "filter": "ALL",
  "packet_count": 22,
  "elapsed_seconds": 11.2,
  "mode": "live",
  "status_message": "Capturing live packets"
}
```

### `GET /api/capture/live?since=<index>`
Fetches newly captured packets and real-time Chart.js statistics since the specified packet index.

---

## 3. Session Management

### `GET /api/sessions`
Returns history of captured and imported sessions.

### `GET /api/sessions/<id>`
Retrieves session metadata, complete traffic statistics, and packet slices.

### `GET /api/sessions/<id>/packets`
Queries session packets with filtering and pagination.

**Query Parameters:**
- `protocol`: `ALL`, `TCP`, `UDP`, `ICMP`, `DNS`, `HTTP`, `ARP`
- `ip`: IP search string (e.g. `192.168.1.1`)
- `port`: Port number filter (e.g. `80`)
- `search`: Keyword string filter
- `limit`: Number of packets to return (max 1,000)
- `offset`: Starting row offset for pagination

### `DELETE /api/sessions/<id>`
Permanently deletes a capture session and all its associated packet metadata.

---

## 4. PCAP File Services

### `POST /api/pcap/upload`
Uploads a `.pcap`, `.pcapng`, or `.cap` file for offline parsing.
- Multipart form field: `file`

### `GET /api/pcap/samples`
Lists pre-bundled educational sample captures available on the server.

### `POST /api/pcap/load-sample`
Loads an educational sample capture directly into a new session.

**Request Payload:**
```json
{
  "filename": "sample_mixed_network.pcap"
}
```

---

## 5. Exports and Reports

### `GET /api/export/csv/<session_id>`
Downloads session packet metadata formatted as a standard CSV spreadsheet.

### `GET /api/export/pdf/<session_id>`
Generates and downloads a cybersecurity PDF report featuring:
- Session metadata
- Protocol distribution summary table
- Top network endpoints (source and destination)
- Packet sample records table
- Redaction compliance notices

### `GET /api/export/pcap/<session_id>`
Downloads the session's raw PCAP file if available.
