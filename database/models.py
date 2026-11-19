import sqlite3
import os
import json
from datetime import datetime
from config import Config

def get_db_connection():
    """Get a connection to the SQLite database with row factory enabled."""
    os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

class DatabaseManager:
    """Manages SQLite database schema and operations for PacketScope."""

    @staticmethod
    def init_db():
        """Initialize database schema with required tables and indexes."""
        conn = get_db_connection()
        cursor = conn.cursor()

        # 1. Users Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'analyst',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # 2. Capture Sessions Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS capture_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                interface TEXT,
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time TIMESTAMP,
                total_packets INTEGER DEFAULT 0,
                status TEXT DEFAULT 'stopped',  -- 'running', 'stopped', 'completed', 'imported'
                filter_applied TEXT,
                pcap_path TEXT,
                notes TEXT
            )
        ''')

        # 3. Packet Metadata Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packet_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                packet_number INTEGER NOT NULL,
                timestamp REAL NOT NULL,
                formatted_time TEXT,
                eth_src TEXT,
                eth_dst TEXT,
                eth_type TEXT,
                ip_src TEXT,
                ip_dst TEXT,
                ip_version INTEGER,
                ip_ttl INTEGER,
                protocol TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                packet_len INTEGER NOT NULL,
                tcp_flags TEXT,
                info TEXT,
                payload_preview TEXT,
                layers_json TEXT,
                FOREIGN KEY (session_id) REFERENCES capture_sessions(id) ON DELETE CASCADE
            )
        ''')

        # 4. Protocol Statistics Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS protocol_statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER UNIQUE NOT NULL,
                tcp_count INTEGER DEFAULT 0,
                udp_count INTEGER DEFAULT 0,
                icmp_count INTEGER DEFAULT 0,
                dns_count INTEGER DEFAULT 0,
                http_count INTEGER DEFAULT 0,
                arp_count INTEGER DEFAULT 0,
                other_count INTEGER DEFAULT 0,
                total_bytes INTEGER DEFAULT 0,
                FOREIGN KEY (session_id) REFERENCES capture_sessions(id) ON DELETE CASCADE
            )
        ''')

        # 5. Network Interfaces Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_interfaces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                ip_address TEXT,
                mac_address TEXT,
                is_up BOOLEAN DEFAULT 1,
                is_loopback BOOLEAN DEFAULT 0,
                last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # 6. Export History Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS export_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                export_type TEXT NOT NULL,  -- 'csv', 'pdf', 'pcap'
                file_name TEXT NOT NULL,
                file_size INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES capture_sessions(id) ON DELETE SET NULL
            )
        ''')

        # Database Indexes for Performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_packet_session ON packet_metadata(session_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_packet_proto ON packet_metadata(protocol)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_packet_ip_src ON packet_metadata(ip_src)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_packet_ip_dst ON packet_metadata(ip_dst)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_packet_timestamp ON packet_metadata(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_session_time ON capture_sessions(start_time)')

        conn.commit()
        conn.close()

    # Capture Sessions Queries
    @staticmethod
    def create_session(name, interface="all", filter_applied="None", notes=None, pcap_path=None):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO capture_sessions (name, interface, start_time, status, filter_applied, notes, pcap_path)
            VALUES (?, ?, ?, 'running', ?, ?, ?)
        ''', (name, interface, datetime.now().isoformat(), filter_applied, notes, pcap_path))
        session_id = cursor.lastrowid
        
        # Initialize protocol stats row
        cursor.execute('''
            INSERT INTO protocol_statistics (session_id) VALUES (?)
        ''', (session_id,))
        
        conn.commit()
        conn.close()
        return session_id

    @staticmethod
    def finish_session(session_id, total_packets=None, status="completed", pcap_path=None):
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        if total_packets is None:
            cursor.execute('SELECT COUNT(*) as count FROM packet_metadata WHERE session_id = ?', (session_id,))
            row = cursor.fetchone()
            total_packets = row['count'] if row else 0

        cursor.execute('''
            UPDATE capture_sessions
            SET end_time = ?, total_packets = ?, status = ?, pcap_path = COALESCE(?, pcap_path)
            WHERE id = ?
        ''', (now, total_packets, status, pcap_path, session_id))
        
        # Update protocol statistics summary
        cursor.execute('''
            SELECT 
                SUM(CASE WHEN protocol = 'TCP' THEN 1 ELSE 0 END) as tcp_c,
                SUM(CASE WHEN protocol = 'UDP' THEN 1 ELSE 0 END) as udp_c,
                SUM(CASE WHEN protocol = 'ICMP' THEN 1 ELSE 0 END) as icmp_c,
                SUM(CASE WHEN protocol = 'DNS' THEN 1 ELSE 0 END) as dns_c,
                SUM(CASE WHEN protocol = 'HTTP' THEN 1 ELSE 0 END) as http_c,
                SUM(CASE WHEN protocol = 'ARP' THEN 1 ELSE 0 END) as arp_c,
                SUM(CASE WHEN protocol NOT IN ('TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'ARP') THEN 1 ELSE 0 END) as other_c,
                SUM(packet_len) as total_bytes
            FROM packet_metadata WHERE session_id = ?
        ''', (session_id,))
        stats = cursor.fetchone()
        if stats:
            cursor.execute('''
                UPDATE protocol_statistics
                SET tcp_count = ?, udp_count = ?, icmp_count = ?, dns_count = ?,
                    http_count = ?, arp_count = ?, other_count = ?, total_bytes = ?
                WHERE session_id = ?
            ''', (
                stats['tcp_c'] or 0, stats['udp_c'] or 0, stats['icmp_c'] or 0,
                stats['dns_c'] or 0, stats['http_c'] or 0, stats['arp_c'] or 0,
                stats['other_c'] or 0, stats['total_bytes'] or 0, session_id
            ))

        conn.commit()
        conn.close()

    @staticmethod
    def save_packets_batch(session_id, packet_list):
        """Batch insert packets into SQLite for speed."""
        if not packet_list:
            return 0
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.executemany('''
            INSERT INTO packet_metadata (
                session_id, packet_number, timestamp, formatted_time,
                eth_src, eth_dst, eth_type, ip_src, ip_dst, ip_version,
                ip_ttl, protocol, src_port, dst_port, packet_len,
                tcp_flags, info, payload_preview, layers_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', [
            (
                session_id,
                p.get('packet_number', idx + 1),
                p.get('timestamp', 0.0),
                p.get('formatted_time', ''),
                p.get('eth_src', 'N/A'),
                p.get('eth_dst', 'N/A'),
                p.get('eth_type', 'N/A'),
                p.get('ip_src', 'N/A'),
                p.get('ip_dst', 'N/A'),
                p.get('ip_version', 4),
                p.get('ip_ttl', 64),
                p.get('protocol', 'OTHER'),
                p.get('src_port'),
                p.get('dst_port'),
                p.get('packet_len', 0),
                p.get('tcp_flags', ''),
                p.get('info', ''),
                p.get('payload_preview', ''),
                json.dumps(p.get('layers', []))
            )
            for idx, p in enumerate(packet_list)
        ])
        conn.commit()
        conn.close()
        return len(packet_list)

    @staticmethod
    def get_sessions(limit=50):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT s.*, 
                   ps.tcp_count, ps.udp_count, ps.icmp_count, ps.dns_count, 
                   ps.http_count, ps.arp_count, ps.other_count, ps.total_bytes
            FROM capture_sessions s
            LEFT JOIN protocol_statistics ps ON s.id = ps.session_id
            ORDER BY s.id DESC LIMIT ?
        ''', (limit,))
        sessions = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return sessions

    @staticmethod
    def get_session(session_id):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT s.*, 
                   ps.tcp_count, ps.udp_count, ps.icmp_count, ps.dns_count, 
                   ps.http_count, ps.arp_count, ps.other_count, ps.total_bytes
            FROM capture_sessions s
            LEFT JOIN protocol_statistics ps ON s.id = ps.session_id
            WHERE s.id = ?
        ''', (session_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    @staticmethod
    def delete_session(session_id):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM capture_sessions WHERE id = ?', (session_id,))
        cursor.execute('DELETE FROM packet_metadata WHERE session_id = ?', (session_id,))
        cursor.execute('DELETE FROM protocol_statistics WHERE session_id = ?', (session_id,))
        conn.commit()
        conn.close()
        return True

    @staticmethod
    def get_packets(session_id, protocol=None, ip=None, port=None, search=None, limit=500, offset=0):
        conn = get_db_connection()
        cursor = conn.cursor()

        query = 'SELECT * FROM packet_metadata WHERE session_id = ?'
        params = [session_id]

        if protocol and protocol.upper() != 'ALL':
            query += ' AND UPPER(protocol) = ?'
            params.append(protocol.upper())

        if ip:
            query += ' AND (ip_src LIKE ? OR ip_dst LIKE ?)'
            params.extend([f'%{ip}%', f'%{ip}%'])

        if port:
            query += ' AND (src_port = ? OR dst_port = ?)'
            params.extend([int(port), int(port)])

        if search:
            query += ' AND (info LIKE ? OR ip_src LIKE ? OR ip_dst LIKE ? OR protocol LIKE ?)'
            search_param = f'%{search}%'
            params.extend([search_param, search_param, search_param, search_param])

        query += ' ORDER BY packet_number ASC LIMIT ? OFFSET ?'
        params.extend([limit, offset])

        cursor.execute(query, params)
        packets = [dict(row) for row in cursor.fetchall()]
        
        # Total count query for pagination
        count_query = query.replace('SELECT * FROM packet_metadata', 'SELECT COUNT(*) as count FROM packet_metadata').split(' ORDER BY')[0]
        cursor.execute(count_query, params[:-2])
        total_row = cursor.fetchone()
        total_count = total_row['count'] if total_row else len(packets)

        conn.close()
        return packets, total_count

    @staticmethod
    def get_packet_by_id(packet_id):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM packet_metadata WHERE id = ?', (packet_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    @staticmethod
    def log_export(session_id, export_type, file_name, file_size=0):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO export_history (session_id, export_type, file_name, file_size)
            VALUES (?, ?, ?, ?)
        ''', (session_id, export_type, file_name, file_size))
        conn.commit()
        conn.close()

    @staticmethod
    def save_interfaces(iface_list):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM network_interfaces')
        for iface in iface_list:
            cursor.execute('''
                INSERT INTO network_interfaces (name, description, ip_address, mac_address, is_up, is_loopback)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                iface.get('name'),
                iface.get('description'),
                iface.get('ip_address'),
                iface.get('mac_address'),
                1 if iface.get('is_up', True) else 0,
                1 if iface.get('is_loopback', False) else 0
            ))
        conn.commit()
        conn.close()

    @staticmethod
    def get_cached_interfaces():
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM network_interfaces')
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows
