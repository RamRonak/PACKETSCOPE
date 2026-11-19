"""Database initialization script for PacketScope."""
import sys
import os
import hashlib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.models import DatabaseManager, get_db_connection

def initialize_database():
    print("[*] Initializing PacketScope database...")
    DatabaseManager.init_db()
    
    # Check if default admin/analyst user exists
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) as count FROM users')
    count = cursor.fetchone()['count']
    
    if count == 0:
        # Default secure educational analyst account
        default_user = "analyst"
        default_pwd_hash = hashlib.sha256("packetscope2026".encode()).hexdigest()
        cursor.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            (default_user, default_pwd_hash, 'admin')
        )
        conn.commit()
        print(f"[+] Created default educational user: {default_user}")

    conn.close()
    print("[+] Database initialized successfully.")

if __name__ == "__main__":
    initialize_database()
