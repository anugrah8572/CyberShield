import sqlite3
import hashlib
import datetime
from typing import List, Dict

class CybersecurityDB:
    def __init__(self, db_path="cybersecurity.db"):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # User activity logs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                tool_name TEXT NOT NULL,
                input_data TEXT,
                result_data TEXT,
                ip_address TEXT,
                user_agent TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Admin credentials (cyberadmin / Shield2026!)
        admin_hash = hashlib.sha256("anugrah8572".encode()).hexdigest()
        cursor.execute('''
            INSERT OR IGNORE INTO users (username, password_hash, is_admin)
            VALUES (?, ?, 1)
        ''', ("admin", admin_hash))
        
        conn.commit()
        conn.close()
    
    def verify_user(self, username: str, password: str) -> bool:
        """Verify admin login"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        cursor.execute('SELECT is_admin FROM users WHERE username=? AND password_hash=?',
                      (username, password_hash))
        result = cursor.fetchone()
        conn.close()
        return result and result[0] == 1
    
    def log_activity(self, user_id: int, tool_name: str, input_data: str, 
                    result_data: str, ip_address: str = None, user_agent: str = None):
        """Log user activity"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO user_logs (user_id, tool_name, input_data, result_data, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, tool_name, input_data[:500], result_data[:1000], ip_address, user_agent[:500]))
        conn.commit()
        conn.close()
    
    def get_user_logs(self, limit: int = 100) -> List[Dict]:
        """Get recent user logs for admin"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ul.*, u.username 
            FROM user_logs ul 
            LEFT JOIN users u ON ul.user_id = u.id 
            ORDER BY ul.timestamp DESC LIMIT ?
        ''', (limit,))
        logs = cursor.fetchall()
        conn.close()
        
        return [{
            'id': row[0], 'user_id': row[1], 'tool': row[2], 'input': row[3],
            'result': row[4], 'ip': row[5], 'agent': row[6], 'timestamp': row[7],
            'username': row[8]
        } for row in logs]
    
    def clear_logs(self):
        """Clear all logs (admin only)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM user_logs')
        conn.commit()
        conn.close()
