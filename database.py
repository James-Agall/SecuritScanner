import sqlite3
from datetime import datetime

def init_db():
    conn = sqlite3.connect('scanner.db')
    c = conn.cursor()
    c.execute '''(
        CREATE TABLE IF NOT EXISTS scans
        (id INTEGER PRIMARY KEY AUTOINCREMENT, target_url TEXT, start_time TEXT, status TEXT)
    )'''
    c.execute '''(
        CREATE TABLE IF NOT EXISTS vulnerabilities
        (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, vuln_type TEXT, severity TEXT, url TEXT, parameter TEXT, payload TEXT, description TEXT, remediation TEXT)
    )'''
    conn.commit()
    conn.close()

def save_scan(target_url):
    conn = sqlite3.connect('scanner.db')
    c = conn.cursor()
    c.execute('INSERT INTO scans (target_url, start_time, status) VALUES (?, ?, ?)', 
              (target_url, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'Completed'))
    scan_id = c.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def save_vulnerability(scan_id, vuln_dict):
    conn = sqlite3.connect('scanner.db')
    c = conn.cursor()
    c.execute '''(
        INSERT INTO vulnerabilities (scan_id, vuln_type, severity, url, parameter, payload, description, remediation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    )''', (scan_id, vuln_dict['type'], vuln_dict['severity'], vuln_dict['url'], 
           vuln_dict.get('vulnerable_param', ''), vuln_dict.get('payload_used', ''), 
           vuln_dict.get('description', ''), vuln_dict.get('remediation', ''))
    conn.commit()
    conn.close()
