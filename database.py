import sqlite3
from datetime import datetime
from typing import NotRequired, TypedDict


class Vulnerability(TypedDict):
    type: str
    severity: str
    url: str
    description: str
    remediation: str
    vulnerable_param: NotRequired[str]
    payload_used: NotRequired[str]


class VulnerabilityRecord(Vulnerability):
    id: int
    scan_id: int


class ScanRecord(TypedDict):
    id: int
    target_url: str
    start_time: str
    status: str
    current_phase: str | None
    vulnerability_count: int


def init_db() -> None:
    conn = sqlite3.connect('scanner.db')
    c = conn.cursor()
    # Fixed the syntax error here!
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans
        (id INTEGER PRIMARY KEY AUTOINCREMENT, target_url TEXT, start_time TEXT, status TEXT, current_phase TEXT)
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities
        (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, vuln_type TEXT, severity TEXT, url TEXT, parameter TEXT, payload TEXT, description TEXT, remediation TEXT)
    ''')
    # Upgrade path for pre-existing scanner.db files created before this column existed.
    try:
        c.execute("ALTER TABLE scans ADD COLUMN current_phase TEXT")
    except sqlite3.OperationalError as e:
        if "duplicate column" not in str(e):
            raise
    conn.commit()
    conn.close()

def save_scan(target_url: str, status: str = 'Completed') -> int | None:
    conn = sqlite3.connect('scanner.db')
    c = conn.cursor()
    c.execute('INSERT INTO scans (target_url, start_time, status) VALUES (?, ?, ?)',
              (target_url, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), status))
    scan_id = c.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def update_scan_status(scan_id: int, status: str) -> None:
    conn = sqlite3.connect('scanner.db')
    c = conn.cursor()
    c.execute('UPDATE scans SET status = ? WHERE id = ?', (status, scan_id))
    conn.commit()
    conn.close()


def update_scan_phase(scan_id: int, phase: str) -> None:
    conn = sqlite3.connect('scanner.db')
    c = conn.cursor()
    c.execute('UPDATE scans SET current_phase = ? WHERE id = ?', (phase, scan_id))
    conn.commit()
    conn.close()

def save_vulnerability(scan_id: int | None, vuln_dict: Vulnerability) -> None:
    conn = sqlite3.connect('scanner.db')
    c = conn.cursor()
    c.execute('''
        INSERT INTO vulnerabilities (scan_id, vuln_type, severity, url, parameter, payload, description, remediation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (scan_id, vuln_dict['type'], vuln_dict['severity'], vuln_dict['url'],
           vuln_dict.get('vulnerable_param', ''), vuln_dict.get('payload_used', ''),
           vuln_dict.get('description', ''), vuln_dict.get('remediation', '')))
    conn.commit()
    conn.close()


def _row_to_scan_record(row: tuple[int, str, str, str, str | None, int]) -> ScanRecord:
    scan_id, target_url, start_time, status, current_phase, vuln_count = row
    return {
        "id": scan_id,
        "target_url": target_url,
        "start_time": start_time,
        "status": status,
        "current_phase": current_phase,
        "vulnerability_count": vuln_count,
    }


def get_scan(scan_id: int) -> ScanRecord | None:
    conn = sqlite3.connect('scanner.db')
    c = conn.cursor()
    c.execute('''
        SELECT s.id, s.target_url, s.start_time, s.status, s.current_phase, COUNT(v.id)
        FROM scans s
        LEFT JOIN vulnerabilities v ON v.scan_id = s.id
        WHERE s.id = ?
        GROUP BY s.id
    ''', (scan_id,))
    row = c.fetchone()
    conn.close()
    return _row_to_scan_record(row) if row else None


def get_all_scans() -> list[ScanRecord]:
    conn = sqlite3.connect('scanner.db')
    c = conn.cursor()
    c.execute('''
        SELECT s.id, s.target_url, s.start_time, s.status, s.current_phase, COUNT(v.id)
        FROM scans s
        LEFT JOIN vulnerabilities v ON v.scan_id = s.id
        GROUP BY s.id
        ORDER BY s.id DESC
    ''')
    rows = c.fetchall()
    conn.close()
    return [_row_to_scan_record(row) for row in rows]


def get_vulnerabilities_for_scan(scan_id: int) -> list[VulnerabilityRecord]:
    conn = sqlite3.connect('scanner.db')
    c = conn.cursor()
    c.execute('''
        SELECT id, scan_id, vuln_type, severity, url, parameter, payload, description, remediation
        FROM vulnerabilities WHERE scan_id = ?
        ORDER BY id
    ''', (scan_id,))
    rows = c.fetchall()
    conn.close()
    return [
        {
            "id": vuln_id,
            "scan_id": vuln_scan_id,
            "type": vuln_type,
            "severity": severity,
            "url": url,
            "vulnerable_param": parameter,
            "payload_used": payload,
            "description": description,
            "remediation": remediation,
        }
        for vuln_id, vuln_scan_id, vuln_type, severity, url, parameter, payload, description, remediation in rows
    ]


def delete_scan(scan_id: int) -> bool:
    conn = sqlite3.connect('scanner.db')
    c = conn.cursor()
    c.execute('DELETE FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
    c.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    deleted = c.rowcount > 0
    conn.commit()
    conn.close()
    return deleted
