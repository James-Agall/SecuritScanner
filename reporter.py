import sqlite3
import webbrowser
import os
from datetime import datetime

def generate_html_report(db_path='scanner.db'):
    print("\n[*] Generating HTML Report...")
    
    # 1. Connect to the database and fetch the latest scan
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Get the most recent scan
    c.execute("SELECT id, target_url, start_time, status FROM scans ORDER BY id DESC LIMIT 1")
    scan = c.fetchone()
    
    if not scan:
        print("[!] No scans found in the database.")
        return
        
    scan_id, target_url, start_time, status = scan
    
    # Get all vulnerabilities for this scan
    c.execute("SELECT vuln_type, severity, url, parameter, payload, description, remediation FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
    vulns = c.fetchall()
    conn.close()

    # 2. Group vulnerabilities by severity for the summary
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for v in vulns:
        sev = v[1]
        if sev in severity_counts:
            severity_counts[sev] += 1

    # 3. Build the vulnerability cards HTML
    vuln_cards_html = ""
    if not vulns:
        vuln_cards_html = "<p>✅ No vulnerabilities were found during this scan. The target appears secure against the tested vectors.</p>"
    else:
        for v in vulns:
            vuln_type, severity, url, parameter, payload, description, remediation = v
            vuln_cards_html += f"""
            <div class="vuln-card {severity}">
                <h3><span class="badge {severity}">{severity}</span> {vuln_type}</h3>
                <p><strong>Affected URL:</strong> <code>{url}</code></p>
                <p><strong>Vulnerable Parameter:</strong> <code>{parameter}</code></p>
                <p><strong>Payload Used:</strong> <code>{payload}</code></p>
                <p><strong>Description:</strong> {description}</p>
                <p><strong>🛠️ Remediation:</strong> {remediation}</p>
            </div>
            """

    # 4. Build the main HTML template (using .format() to avoid brace escaping issues)
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Security Audit Report - {target_url}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; max-width: 1000px; margin: 0 auto; padding: 20px; background-color: #f4f7f6; }}
            h1, h2, h3 {{ color: #2c3e50; }}
            .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
            .summary-box {{ display: flex; gap: 15px; margin-bottom: 30px; }}
            .stat {{ flex: 1; background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
            .stat h3 {{ margin: 0; font-size: 2em; }}
            .critical {{ color: #d9534f; border-bottom: 3px solid #d9534f; }}
            .high {{ color: #f0ad4e; border-bottom: 3px solid #f0ad4e; }}
            .medium {{ color: #5bc0de; border-bottom: 3px solid #5bc0de; }}
            .low {{ color: #5cb85c; border-bottom: 3px solid #5cb85c; }}
            .vuln-card {{ background: white; padding: 20px; margin-bottom: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 5px solid #ccc; }}
            .vuln-card.CRITICAL {{ border-left-color: #d9534f; }}
            .vuln-card.HIGH {{ border-left-color: #f0ad4e; }}
            .vuln-card.MEDIUM {{ border-left-color: #5bc0de; }}
            .vuln-card.LOW {{ border-left-color: #5cb85c; }}
            .badge {{ display: inline-block; padding: 5px 10px; border-radius: 4px; color: white; font-weight: bold; font-size: 0.8em; }}
            .badge.CRITICAL {{ background-color: #d9534f; }}
            .badge.HIGH {{ background-color: #f0ad4e; }}
            .badge.MEDIUM {{ background-color: #5bc0de; }}
            .badge.LOW {{ background-color: #5cb85c; }}
            code {{ background-color: #f8f9fa; padding: 2px 5px; border-radius: 3px; font-family: monospace; color: #d63384; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ Security Audit Report</h1>
            <p><strong>Target:</strong> {target_url} | <strong>Date:</strong> {start_time} | <strong>Status:</strong> {status}</p>
        </div>

        <div class="summary-box">
            <div class="stat critical"><h3>{critical_count}</h3><p>Critical</p></div>
            <div class="stat high"><h3>{high_count}</h3><p>High</p></div>
            <div class="stat medium"><h3>{medium_count}</h3><p>Medium</p></div>
            <div class="stat low"><h3>{low_count}</h3><p>Low</p></div>
        </div>

        <h2>🚨 Discovered Vulnerabilities</h2>
        {vuln_cards}
    </body>
    </html>
    """
    
    # Format the template with our data
    html_content = html_template.format(
        target_url=target_url,
        start_time=start_time,
        status=status,
        critical_count=severity_counts['CRITICAL'],
        high_count=severity_counts['HIGH'],
        medium_count=severity_counts['MEDIUM'],
        low_count=severity_counts['LOW'],
        vuln_cards=vuln_cards_html
    )

    # 5. Write to file and open in browser
    report_filename = f"report_{scan_id}.html"
    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    print(f"[*] Report saved to {os.path.abspath(report_filename)}")
    print("[*] Opening report in default web browser...")
    webbrowser.open(f"file://{os.path.abspath(report_filename)}")