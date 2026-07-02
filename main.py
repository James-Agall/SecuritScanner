from enforcer import ScopeEnforcer
from crawler import HTMLCrawler
from analyzer import SecurityHeaderAnalyzer
from xss_scanner import XSSScanner
from sqli_scanner import SQLiScanner
from database import init_db, save_scan, save_vulnerability
from reporter import generate_html_report
from fuzzer import DirectoryFuzzer
from csrf_scanner import CSRFScanner
from ssl_scanner import SSLScanner
from cmd_injection_scanner import CommandInjectionScanner
if __name__ == "__main__":
    init_db()
    scan_id = save_scan("https://localhost:5000")

    roe_config = {
        "allowed_domains": ["localhost", "127.0.0.1"],
        "allowed_cidrs": [],
        "allowed_ports": [5000],
        "excluded_paths": [],
        "allow_local_testing": True
    }

    enforcer = ScopeEnforcer(roe_config)

    # Start at the root so the crawler has to find the links!
    crawler = HTMLCrawler(
        seed_url="https://localhost:5000/",
        enforcer=enforcer,
        max_pages=10,
        delay=0.1
    )

    results = crawler.crawl()

    analyzer = SecurityHeaderAnalyzer()
    header_findings = analyzer.analyze(results)

    xss_scanner = XSSScanner(enforcer)
    xss_findings = xss_scanner.scan(results)

    sqli_scanner = SQLiScanner(enforcer)
    sqli_findings = sqli_scanner.scan(results)
    fuzzer = DirectoryFuzzer(enforcer)
    fuzz_findings = fuzzer.scan(results)

    csrf_scanner = CSRFScanner(enforcer)
    csrf_findings = csrf_scanner.scan(results)

    ssl_scanner = SSLScanner(enforcer, "localhost")
    ssl_findings = ssl_scanner.scan()

    cmd_injection_scanner = CommandInjectionScanner(enforcer)
    cmd_injection_findings = cmd_injection_scanner.scan(results)

    print("\n" + "="*60)
    print("🚨 COMPREHENSIVE SECURITY AUDIT REPORT")
    print("="*60)

    print(f"\n--- PASSIVE FINDINGS: {len(header_findings)} Header Misconfigurations ---")
    for i, vuln in enumerate(header_findings, 1):
        print(f"[{i}] {vuln['severity']} | {vuln['type']}")
        print(f"    ↳ {vuln['url']}")
        save_vulnerability(scan_id, vuln)

    print(f"\n--- ACTIVE FINDINGS: {len(xss_findings)} XSS Vulnerabilities ---")
    if not xss_findings:
        print("✅ No Reflected XSS found.")
    else:
        for i, vuln in enumerate(xss_findings, 1):
            print(f"\n[{i}] {vuln['severity']} | {vuln['type']}")
            print(f"    🌐 URL: {vuln['url']}")
            print(f"    🎯 Vulnerable Parameter: {vuln['vulnerable_param']}")
            print(f"    💉 Payload that worked: {vuln['payload_used']}")
            print(f"    🛠️ Fix: {vuln['remediation']}")
            save_vulnerability(scan_id, vuln)

    print(f"\n--- SQLI FINDINGS: {len(sqli_findings)} SQL Injection Vulnerabilities ---")
    if not sqli_findings:
        print("✅ No Error-Based SQLi found.")
    else:
        for i, vuln in enumerate(sqli_findings, 1):
            print(f"\n[{i}] {vuln['severity']} | {vuln['type']}")
            print(f"    🌐 URL: {vuln['url']}")
            print(f"    🎯 Vulnerable Parameter: {vuln['vulnerable_param']}")
            print(f"    💉 Payload that worked: {vuln['payload_used']}")
            print(f"    🛠️ Fix: {vuln['remediation']}")
            save_vulnerability(scan_id, vuln)

    print(f"\n--- FUZZING FINDINGS: {len(fuzz_findings)} Exposed Paths ---")
    if not fuzz_findings:
        print("✅ No exposed sensitive paths found.")
    else:
        for i, vuln in enumerate(fuzz_findings, 1):
            print(f"\n[{i}] {vuln['severity']} | {vuln['type']}")
            print(f"    🌐 URL: {vuln['url']}")
            print(f"     Details: {vuln['description']}")
            print(f"    🛠️ Fix: {vuln['remediation']}")
            save_vulnerability(scan_id, vuln)

    print(f"\n--- CSRF FINDINGS: {len(csrf_findings)} Forms Missing CSRF Protection ---")
    if not csrf_findings:
        print("✅ No missing CSRF tokens found.")
    else:
        for i, vuln in enumerate(csrf_findings, 1):
            print(f"\n[{i}] {vuln['severity']} | {vuln['type']}")
            print(f"    🌐 URL: {vuln['url']}")
            print(f"    🎯 Vulnerable Form Action: {vuln['vulnerable_param']}")
            print(f"    🛠️ Fix: {vuln['remediation']}")
            save_vulnerability(scan_id, vuln)

    print(f"\n--- SSL/TLS FINDINGS: {len(ssl_findings)} Certificate/Configuration Issues ---")
    if not ssl_findings:
        print("✅ No SSL/TLS issues found.")
    else:
        for i, vuln in enumerate(ssl_findings, 1):
            print(f"\n[{i}] {vuln['severity']} | {vuln['type']}")
            print(f"    🌐 URL: {vuln['url']}")
            print(f"     Details: {vuln['description']}")
            print(f"    🛠️ Fix: {vuln['remediation']}")
            save_vulnerability(scan_id, vuln)

    print(f"\n--- COMMAND INJECTION FINDINGS: {len(cmd_injection_findings)} OS Command Injection Vulnerabilities ---")
    if not cmd_injection_findings:
        print("✅ No OS Command Injection found.")
    else:
        for i, vuln in enumerate(cmd_injection_findings, 1):
            print(f"\n[{i}] {vuln['severity']} | {vuln['type']}")
            print(f"    🌐 URL: {vuln['url']}")
            print(f"    🎯 Vulnerable Parameter: {vuln['vulnerable_param']}")
            print(f"    💉 Payload that worked: {vuln['payload_used']}")
            print(f"    🛠️ Fix: {vuln['remediation']}")
            save_vulnerability(scan_id, vuln)
    # Generate the final HTML report
generate_html_report()