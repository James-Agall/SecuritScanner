from typing import Any

from analyzer import SecurityHeaderAnalyzer
from cmd_injection_scanner import CommandInjectionScanner
from cookie_scanner import CookieScanner
from cors_scanner import CORSScanner
from crawler import HTMLCrawler
from csrf_scanner import CSRFScanner
from database import init_db, save_scan, save_vulnerability
from enforcer import ScopeEnforcer
from fuzzer import DirectoryFuzzer
from idor_scanner import IDORScanner
from lfi_scanner import LFIScanner
from open_redirect_scanner import OpenRedirectScanner
from reporter import generate_html_report
from sqli_scanner import SQLiScanner
from ssl_scanner import SSLScanner
from ssrf_scanner import SSRFScanner
from xss_scanner import XSSScanner
from xxe_scanner import XXEScanner

if __name__ == "__main__":
    init_db()
    scan_id = save_scan("https://localhost:5000")

    roe_config: dict[str, Any] = {
        "allowed_domains": ["localhost", "127.0.0.1"],
        "allowed_cidrs": [],
        "allowed_ports": [5000],
        "excluded_paths": [],
        "allow_local_testing": True,
        "stealth_mode": True,
        "proxy_url": "",
        "test_username": "admin",
        "test_password": "admin123"
    }

    enforcer = ScopeEnforcer(roe_config)

    # Start at the root so the crawler has to find the links!
    crawler = HTMLCrawler(
        seed_url="https://localhost:5000/",
        enforcer=enforcer,
        max_pages=20,
        delay=0.1
    )

    results = crawler.crawl()

    analyzer = SecurityHeaderAnalyzer()
    header_findings = analyzer.analyze(results)

    cookie_scanner = CookieScanner(enforcer, roe_config["test_username"], roe_config["test_password"])
    cookie_findings = cookie_scanner.scan(results)

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

    idor_scanner = IDORScanner(enforcer, roe_config["test_username"], roe_config["test_password"])
    idor_scanner.login(results[0]['url'])
    idor_findings = idor_scanner.scan(results)

    lfi_scanner = LFIScanner(enforcer)
    lfi_findings = lfi_scanner.scan(results)

    ssrf_scanner = SSRFScanner(enforcer)
    ssrf_findings = ssrf_scanner.scan(results)

    cors_scanner = CORSScanner(enforcer)
    cors_findings = cors_scanner.scan(results)

    xxe_scanner = XXEScanner(enforcer)
    xxe_findings = xxe_scanner.scan(results)

    open_redirect_scanner = OpenRedirectScanner(enforcer)
    open_redirect_findings = open_redirect_scanner.scan(results)

    print("\n" + "="*60)
    print("🚨 COMPREHENSIVE SECURITY AUDIT REPORT")
    print("="*60)

    print(f"\n--- PASSIVE FINDINGS: {len(header_findings)} Header Misconfigurations ---")
    for i, vuln in enumerate(header_findings, 1):
        print(f"[{i}] {vuln['severity']} | {vuln['type']}")
        print(f"    ↳ {vuln['url']}")
        save_vulnerability(scan_id, vuln)

    print(f"\n--- COOKIE FINDINGS: {len(cookie_findings)} Cookie Security Issues ---")
    if not cookie_findings:
        print("✅ No cookie security issues found.")
    else:
        for i, vuln in enumerate(cookie_findings, 1):
            print(f"\n[{i}] {vuln['severity']} | {vuln['type']}")
            print(f"    🌐 URL: {vuln['url']}")
            print(f"    🎯 Vulnerable Parameter: {vuln['vulnerable_param']}")
            print(f"    🛠️ Fix: {vuln['remediation']}")
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

    print(f"\n--- IDOR FINDINGS: {len(idor_findings)} Insecure Direct Object References ---")
    if not idor_findings:
        print("✅ No IDOR vulnerabilities found.")
    else:
        for i, vuln in enumerate(idor_findings, 1):
            print(f"\n[{i}] {vuln['severity']} | {vuln['type']}")
            print(f"    🌐 URL: {vuln['url']}")
            print(f"    🎯 Vulnerable Parameter: {vuln['vulnerable_param']}")
            print(f"    💉 Payload that worked: {vuln['payload_used']}")
            print(f"    🛠️ Fix: {vuln['remediation']}")
            save_vulnerability(scan_id, vuln)

    print(f"\n--- LFI FINDINGS: {len(lfi_findings)} Path Traversal / LFI Vulnerabilities ---")
    if not lfi_findings:
        print("✅ No Path Traversal / LFI found.")
    else:
        for i, vuln in enumerate(lfi_findings, 1):
            print(f"\n[{i}] {vuln['severity']} | {vuln['type']}")
            print(f"    🌐 URL: {vuln['url']}")
            print(f"    🎯 Vulnerable Parameter: {vuln['vulnerable_param']}")
            print(f"    💉 Payload that worked: {vuln['payload_used']}")
            print(f"    🛠️ Fix: {vuln['remediation']}")
            save_vulnerability(scan_id, vuln)

    print(f"\n--- SSRF FINDINGS: {len(ssrf_findings)} Server-Side Request Forgery Vulnerabilities ---")
    if not ssrf_findings:
        print("✅ No SSRF vulnerabilities found.")
    else:
        for i, vuln in enumerate(ssrf_findings, 1):
            print(f"\n[{i}] {vuln['severity']} | {vuln['type']}")
            print(f"    🌐 URL: {vuln['url']}")
            print(f"    🎯 Vulnerable Parameter: {vuln['vulnerable_param']}")
            print(f"    💉 Payload that worked: {vuln['payload_used']}")
            print(f"    🛠️ Fix: {vuln['remediation']}")
            save_vulnerability(scan_id, vuln)

    print(f"\n--- CORS FINDINGS: {len(cors_findings)} CORS Misconfigurations ---")
    if not cors_findings:
        print("✅ No CORS misconfigurations found.")
    else:
        for i, vuln in enumerate(cors_findings, 1):
            print(f"\n[{i}] {vuln['severity']} | {vuln['type']}")
            print(f"    🌐 URL: {vuln['url']}")
            print(f"    🎯 Vulnerable Parameter: {vuln['vulnerable_param']}")
            print(f"    💉 Payload that worked: {vuln['payload_used']}")
            print(f"    🛠️ Fix: {vuln['remediation']}")
            save_vulnerability(scan_id, vuln)

    print(f"\n--- XXE FINDINGS: {len(xxe_findings)} XML External Entity Injection Vulnerabilities ---")
    if not xxe_findings:
        print("✅ No XXE vulnerabilities found.")
    else:
        for i, vuln in enumerate(xxe_findings, 1):
            print(f"\n[{i}] {vuln['severity']} | {vuln['type']}")
            print(f"    🌐 URL: {vuln['url']}")
            print(f"    🎯 Vulnerable Parameter: {vuln['vulnerable_param']}")
            print(f"    💉 Payload that worked: {vuln['payload_used']}")
            print(f"    🛠️ Fix: {vuln['remediation']}")
            save_vulnerability(scan_id, vuln)

    print(f"\n--- OPEN REDIRECT FINDINGS: {len(open_redirect_findings)} Open Redirect Vulnerabilities ---")
    if not open_redirect_findings:
        print("✅ No Open Redirect vulnerabilities found.")
    else:
        for i, vuln in enumerate(open_redirect_findings, 1):
            print(f"\n[{i}] {vuln['severity']} | {vuln['type']}")
            print(f"    🌐 URL: {vuln['url']}")
            print(f"    🎯 Vulnerable Parameter: {vuln['vulnerable_param']}")
            print(f"    💉 Payload that worked: {vuln['payload_used']}")
            print(f"    🛠️ Fix: {vuln['remediation']}")
            save_vulnerability(scan_id, vuln)

    # Generate the final HTML report
    generate_html_report()