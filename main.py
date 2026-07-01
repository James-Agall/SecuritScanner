from enforcer import ScopeEnforcer
from crawler import HTMLCrawler
from analyzer import SecurityHeaderAnalyzer
from xss_scanner import XSSScanner # <--- Import the new plugin

if __name__ == "__main__":
    # 1. Target our local Flask app, and TURN ON local testing mode!
    roe_config = {
        "allowed_domains": ["localhost", "127.0.0.1"],
        "allowed_cidrs": [], 
        "allowed_ports": [5000], # Flask runs on 5000 by default
        "excluded_paths": [],
        "allow_local_testing": True # <--- THE NEW FLAG TO BYPASS SSRF PROTECTION
    }
    
    enforcer = ScopeEnforcer(roe_config)

    # 2. Seed the crawler with our vulnerable search page
    crawler = HTMLCrawler(
        seed_url="http://localhost:5000/search?query=hello", 
        enforcer=enforcer, 
        max_pages=10, 
        delay=0.1
    )

    # 3. Execute the Crawler
    results = crawler.crawl()

    # 4. Execute Passive Plugin (Headers)
    analyzer = SecurityHeaderAnalyzer()
    header_findings = analyzer.analyze(results)

    # 5. Execute Active Plugin (XSS)
    xss_scanner = XSSScanner(enforcer)
    xss_findings = xss_scanner.scan(results)

    # ==========================================
    # FINAL COMBINED REPORT
    # ==========================================
    print("\n" + "="*60)
    print("🚨 COMPREHENSIVE SECURITY AUDIT REPORT")
    print("="*60)
    
    # Print Header Findings
    print(f"\n--- PASSIVE FINDINGS: {len(header_findings)} Header Misconfigurations ---")
    for i, vuln in enumerate(header_findings, 1):
        print(f"[{i}] {vuln['severity']} | {vuln['type']}")
        print(f"    ↳ {vuln['url']}")

    # Print XSS Findings
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