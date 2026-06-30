from enforcer import ScopeEnforcer
from crawler import HTMLCrawler
from analyzer import SecurityHeaderAnalyzer
from xss_scanner import XSSScanner # <--- Import the new plugin

if __name__ == "__main__":
    # 1. NEW TARGET: An intentionally vulnerable site to test our active scanner
    roe_config = {
        "allowed_domains": ["testphp.vulnweb.com"],
        "allowed_cidrs": [], 
        "allowed_ports": [80, 443],
        "excluded_paths": ["/logout", "/Mod_Rewrite_shop/Buy"] # Avoiding cart actions
    }
    
    enforcer = ScopeEnforcer(roe_config)

    # 2. Seed the crawler with a URL that HAS parameters, so the XSS scanner has something to test!
    crawler = HTMLCrawler(
        seed_url="http://testphp.vulnweb.com/listproducts.php?cat=1", 
        enforcer=enforcer, 
        max_pages=25, 
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
