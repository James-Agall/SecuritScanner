import urllib.parse
import time
from typing import Set, List, Dict, Any
from collections import deque
from bs4 import BeautifulSoup
from enforcer import ScopeEnforcer, safe_http_request

class HTMLCrawler:
    def __init__(self, seed_url: str, enforcer: ScopeEnforcer, max_pages: int = 20, delay: float = 0.5):
        self.seed_url = seed_url
        self.enforcer = enforcer
        self.max_pages = max_pages
        self.delay = delay
        self.visited: Set[str] = set()
        self.queue = deque([seed_url])
        self.discovered_assets: List[Dict[str, Any]] = []

    def _normalize_url(self, url: str) -> str:
        try:
            parsed = urllib.parse.urlparse(url)
            return urllib.parse.urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path, parsed.params, parsed.query, ''))
        except Exception:
            return url

    def _extract_links(self, html: str, base_url: str) -> List[str]:
        soup = BeautifulSoup(html, 'html.parser')
        links = []
        for tag, attr in [('a', 'href'), ('form', 'action'), ('iframe', 'src')]:
            for element in soup.find_all(tag):
                href = element.get(attr)
                if href and not href.startswith(('javascript:', 'mailto:', 'tel:')):
                    links.append(urllib.parse.urljoin(base_url, href))
        return links

    def crawl(self) -> List[Dict[str, Any]]:
        print(f"[*] Starting crawl: {self.seed_url} (Max: {self.max_pages})")
        while self.queue and len(self.visited) < self.max_pages:
            current_url = self.queue.popleft()
            normalized_url = self._normalize_url(current_url)
            
            if normalized_url in self.visited: continue
            is_allowed, _ = self.enforcer.check(normalized_url)
            if not is_allowed: continue
                
            self.visited.add(normalized_url)
            print(f"[+] Crawling: {normalized_url}")
            
            response = safe_http_request(normalized_url, self.enforcer)
            if not response: 
                print(f"    ↳ [!] No response received.")
                continue
            
            # NEW DEBUG PRINT: Let's see exactly what the server is sending back
            print(f"    ↳ Status: {response.status_code} | Content-Type: {response.headers.get('Content-Type', 'MISSING')}")
                
            content_type = response.headers.get('Content-Type', '').lower()
            is_html = 'text/html' in content_type
            
            # Update this dictionary to include the headers!
            asset_record = {
                'url': normalized_url, 
                'status_code': response.status_code, 
                'is_html': is_html,
                'headers': dict(response.headers) # <--- ADD THIS LINE
            }
            
            if is_html:
                try:
                    new_links = self._extract_links(response.text, normalized_url)
                    asset_record['links_found'] = len(new_links)
                    for link in new_links:
                        norm_link = self._normalize_url(link)
                        if norm_link not in self.visited: self.queue.append(norm_link)
                except Exception: pass
                    
            self.discovered_assets.append(asset_record)
            time.sleep(self.delay)
            
        return self.discovered_assets
    