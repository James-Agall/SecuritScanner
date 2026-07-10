import time
import urllib.parse
from collections import deque
from typing import NotRequired, TypedDict

from bs4 import BeautifulSoup

from enforcer import ScopeEnforcer, safe_http_request


class Asset(TypedDict):
    url: str
    status_code: int
    is_html: bool
    headers: dict[str, str]
    links_found: NotRequired[int]


class HTMLCrawler:
    def __init__(self, seed_url: str, enforcer: ScopeEnforcer, max_pages: int = 20, delay: float = 0.5):
        self.seed_url = seed_url
        self.enforcer = enforcer
        self.max_pages = max_pages
        self.delay = delay
        self.visited: set[str] = set()
        self.queue: deque[str] = deque([seed_url])
        self.discovered_assets: list[Asset] = []

    def _normalize_url(self, url: str) -> str:
        try:
            parsed = urllib.parse.urlparse(url)
            return urllib.parse.urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path, parsed.params, parsed.query, ''))
        except Exception:
            return url

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        soup = BeautifulSoup(html, 'html.parser')
        links: list[str] = []
        for tag, attr in [('a', 'href'), ('form', 'action'), ('iframe', 'src')]:
            for element in soup.find_all(tag):
                href = element.get(attr)
                if href and not href.startswith(('javascript:', 'mailto:', 'tel:')):  # type: ignore[union-attr]
                    links.append(urllib.parse.urljoin(base_url, href))  # type: ignore[arg-type,type-var]
        return links

    def crawl(self) -> list[Asset]:
        print(f"[*] Starting crawl: {self.seed_url} (Max: {self.max_pages})")
        while self.queue and len(self.visited) < self.max_pages:
            current_url = self.queue.popleft()
            normalized_url = self._normalize_url(current_url)

            if normalized_url in self.visited:
                continue
            is_allowed, _ = self.enforcer.check(normalized_url)
            if not is_allowed:
                continue

            self.visited.add(normalized_url)
            print(f"[+] Crawling: {normalized_url}")

            # Request without auto-following redirects, so a redirect endpoint's
            # own URL/params/status is captured as its own asset (needed by
            # scanners like Open Redirect) before we ever chase its Location.
            response = safe_http_request(normalized_url, self.enforcer, allow_redirects=False)
            if response is None:
                print("    ↳ [!] No response received.")
                continue

            # NEW DEBUG PRINT: Let's see exactly what the server is sending back
            print(f"    ↳ Status: {response.status_code} | Content-Type: {response.headers.get('Content-Type', 'MISSING')}")

            content_type = response.headers.get('Content-Type', '').lower()
            is_html = 'text/html' in content_type

            # Update this dictionary to include the headers!
            asset_record: Asset = {
                'url': normalized_url,
                'status_code': response.status_code,
                'is_html': is_html,
                'headers': dict(response.headers) # <--- ADD THIS LINE
            }
            self.discovered_assets.append(asset_record)

            if response.status_code in (301, 302, 303, 307, 308):
                # Don't extract links from a redirect body — instead queue the
                # destination so the crawler discovers pages beyond it, without
                # overwriting this URL's own asset record above.
                location = response.headers.get('Location')
                if location:
                    redirect_url = urllib.parse.urljoin(normalized_url, location)
                    norm_redirect = self._normalize_url(redirect_url)
                    if norm_redirect not in self.visited:
                        self.queue.append(norm_redirect)
            elif is_html:
                try:
                    new_links = self._extract_links(response.text, normalized_url)
                    asset_record['links_found'] = len(new_links)
                    for link in new_links:
                        norm_link = self._normalize_url(link)
                        if norm_link not in self.visited:
                            self.queue.append(norm_link)
                except Exception:
                    pass

            time.sleep(self.delay)

        return self.discovered_assets
    