import responses as responses_lib

from crawler import HTMLCrawler


def html_response_kwargs(links_html, content_type="text/html"):
    return {"body": links_html, "status": 200, "content_type": content_type}


class TestHTMLCrawlerLinkExtraction:
    def test_extracts_a_form_and_iframe_links(self, enforcer):
        crawler = HTMLCrawler("https://localhost:5000/", enforcer)
        html = """
        <a href="/page1">p1</a>
        <form action="/submit"></form>
        <iframe src="/frame"></iframe>
        <a href="javascript:void(0)">skip me</a>
        <a href="mailto:test@example.com">skip me too</a>
        """
        links = crawler._extract_links(html, "https://localhost:5000/")
        assert "https://localhost:5000/page1" in links
        assert "https://localhost:5000/submit" in links
        assert "https://localhost:5000/frame" in links
        assert not any("javascript:" in link or "mailto:" in link for link in links)

    def test_normalize_strips_fragment_and_lowercases_host(self, enforcer):
        crawler = HTMLCrawler("https://localhost:5000/", enforcer)
        assert crawler._normalize_url("https://LOCALHOST:5000/path?x=1#frag") == "https://localhost:5000/path?x=1"


class TestHTMLCrawlerCrawl:
    @responses_lib.activate
    def test_bfs_discovers_linked_pages(self, enforcer):
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/",
            body='<a href="/about">About</a>', status=200, content_type="text/html",
        )
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/about",
            body="<p>about page, no links</p>", status=200, content_type="text/html",
        )
        crawler = HTMLCrawler("https://localhost:5000/", enforcer, max_pages=10, delay=0)
        assets = crawler.crawl()

        urls = {a["url"] for a in assets}
        assert urls == {"https://localhost:5000/", "https://localhost:5000/about"}

    @responses_lib.activate
    def test_respects_max_pages(self, enforcer):
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/",
            body='<a href="/p1">1</a><a href="/p2">2</a><a href="/p3">3</a>',
            status=200, content_type="text/html",
        )
        for p in ("p1", "p2", "p3"):
            responses_lib.add(
                responses_lib.GET, f"https://localhost:5000/{p}",
                body="no links here", status=200, content_type="text/html",
            )
        crawler = HTMLCrawler("https://localhost:5000/", enforcer, max_pages=2, delay=0)
        assets = crawler.crawl()
        assert len(assets) == 2

    @responses_lib.activate
    def test_out_of_scope_link_is_never_requested(self, enforcer):
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/",
            body='<a href="https://evil.com/steal">steal</a>', status=200, content_type="text/html",
        )
        crawler = HTMLCrawler("https://localhost:5000/", enforcer, max_pages=10, delay=0)
        assets = crawler.crawl()
        assert len(assets) == 1
        assert not any(call.request.url.startswith("https://evil.com") for call in responses_lib.calls)

    @responses_lib.activate
    def test_no_response_is_skipped_gracefully(self, enforcer):
        # No `responses` registration -> requests raises ConnectionError -> safe_http_request returns None
        crawler = HTMLCrawler("https://localhost:5000/", enforcer, max_pages=10, delay=0)
        assets = crawler.crawl()
        assert assets == []

    @responses_lib.activate
    def test_redirect_stores_original_url_and_queues_destination_separately(self, enforcer):
        # This is the core architectural fix: a redirecting URL (e.g. an open
        # redirect test endpoint) must be stored as its OWN asset with its own
        # raw 302 status, not silently replaced by the destination page.
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/redirect",
            status=302, headers={"Location": "/dashboard"},
        )
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/dashboard",
            body="<p>you made it</p>", status=200, content_type="text/html",
        )
        crawler = HTMLCrawler("https://localhost:5000/redirect", enforcer, max_pages=10, delay=0)
        assets = crawler.crawl()

        assets_by_url = {a["url"]: a for a in assets}
        assert assets_by_url["https://localhost:5000/redirect"]["status_code"] == 302
        assert assets_by_url["https://localhost:5000/dashboard"]["status_code"] == 200

    @responses_lib.activate
    def test_redirect_with_query_params_preserved_in_asset(self, enforcer):
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/redirect",
            status=302, headers={"Location": "/dashboard"},
            match=[responses_lib.matchers.query_param_matcher({"next": "/dashboard"})],
        )
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/dashboard",
            body="ok", status=200, content_type="text/html",
        )
        crawler = HTMLCrawler("https://localhost:5000/redirect?next=/dashboard", enforcer, max_pages=10, delay=0)
        assets = crawler.crawl()

        urls = [a["url"] for a in assets]
        assert "https://localhost:5000/redirect?next=/dashboard" in urls

    @responses_lib.activate
    def test_redirect_without_location_header_stops_there(self, enforcer):
        responses_lib.add(responses_lib.GET, "https://localhost:5000/", status=302)
        crawler = HTMLCrawler("https://localhost:5000/", enforcer, max_pages=10, delay=0)
        assets = crawler.crawl()
        assert len(assets) == 1
        assert assets[0]["status_code"] == 302

    @responses_lib.activate
    def test_non_html_asset_records_no_links_found_key(self, enforcer):
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/data.json",
            body='{"a": 1}', status=200, content_type="application/json",
        )
        crawler = HTMLCrawler("https://localhost:5000/data.json", enforcer, max_pages=10, delay=0)
        assets = crawler.crawl()
        assert assets[0]["is_html"] is False
        assert "links_found" not in assets[0]

    @responses_lib.activate
    def test_already_visited_url_not_requested_twice(self, enforcer):
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/",
            body='<a href="/">home again</a>', status=200, content_type="text/html",
        )
        crawler = HTMLCrawler("https://localhost:5000/", enforcer, max_pages=10, delay=0)
        assets = crawler.crawl()
        assert len(assets) == 1
