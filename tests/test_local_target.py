import sqlite3
import pytest


class TestIndexRoute:
    def test_homepage_lists_vulnerable_endpoints(self, local_target_client):
        resp = local_target_client.get("/")
        assert resp.status_code == 200
        assert b"/login" in resp.data
        assert b"/view-doc" in resp.data
        assert b"/redirect" in resp.data


class TestOpenRedirectRoute:
    def test_redirects_to_supplied_url(self, local_target_client):
        resp = local_target_client.get("/redirect?next=https://evil.com", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["Location"] == "https://evil.com"

    def test_url_param_also_accepted(self, local_target_client):
        resp = local_target_client.get("/redirect?url=https://evil.com", follow_redirects=False)
        assert resp.status_code == 302

    def test_missing_param_returns_message(self, local_target_client):
        resp = local_target_client.get("/redirect")
        assert b"Missing" in resp.data

    def test_crlf_payload_raises_due_to_invalid_header_value(self, local_target_client):
        # Modern Werkzeug rejects raw CR/LF in header values, so this
        # particular classic payload does NOT actually achieve header
        # injection against this Flask version -- it 500s instead.
        with pytest.raises(ValueError):
            local_target_client.get("/redirect?next=%0d%0aLocation: https://evil.com")


class TestParseXmlRoute:
    def test_xxe_reads_arbitrary_local_file(self, local_target_client, tmp_path):
        secret_file = tmp_path.parent / f"xxe_secret_{tmp_path.name}.txt"
        secret_file.write_text("TOP-SECRET-CONTENTS")
        try:
            payload = f'''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{secret_file}">]>
<data>&xxe;</data>'''
            resp = local_target_client.post("/parse-xml", data=payload, content_type="application/xml")
            assert b"TOP-SECRET-CONTENTS" in resp.data
        finally:
            secret_file.unlink()

    def test_well_formed_xml_returns_text_content(self, local_target_client):
        resp = local_target_client.post("/parse-xml", data="<data>Hello</data>", content_type="application/xml")
        assert resp.data == b"Hello"

    def test_malformed_xml_returns_error_text_not_500(self, local_target_client):
        resp = local_target_client.post("/parse-xml", data="<data>", content_type="application/xml")
        assert resp.status_code == 200


class TestApiUserDataRoute:
    def test_reflects_arbitrary_origin_with_credentials(self, local_target_client):
        resp = local_target_client.get("/api/user-data", headers={"Origin": "https://evil.com"})
        assert resp.headers["Access-Control-Allow-Origin"] == "https://evil.com"
        assert resp.headers["Access-Control-Allow-Credentials"] == "true"

    def test_no_origin_header_no_cors_headers_set(self, local_target_client):
        resp = local_target_client.get("/api/user-data")
        assert "Access-Control-Allow-Origin" not in resp.headers


class TestFetchDataRoute:
    def test_ssrf_fetches_supplied_url(self, local_target_client, monkeypatch):
        import local_target

        class FakeResponse:
            text = "fetched-body-content"

        captured = {}

        def fake_get(url, verify, timeout):
            captured["url"] = url
            return FakeResponse()

        monkeypatch.setattr(local_target.requests, "get", fake_get)
        resp = local_target_client.get("/fetch-data?url=https://internal.local/secrets")
        assert captured["url"] == "https://internal.local/secrets"
        assert resp.data == b"fetched-body-content"


class TestViewDocRoute:
    def test_reads_file_in_cwd(self, local_target_client, tmp_path):
        (tmp_path / "welcome.txt").write_text("hello from welcome")
        resp = local_target_client.get("/view-doc?filename=welcome.txt")
        assert b"hello from welcome" in resp.data

    def test_path_traversal_reads_file_outside_cwd(self, local_target_client, tmp_path):
        outside_file = tmp_path.parent / f"traversal_secret_{tmp_path.name}.txt"
        outside_file.write_text("ESCAPED-THE-SANDBOX")
        try:
            resp = local_target_client.get(f"/view-doc?filename=../{outside_file.name}")
            assert b"ESCAPED-THE-SANDBOX" in resp.data
        finally:
            outside_file.unlink()

    def test_missing_file_returns_error_text(self, local_target_client):
        resp = local_target_client.get("/view-doc?filename=does_not_exist.txt")
        assert resp.status_code == 200
        assert b"No such file" in resp.data


class TestLoginAndProfileFlow:
    def test_login_form_rendered_on_get(self, local_target_client):
        resp = local_target_client.get("/login")
        assert b"Login" in resp.data

    def test_invalid_credentials_rejected(self, local_target_client):
        resp = local_target_client.post("/login", data={"username": "admin", "password": "wrong"})
        assert b"Invalid credentials" in resp.data

    def test_valid_login_sets_insecure_session_cookie_and_redirects(self, local_target_client):
        resp = local_target_client.post(
            "/login", data={"username": "admin", "password": "admin123"}, follow_redirects=False,
        )
        assert resp.status_code == 302
        assert resp.headers["Location"] == "/profile?user_id=1"

        set_cookie_headers = resp.headers.get_all("Set-Cookie")
        session_id_cookie = next(c for c in set_cookie_headers if c.startswith("session_id="))
        assert "Secure" not in session_id_cookie
        assert "HttpOnly" not in session_id_cookie
        assert "SameSite=None" in session_id_cookie

    def test_profile_requires_login(self, local_target_client):
        resp = local_target_client.get("/profile?user_id=1")
        assert b"Access Denied" in resp.data

    def test_idor_logged_in_user_can_view_other_profile(self, local_target_client):
        local_target_client.post("/login", data={"username": "admin", "password": "admin123"})
        own_profile = local_target_client.get("/profile?user_id=1")
        assert b"admin" in own_profile.data

        other_profile = local_target_client.get("/profile?user_id=2")
        assert b"user1" in other_profile.data


class TestUserSqliRoute:
    def test_valid_id_returns_username(self, local_target_client):
        resp = local_target_client.get("/user?id=1")
        assert resp.data == b"admin"

    def test_unknown_id_returns_not_found(self, local_target_client):
        resp = local_target_client.get("/user?id=999")
        assert b"User not found" in resp.data

    def test_sqli_payload_leaks_raw_database_error(self, local_target_client):
        resp = local_target_client.get("/user?id=1'")
        # This is the exact raw sqlite3 error the SQLiScanner's error_keywords
        # list is designed to catch ("unrecognized token").
        assert b"unrecognized token" in resp.data.lower()


class TestMiscRoutes:
    def test_search_reflects_query_unescaped(self, local_target_client):
        resp = local_target_client.get("/search?query=<b>hi</b>")
        assert b"<b>hi</b>" in resp.data

    def test_env_file_exposes_fake_secrets(self, local_target_client):
        resp = local_target_client.get("/.env")
        assert b"DB_PASSWORD" in resp.data

    def test_admin_panel_publicly_accessible(self, local_target_client):
        resp = local_target_client.get("/admin")
        assert b"Administrator" in resp.data

    def test_transfer_form_and_submission(self, local_target_client):
        get_resp = local_target_client.get("/transfer")
        assert b"Transfer Money" in get_resp.data
        post_resp = local_target_client.post("/transfer", data={"amount": "500"})
        assert b"500" in post_resp.data

    def test_ping_form_rendered(self, local_target_client):
        resp = local_target_client.get("/ping")
        assert b"Ping a Host" in resp.data

    def test_ping_command_injection(self, local_target_client, monkeypatch):
        import local_target

        captured = {}

        class FakeCompletedProcess:
            stdout = "PING_MARKER_OUTPUT"

        def fake_run(command, shell, capture_output, text):
            captured["command"] = command
            return FakeCompletedProcess()

        monkeypatch.setattr(local_target.subprocess, "run", fake_run)
        resp = local_target_client.post("/ping", data={"target": "127.0.0.1 & echo INJECTED"})
        assert "127.0.0.1 & echo INJECTED" in captured["command"]
        assert b"PING_MARKER_OUTPUT" in resp.data


class TestUserDbInit:
    def test_init_user_db_creates_default_users(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        import local_target
        local_target.init_user_db()

        conn = sqlite3.connect(tmp_path / "users.db")
        c = conn.cursor()
        c.execute("SELECT id, username FROM users ORDER BY id")
        rows = c.fetchall()
        conn.close()
        assert rows == [(1, "admin"), (2, "user1")]

    def test_init_user_db_is_idempotent(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        import local_target
        local_target.init_user_db()
        local_target.init_user_db()  # must not raise or duplicate rows

        conn = sqlite3.connect(tmp_path / "users.db")
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM users")
        count = c.fetchone()[0]
        conn.close()
        assert count == 2
