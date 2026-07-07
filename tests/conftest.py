import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from enforcer import ScopeEnforcer


@pytest.fixture
def enforcer():
    """A permissive ScopeEnforcer scoped to localhost:5000, matching main.py's roe_config."""
    return ScopeEnforcer({
        "allowed_domains": ["localhost", "127.0.0.1"],
        "allowed_cidrs": [],
        "allowed_ports": [5000],
        "excluded_paths": [],
        "allow_local_testing": True,
        "stealth_mode": False,
        "proxy_url": "",
    })


@pytest.fixture
def stealth_enforcer():
    """Same as `enforcer` but with stealth_mode on, for testing the evasion code path."""
    return ScopeEnforcer({
        "allowed_domains": ["localhost", "127.0.0.1"],
        "allowed_cidrs": [],
        "allowed_ports": [5000],
        "excluded_paths": [],
        "allow_local_testing": True,
        "stealth_mode": True,
        "proxy_url": "",
    })


@pytest.fixture
def local_target_client(tmp_path, monkeypatch):
    """
    Flask test client for local_target.py, isolated from the real repo's
    users.db/cert.pem by chdir-ing into a throwaway tmp directory (the app
    hardcodes relative paths like 'users.db').
    """
    monkeypatch.chdir(tmp_path)
    import local_target
    local_target.init_user_db()
    local_target.app.testing = True
    with local_target.app.test_client() as client:
        yield client
