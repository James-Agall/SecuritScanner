from typing import Any

from database import init_db, save_scan
from scan_runner import run_scan_pipeline

if __name__ == "__main__":
    init_db()
    scan_id = save_scan("https://localhost:5000", status="pending")
    assert scan_id is not None

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

    run_scan_pipeline(scan_id, "https://localhost:5000/", roe_config, max_pages=20, delay=0.1)
