from pydantic import BaseModel, Field


class ScanCreateRequest(BaseModel):
    target_url: str = Field(
        ...,
        description="Seed URL for the crawler, e.g. https://localhost:5000/",
        examples=["https://localhost:5000/"],
    )
    max_pages: int = Field(default=20, ge=1, le=200, description="Crawl page budget for the BFS crawler.")
    allowed_domains: list[str] | None = Field(
        default=None, description="ScopeEnforcer allowlist. Defaults to just the target URL's hostname."
    )
    allowed_ports: list[int] | None = Field(
        default=None, description="ScopeEnforcer allowlist. Defaults to just the target URL's port."
    )
    allow_local_testing: bool = Field(
        default=False,
        description="Allow scanning loopback/private-IP targets (required to scan local_target.py).",
    )
    stealth_mode: bool = Field(default=True, description="Randomize User-Agent and pace requests via evasion.py.")
    test_username: str | None = Field(default=None, description="Credentials for cookie/IDOR authenticated checks.")
    test_password: str | None = Field(default=None, description="Credentials for cookie/IDOR authenticated checks.")


class ScanResponse(BaseModel):
    id: int
    target_url: str
    start_time: str
    status: str
    vulnerability_count: int


class VulnerabilityResponse(BaseModel):
    id: int
    scan_id: int
    type: str
    severity: str
    url: str
    vulnerable_param: str
    payload_used: str
    description: str
    remediation: str
