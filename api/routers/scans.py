import os
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from fastapi.responses import FileResponse

from api.schemas import ScanCreateRequest, ScanResponse, VulnerabilityResponse
from database import delete_scan, get_all_scans, get_scan, get_vulnerabilities_for_scan, save_scan
from reporter import generate_html_report
from scan_runner import run_scan_pipeline

router = APIRouter(prefix="/scans", tags=["scans"])


def _build_roe_config(request: ScanCreateRequest) -> dict[str, Any]:
    parsed = urlparse(request.target_url)
    default_port = 443 if parsed.scheme == "https" else 80
    return {
        "allowed_domains": request.allowed_domains or ([parsed.hostname] if parsed.hostname else []),
        "allowed_cidrs": [],
        "allowed_ports": request.allowed_ports or [parsed.port or default_port],
        "excluded_paths": [],
        "allow_local_testing": request.allow_local_testing,
        "stealth_mode": request.stealth_mode,
        "proxy_url": "",
        "test_username": request.test_username,
        "test_password": request.test_password,
    }


@router.post("", response_model=ScanResponse, status_code=202, summary="Start a new scan")
def create_scan(request: ScanCreateRequest, background_tasks: BackgroundTasks) -> ScanResponse:
    """
    Creates the scan row immediately (status=pending) and runs the full
    crawl + 14-scanner pipeline in a background task. Poll GET /scans/{id}
    for status until it reaches "completed" or "failed".
    """
    scan_id = save_scan(request.target_url, status="pending")
    if scan_id is None:
        raise HTTPException(status_code=500, detail="Failed to create scan record.")

    roe_config = _build_roe_config(request)
    background_tasks.add_task(
        run_scan_pipeline,
        scan_id,
        request.target_url,
        roe_config,
        max_pages=request.max_pages,
        generate_report=True,
        open_browser=False,
    )

    record = get_scan(scan_id)
    assert record is not None
    return ScanResponse(**record)


@router.get("", response_model=list[ScanResponse], summary="List all scans")
def list_scans() -> list[ScanResponse]:
    return [ScanResponse(**record) for record in get_all_scans()]


@router.get("/{scan_id}", response_model=ScanResponse, summary="Get one scan")
def get_scan_by_id(scan_id: int) -> ScanResponse:
    record = get_scan(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")
    return ScanResponse(**record)


@router.delete("/{scan_id}", status_code=204, summary="Delete a scan and its findings")
def delete_scan_by_id(scan_id: int) -> None:
    if not delete_scan(scan_id):
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")


@router.get(
    "/{scan_id}/vulnerabilities",
    response_model=list[VulnerabilityResponse],
    summary="List findings for a scan",
)
def list_vulnerabilities(scan_id: int) -> list[VulnerabilityResponse]:
    if get_scan(scan_id) is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")
    return [VulnerabilityResponse(**record) for record in get_vulnerabilities_for_scan(scan_id)]


@router.get("/{scan_id}/report", summary="Download the HTML or PDF report for a scan")
def download_report(scan_id: int, format: str = Query(default="html", pattern="^(html|pdf)$")) -> FileResponse:
    record = get_scan(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")
    if record["status"] != "completed":
        raise HTTPException(status_code=409, detail=f"Scan {scan_id} is '{record['status']}', not completed yet.")

    html_path = generate_html_report(scan_id=scan_id, open_browser=False)
    if html_path is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")

    if format == "html":
        return FileResponse(html_path, media_type="text/html", filename=os.path.basename(html_path))

    pdf_path = html_path.replace(".html", ".pdf")
    if not os.path.exists(pdf_path):
        raise HTTPException(
            status_code=503,
            detail="PDF generation unavailable (wkhtmltopdf not installed on the server).",
        )
    return FileResponse(pdf_path, media_type="application/pdf", filename=os.path.basename(pdf_path))
