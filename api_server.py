# ~/fyp1/api_server.py
import os
import re
import json
import uuid
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl

PROJECT_ROOT = Path.home() / "fyp1"
OUTPUT_BASE = PROJECT_ROOT / "scans" / "output"
def scan_dir(scan_id: str) -> Path:
    return OUTPUT_BASE / scan_id

app = FastAPI(title="AVAP Scan API")

# ----------------------------
# Models
# ----------------------------
class ScanStartReq(BaseModel):
    url: str
    mode: str  # "basic" or "deep"

def safe_slug(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"^https?://", "", s)
    s = re.sub(r"[^a-z0-9._-]+", "_", s)
    return s[:80].strip("_") or "target"

def normalize_url(url: str) -> str:
    url = url.strip()
    p = urlparse(url)

    scheme = (p.scheme or "https").lower()
    netloc = p.netloc.lower().strip()
    path = (p.path or "").rstrip("/")

    return f"{scheme}://{netloc}{path}" if path else f"{scheme}://{netloc}"


def now_iso():
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"

def write_status(scan_folder: Path, data: dict):
    scan_folder.mkdir(parents=True, exist_ok=True)
    data["updated_at"] = now_iso()
    (scan_folder / "status.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

def read_status(scan_dir: Path) -> dict:
    p = scan_dir / "status.json"
    if not p.exists():
        raise FileNotFoundError("status.json not found")
    return json.loads(p.read_text(encoding="utf-8"))

def scan_dir_from_id(scan_id: str) -> Path:
    return OUTPUT_BASE / scan_id

def find_recent_scan_by_url(input_url: str):
    target = normalize_url(input_url)

    if not OUTPUT_BASE.exists():
        return None

    matches = []

    for folder in OUTPUT_BASE.iterdir():
        if not folder.is_dir():
            continue

        status_file = folder / "status.json"
        if not status_file.exists():
            continue

        try:
            data = json.loads(status_file.read_text(encoding="utf-8"))
        except Exception:
            continue

        saved_normalized = data.get("normalized_url")
        if not saved_normalized and data.get("url"):
            saved_normalized = normalize_url(data["url"])

        if saved_normalized != target:
            continue

        matches.append(data)

    if not matches:
        return None

    def sort_key(x):
        return x.get("finished_at") or x.get("updated_at") or x.get("started_at") or ""

    matches.sort(key=sort_key, reverse=True)
    return matches[0]
# ----------------------------
# Background worker (simple)
# ----------------------------
def launch_scan(scan_id: str, url: str, mode: str):
    scan_dir = scan_dir_from_id(scan_id)

    # running
    write_status(scan_dir, {
        "scan_id": scan_id,
        "url": url,
        "normalized_url": normalize_url(url),
        "mode": mode,
        "status": "running",
        "phase": "pipeline",
        "started_at": now_iso(),
        "error": None
    })

    cmd = ["python3", str(PROJECT_ROOT / "run_pipeline.py"), url, mode, "--scan-id", scan_id]

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True
        )

        if proc.returncode != 0:
            write_status(scan_dir, {
                "scan_id": scan_id,
                "url": url,
                "normalized_url": normalize_url(url),
                "mode": mode,
                "status": "failed",
                "phase": "pipeline",
                "started_at": read_status(scan_dir).get("started_at"),
                "finished_at": now_iso(),
                "error": (proc.stderr[-1500:] or proc.stdout[-1500:] or "Unknown error")
            })
            return

        combined = scan_dir / "combined_report.json"
        if not combined.exists():
            write_status(scan_dir, {
                "scan_id": scan_id,
                "url": url,
                "normalized_url": normalize_url(url),
                "mode": mode,
                "status": "failed",
                "phase": "result",
                "started_at": read_status(scan_dir).get("started_at"),
                "finished_at": now_iso(),
                "error": "combined_report.json not found in expected scan folder. Ensure run_pipeline.py supports --scan-id."
            })
            return

        write_status(scan_dir, {
            "scan_id": scan_id,
            "url": url,
            "normalized_url": normalize_url(url),
            "mode": mode,
            "status": "completed",
            "phase": "done",
            "started_at": read_status(scan_dir).get("started_at"),
            "finished_at": now_iso(),
            "error": None
        })

    except Exception as e:
        write_status(scan_dir, {
            "scan_id": scan_id,
            "url": url,
            "normalized_url": normalize_url(url),
            "mode": mode,
            "status": "failed",
            "phase": "pipeline",
            "started_at": read_status(scan_dir).get("started_at"),
            "finished_at": now_iso(),
            "error": str(e)
        })
# ----------------------------
# API Endpoints
# ----------------------------
@app.post("/api/scans")
def start_scan(req: ScanStartReq):
    mode = req.mode.strip().lower()
    if mode not in ("basic", "deep"):
        raise HTTPException(status_code=400, detail="mode must be basic or deep")
  
    normalized = normalize_url(req.url)
    scan_id = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{safe_slug(normalized)}_{mode}_{uuid.uuid4().hex[:6]}"
    scan_dir = scan_dir_from_id(scan_id)

    write_status(scan_dir, {
        "scan_id": scan_id,
        "url": req.url,
        "normalized_url": normalized,
        "mode": mode,
        "status": "queued",
        "phase": "queued",
        "started_at": None,
        "error": None
        })

    # Fire-and-forget background process (simple approach)
    # This keeps FastAPI responsive.
    subprocess.Popen(
            [
                "python3", "-c",
                "from api_server import launch_scan; import sys; launch_scan(sys.argv[1], sys.argv[2], sys.argv[3])",
                scan_id, normalized, mode
            ],
            cwd=str(PROJECT_ROOT)
    )

    return {"scan_id": scan_id, "status": "queued"}

@app.get("/api/scans/recent")
def get_recent_scan(url: str):
    recent = find_recent_scan_by_url(url)

    if not recent:
        return {
            "found": False,
            "message": "No previous scan found for this URL"
        }

    return {
        "found": True,
        "scan_id": recent.get("scan_id"),
        "url": recent.get("url"),
        "normalized_url": recent.get("normalized_url"),
        "mode": recent.get("mode"),
        "status": recent.get("status"),
        "phase": recent.get("phase"),
        "started_at": recent.get("started_at"),
        "finished_at": recent.get("finished_at"),
        "updated_at": recent.get("updated_at")
    }



@app.get("/api/scans/{scan_id}/status")
def get_status(scan_id: str):
    scan_dir = scan_dir_from_id(scan_id)
    try:
        return read_status(scan_dir)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="scan_id not found")

@app.get("/api/scans/{scan_id}/result")
def get_result(scan_id: str):
    scan_dir = scan_dir_from_id(scan_id)
    combined = scan_dir / "combined_report.json"
    if not combined.exists():
        raise HTTPException(status_code=404, detail="result not ready")
    return json.loads(combined.read_text(encoding="utf-8"))

@app.get("/api/scans/{scan_id}/validated-result")
def get_validated_result(scan_id: str):
    scan_dir = scan_dir_from_id(scan_id)
    validated = scan_dir / "validated_report.json"
    if not validated.exists():
        raise HTTPException(status_code=404, detail="validated result not ready")
    return json.loads(validated.read_text(encoding="utf-8"))

@app.get("/api/scans/{scan_id}/metrics")
def get_metrics(scan_id: str):
    p = scan_dir(scan_id) / "validation_metrics.json"
    if not p.exists():
        raise HTTPException(status_code=404, detail="metrics not ready")
    return json.loads(p.read_text(encoding="utf-8"))
                                                       
