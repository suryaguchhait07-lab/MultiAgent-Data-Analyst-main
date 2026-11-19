from __future__ import annotations
import os, sqlite3, time
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, HttpUrl
from .scanner import analyse_url, normalise_url

BASE = Path(__file__).resolve().parent
DB_PATH = os.getenv("DATABASE_PATH", str(BASE.parent / "master_mind.db"))
app = FastAPI(title="Master Mind Web Threat Intelligence", version="1.0.0",
              description="Hackathon MVP for phishing indicators, DNS and TLS checks, and community reports.")
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            reason TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending'
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            category TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )""")
init_db()

class ScanRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)

class ReportRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)
    reason: str = Field(min_length=5, max_length=1000)

@app.get("/", response_class=HTMLResponse)
def home():
    return (BASE / "static" / "index.html").read_text(encoding="utf-8")

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "Master Mind", "version": "1.0.0"}

@app.post("/api/scan")
def scan(payload: ScanRequest, request: Request):
    try:
        result = analyse_url(payload.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        raise HTTPException(status_code=422, detail="The URL could not be analysed. Check the hostname and try again.")
    with db() as con:
        con.execute("INSERT INTO scans(url, score, category) VALUES(?,?,?)",
                    (result["submitted_url"], result["risk_score"], result["category"]))
    return result

@app.post("/api/reports")
def submit_report(payload: ReportRequest):
    try:
        url = normalise_url(payload.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    with db() as con:
        cur = con.execute("INSERT INTO reports(url, reason) VALUES(?,?)", (url, payload.reason.strip()))
        report_id = cur.lastrowid
    return {"message": "Report received for moderation.", "report_id": report_id, "status": "pending"}

@app.get("/api/stats")
def stats():
    with db() as con:
        scans = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        reports = con.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        pending = con.execute("SELECT COUNT(*) FROM reports WHERE status='pending'").fetchone()[0]
        high = con.execute("SELECT COUNT(*) FROM scans WHERE score >= 60").fetchone()[0]
    return {"total_scans": scans, "community_reports": reports, "pending_reports": pending,
            "high_indicator_scans": high}
