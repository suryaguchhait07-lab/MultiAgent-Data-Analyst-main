# MASTER MIND — Complete Hackathon MVP

A runnable full-stack starter for an intelligent phishing and malicious-website detection platform.

## Included
- Responsive web dashboard.
- FastAPI backend and JSON API.
- URL normalisation and basic explainable phishing indicators.
- Public DNS resolution checks.
- Real TLS handshake with certificate/hostname verification for HTTPS hosts.
- SQLite storage for scan history and community threat reports.
- Community reports are saved as `pending` for moderator review.
- Dockerfile and API health endpoint.

## Run locally
Requirements: Python 3.10+.

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000

API documentation: http://127.0.0.1:8000/docs

## Docker
```bash
docker build -t master-mind .
docker run --rm -p 8000:8000 master-mind
```

## API endpoints
- `GET /api/health` — service health
- `POST /api/scan` — analyse a URL
  ```json
  {"url":"https://example.com"}
  ```
- `GET /api/stats` — basic platform activity counts
- `POST /api/reports` — submit a community report
  ```json
  {"url":"https://example.com","reason":"This page impersonates an organisation."}
  ```

## Important scope and limitations
This is a working hackathon MVP, not a production-grade security product:
- The risk score is based on explainable URL heuristics, not a trained AI model.
- No webpage HTML or scripts are fetched or executed.
- TLS validation and public DNS resolution are performed server-side.
- Domain reputation APIs (for example VirusTotal or Google Safe Browsing), Certificate Transparency monitoring, a trained/evaluated ML model, admin authentication and moderation UI are not configured.
- Website security-header assessment requires safe HTTP fetching and additional hardened isolation; it is intentionally not implemented in this MVP.
- TLS/DNS network checks need outbound network access from the host.
- A valid certificate, HTTPS, or a low heuristic score does not prove a website is safe.

## Security notes
The scanner rejects non-public IP destinations, resolves hostnames before checks, connects to the resolved public IP for TLS while retaining SNI and hostname verification, and does not follow redirects or fetch page content. This reduces risk but does not replace a professionally reviewed sandbox, egress firewall, rate limiting, abuse controls and DNS-rebinding-resistant network architecture. Do not expose this prototype publicly without additional security review.

## Suggested next production steps
1. Add rate limiting, authentication, audit logs and admin moderation.
2. Integrate licensed threat-intelligence feeds with privacy review and API-key management.
3. Train and evaluate an ML model on recent, correctly labelled data; publish precision, recall and false-positive rates.
4. Build an isolated fetch service for redirect and header analysis with strict egress controls.
5. Add Certificate Transparency monitoring and alerting.
6. Add automated tests, CI/CD, monitoring, backups and deployment hardening.
