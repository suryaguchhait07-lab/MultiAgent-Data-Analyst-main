from __future__ import annotations
import ipaddress, socket, ssl, re
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Any

SUSPICIOUS_WORDS = {
    "login", "verify", "account", "password", "secure", "update",
    "wallet", "payment", "banking", "confirm", "signin", "support"
}

def normalise_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Enter a website URL.")
    if len(raw) > 2048:
        raise ValueError("URL is too long.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not p.hostname:
        raise ValueError("The URL must contain a valid hostname.")
    if p.username or p.password:
        raise ValueError("URLs containing embedded usernames or passwords are not accepted.")
    if p.port and not (1 <= p.port <= 65535):
        raise ValueError("Invalid port.")
    return raw

def resolve_public_addresses(host: str) -> list[str]:
    # Reject IP literals and DNS answers that point to local/private infrastructure.
    try:
        ip = ipaddress.ip_address(host)
        addresses = [ip]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return []
        addresses = list({ipaddress.ip_address(info[4][0]) for info in infos})
    if not addresses:
        return []
    for ip in addresses:
        if not ip.is_global:
            raise ValueError("This scanner blocks private, local, reserved and non-public IP addresses.")
    return [str(x) for x in addresses]

def certificate_check(host: str, port: int = 443, timeout: float = 4.0) -> dict[str, Any]:
    addresses = resolve_public_addresses(host)
    if not addresses:
        return {"status": "unknown", "detail": "Could not resolve a public IP address."}
    context = ssl.create_default_context()
    last_error = None
    for address in addresses:
        try:
            # Connect to the resolved public IP while retaining hostname verification and SNI.
            raw = socket.create_connection((address, port), timeout=timeout)
            with raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    not_after = cert.get("notAfter")
                    expiry = None
                    days_left = None
                    if not_after:
                        expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days_left = (expiry_dt - datetime.now(timezone.utc)).days
                        expiry = expiry_dt.isoformat()
                    cipher = tls.cipher()
                    return {
                        "status": "valid",
                        "detail": "TLS handshake and hostname verification succeeded.",
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "expires_at": expiry,
                        "days_until_expiry": days_left,
                        "tls_version": tls.version(),
                        "cipher": cipher[0] if cipher else None,
                    }
        except Exception as exc:
            last_error = str(exc)
    return {"status": "invalid_or_unavailable", "detail": (last_error or "TLS check failed")[:240]}

def analyse_url(raw: str) -> dict[str, Any]:
    url = normalise_url(raw)
    p = urlparse(url)
    host = (p.hostname or "").lower()
    path = (p.path + "?" + p.query).lower()
    score = 0
    findings = []

    def add(points: int, title: str, detail: str):
        nonlocal score
        score += points
        findings.append({"points": points, "title": title, "detail": detail})

    if p.scheme == "http":
        add(15, "No HTTPS", "The URL uses HTTP. Traffic may not be encrypted.")
    if len(host) > 28:
        add(7, "Long hostname", "Long hostnames can be used deceptively; verify the registered domain.")
    if host.count(".") >= 3:
        add(8, "Many subdomain levels", "Several subdomain levels can make the real registered domain harder to notice.")
    if "xn--" in host:
        add(20, "Punycode hostname", "Internationalised hostname encoding can be used in lookalike domains.")
    if "-" in host:
        add(4, "Hyphen in hostname", "A hyphen is a weak signal only; many legitimate domains contain hyphens.")
    if re.search(r"\d+\.\d+\.\d+\.\d+", host):
        add(18, "IP address used as hostname", "A raw IP address is unusual for many public-facing services.")
    hits = sorted({w for w in SUSPICIOUS_WORDS if w in host or w in path})
    if hits:
        add(min(20, 4 * len(hits)), "Sensitive wording in URL", "Found URL terms: " + ", ".join(hits) + ". Legitimate websites may also use these words.")
    if len(url) > 100:
        add(5, "Unusually long URL", "Long URLs can obscure the destination.")
    if "@" in p.netloc:
        add(20, "At-sign in URL authority", "The URL authority contains an at-sign, which can confuse readers about the destination.")

    # Domain and TLS checks are performed only for public DNS destinations.
    addresses = []
    dns_status = "not_checked"
    try:
        addresses = resolve_public_addresses(host)
        dns_status = "resolved_public"
    except ValueError as exc:
        raise
    except Exception:
        dns_status = "lookup_failed"

    tls = {"status": "not_applicable", "detail": "TLS check is available for HTTPS URLs."}
    if p.scheme == "https":
        port = p.port or 443
        tls = certificate_check(host, port=port)
        if tls["status"] != "valid":
            add(25, "TLS validation failed or unavailable", tls.get("detail", "Certificate could not be verified."))
        elif tls.get("days_until_expiry") is not None and tls["days_until_expiry"] < 21:
            add(8, "Certificate expires soon", "The TLS certificate expires within 21 days.")

    score = min(100, score)
    category = "Low risk indicators" if score < 30 else ("Suspicious indicators" if score < 60 else "High risk indicators")
    return {
        "submitted_url": url,
        "hostname": host,
        "risk_score": score,
        "category": category,
        "findings": findings,
        "dns": {"status": dns_status, "public_addresses": addresses[:5]},
        "tls": tls,
        "limitations": [
            "This score is a heuristic screening aid, not proof that a website is safe or malicious.",
            "No webpage scripts are executed and no page content is downloaded.",
            "A valid HTTPS certificate does not establish that the website operator is trustworthy.",
            "A production AI classifier and licensed threat-intelligence feeds require separate configuration and evaluation."
        ]
    }
