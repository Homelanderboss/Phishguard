# app.py
import os
import re
import sqlite3
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-this-secret")

DB_PATH = os.environ.get("DATABASE_PATH", "/tmp/phishguard.db")

# ... your rest of the app code ...
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.environ.get("DATABASE_PATH", "/tmp/phishguard.db")
)

MAX_URL_LENGTH = 2048


SUSPICIOUS_TERMS = {
    "account": 4,
    "verify": 6,
    "verification": 6,
    "login": 3,
    "signin": 3,
    "password": 5,
    "secure": 2,
    "update": 3,
    "wallet": 5,
    "billing": 3,
    "payment": 3,
    "confirm": 4,
    "recover": 4,
    "webscr": 8,
    "credential": 7,
    "token": 2,
}

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "ow.ly",
    "shorturl.at",
    "buff.ly",
    "rebrand.ly",
    "rb.gy",
}

BRAND_TERMS = {
    "paypal",
    "apple",
    "google",
    "microsoft",
    "amazon",
    "facebook",
    "instagram",
    "netflix",
    "whatsapp",
    "bank",
    "outlook",
}


def init_db():
    folder = os.path.dirname(DB_PATH)

    if folder:
        os.makedirs(folder, exist_ok=True)

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                hostname TEXT,
                verdict TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                indicators TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()


def analyze_url(raw_url):
    """
    Analyze URL text without visiting the destination.
    """
    url = (raw_url or "").strip()
    indicators = []
    score = 0

    if not url:
        return {
            "valid": False,
            "error": "Enter a URL to analyze."
        }

    if len(url) > MAX_URL_LENGTH:
        return {
            "valid": False,
            "error": f"URL is too long (maximum {MAX_URL_LENGTH} characters)."
        }

    candidate = (
        url
        if re.match(r"^https?://", url, re.I)
        else "https://" + url
    )

    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname
        _ = parsed.port

    except ValueError:
        return {
            "valid": False,
            "error": "That URL appears malformed. Check the domain and port."
        }

    if parsed.scheme.lower() not in ("http", "https") or not hostname:
        return {
            "valid": False,
            "error": "Enter a valid HTTP or HTTPS URL with a hostname."
        }

    if parsed.username or parsed.password:
        score += 25
        indicators.append(
            "URL contains embedded username/password fields."
        )

    hostname = hostname.lower().rstrip(".")

    if not hostname or (
        "." not in hostname and hostname != "localhost"
    ):
        score += 10
        indicators.append(
            "Hostname is not a typical fully qualified domain."
        )

    try:
        ipaddress.ip_address(hostname)
        score += 25
        indicators.append(
            "Destination uses an IP address instead of a domain name."
        )
    except ValueError:
        pass

    if parsed.scheme.lower() == "http":
        score += 8
        indicators.append(
            "Uses HTTP rather than HTTPS. "
            "This is a weakness, not proof of phishing."
        )

    if len(url) > 120:
        score += 8
        indicators.append("Unusually long URL.")

    if len(hostname) > 45:
        score += 8
        indicators.append("Unusually long hostname.")

    if hostname.count("-") >= 3:
        score += 8
        indicators.append("Hostname contains several hyphens.")

    if hostname.count(".") >= 4:
        score += 8
        indicators.append("Many hostname labels/subdomains.")

    if "@" in parsed.netloc:
        score += 18
        indicators.append(
            "Contains '@' in the authority section, "
            "which can obscure the actual host."
        )

    if "%" in parsed.netloc:
        score += 8
        indicators.append(
            "Hostname/authority contains percent-encoding."
        )

    if hostname in SHORTENERS:
        score += 12
        indicators.append(
            "Uses a URL-shortening service that hides the final destination."
        )

    combined = (
        hostname + " " + parsed.path + " " + parsed.query
    ).lower()

    matched = []

    for term, weight in SUSPICIOUS_TERMS.items():
        pattern = rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])"

        if re.search(pattern, combined):
            score += weight
            matched.append(term)

    if matched:
        indicators.append(
            "Contains potentially sensitive terms: "
            + ", ".join(matched[:8])
            + "."
        )

    brand_hits = [
        brand for brand in BRAND_TERMS if brand in hostname
    ]

    if brand_hits and any(ch.isdigit() for ch in hostname):
        score += 8
        indicators.append(
            "Hostname combines a brand-related term with digits; "
            "verify the domain carefully."
        )

    score = min(100, score)

    if score >= 55:
        verdict = "High risk"
        level = "high"
    elif score >= 25:
        verdict = "Suspicious"
        level = "medium"
    else:
        verdict = "Lower risk"
        level = "low"

    if not indicators:
        indicators.append(
            "No obvious red flags were found by these basic URL-pattern checks."
        )

    return {
        "valid": True,
        "url": candidate,
        "hostname": hostname,
        "risk_score": score,
        "verdict": verdict,
        "level": level,
        "indicators": indicators,
        "created_at": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ),
        "disclaimer": (
            "Heuristic result only. A low score does not prove a site is safe."
        ),
    }

class check_url_reputation:
    def __init__(self):
        pass

    def method(self):
        raise NotImplementedError

    def another_method(self):
        raise NotImplementedError

    def yet_another_method(self):
        raise NotImplementedError


def scan_url(raw_url):
    """
    Run heuristic analysis and, when configured, threat-intelligence checks.
    Shared by the web dashboard and JSON API.
    """
    result = analyze_url(raw_url)

    if not result.get("valid"):
        return result

    # Check known unsafe URLs without visiting the submitted destination.
    try:
        reputation = check_url_reputation(result["url"])

    except Exception:
        # An unexpected integration error must not crash the scanner.
        reputation = {
            "available": False,
            "unsafe": None,
            "message": "Threat-intelligence lookup failed unexpectedly.",
            "threats": [],
        }

    result["reputation"] = reputation

    if reputation.get("unsafe") is True:
        result["verdict"] = "Known unsafe URL"
        result["level"] = "high"
        result["risk_score"] = max(
            result["risk_score"], 90
        )

        result["disclaimer"] = (
            "A threat-intelligence service reported this URL as unsafe. "
            "Do not visit it."
        )

        result["indicators"].append(
            "Threat intelligence: " + reputation["message"]
        )

        for threat in reputation.get("threats", []):
            result["indicators"].append(
                "Threat category: " + threat
            )

    return result


def save_scan(result):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO scans (
                url,
                hostname,
                verdict,
                risk_score,
                indicators,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                result["url"],
                result["hostname"],
                result["verdict"],
                result["risk_score"],
                "\n".join(result["indicators"]),
                result["created_at"],
            ),
        )
        conn.commit()


def get_history(limit=100):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        rows = conn.execute(
            """
            SELECT
                id,
                url,
                hostname,
                verdict,
                risk_score,
                indicators,
                created_at
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None

    if request.method == "POST":
        result = scan_url(
            request.form.get("url", "")
        )

        if result.get("valid"):
            save_scan(result)
        else:
            error = result.get(
                "error", "Unable to analyze this URL."
            )
            result = None

    with sqlite3.connect(DB_PATH) as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM scans"
        ).fetchone()[0]

        suspicious = conn.execute(
            """
            SELECT COUNT(*)
            FROM scans
            WHERE risk_score >= 25 AND risk_score < 55
            """
        ).fetchone()[0]

        high = conn.execute(
            """
            SELECT COUNT(*)
            FROM scans
            WHERE risk_score >= 55
            """
        ).fetchone()[0]

    stats = {
        "total": total,
        "suspicious": suspicious,
        "high": high,
    }

    history_items = get_history(5)

    return render_template(
        "index.html",
        result=result,
        error=error,
        stats=stats,
        history=history_items,
    )


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}

    result = scan_url(data.get("url", ""))

    if not result.get("valid"):
        return jsonify(result), 400

    save_scan(result)

    return jsonify(result)


@app.route("/history")
def history():
    return render_template(
        "history.html",
        history=get_history(100),
    )


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "PhishGuard",
    })


@app.route("/clear-history", methods=["POST"])
def clear_history():
    token = request.form.get("admin_token", "")
    expected = os.environ.get("ADMIN_TOKEN")

    if not expected or token != expected:
        flash(
            "History clearing is disabled unless ADMIN_TOKEN "
            "is configured and supplied.",
            "error",
        )
        return redirect(url_for("history"))

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM scans")
        conn.commit()

    flash("Scan history cleared.", "success")

    return redirect(url_for("history"))


init_db()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
    )
