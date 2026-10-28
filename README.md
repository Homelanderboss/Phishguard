# PhishGuard — URL Intelligence

A deployable educational phishing-URL pattern analyzer built with Flask, SQLite, HTML, and CSS.

## Features

- URL syntax validation and heuristic pattern checks
- Explainable risk score (0–100) and risk bands
- SQLite scan history and dashboard counts
- JSON API at `POST /api/scan`
- Health endpoint at `GET /health`
- Responsive dashboard
- Docker and Render deployment configuration

## Important limitations

This is a **heuristic educational demo**, not a production phishing reputation service. It does not visit submitted websites, download page content, or verify a domain against a live threat-intelligence database. Scores are not probabilities. False positives and false negatives are expected; a low score never proves a URL is safe.

The app saves submitted URLs to its scan history. Do not submit private URLs containing session tokens, reset codes, personal information, or other secrets. Add authentication and retention controls before using this with real users.

## Run locally

Python 3.10+ recommended.

```bash
python -m venv venv
# Windows PowerShell:
venv\Scripts\Activate.ps1
# macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000.

## Deploy on Render

1. Create a GitHub repository and upload these project files.
2. In Render, choose **New + → Blueprint** and connect the repository.
3. Render reads `render.yaml` and creates the web service.
4. Wait for deployment, then open the service URL. The `/health` endpoint should return `{"status":"ok","service":"PhishGuard"}`.

### Database persistence

The included Render config writes SQLite to the service filesystem. On hosts with ephemeral filesystems, the scan history can be lost when the service restarts or redeploys. For persistent history, attach a persistent disk and set `DATABASE_PATH` to a path on that disk, or migrate to managed PostgreSQL.

### Deploy with Docker

```bash
docker build -t phishguard .
docker run --rm -p 8080:8080 -e SECRET_KEY="replace-with-a-long-random-secret" phishguard
```

Then open http://localhost:8080.



## Suggested next improvements

- Integrate a reputable URL reputation API with safe handling of API keys.
- Add user authentication, per-user scan history, and retention controls.
- Train and evaluate an ML model on a properly licensed dataset.
- Add tests and rate limiting before public launch.
