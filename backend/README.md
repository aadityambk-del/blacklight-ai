# BLACKLIGHT AI — Backend (FastAPI)

Server-side forensic engine. Exposes a single `/analyze` endpoint that the frontend
calls; it does PDF parsing, text extraction, **OCR for scanned documents**, deterministic
ID/arithmetic checks, and Error-Level Analysis, and returns a structured report.

The frontend works without this (it has an in-browser engine). The backend adds OCR for
scanned/image-only PDFs and server-side PDF-page rendering for ELA.

## Run locally

```bash
cd backend
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

Check it: open http://localhost:8000/health

For full OCR + PDF-page ELA you also need two system binaries:

- **Tesseract** — macOS `brew install tesseract` · Ubuntu `sudo apt install tesseract-ocr` · Windows: UB-Mannheim installer
- **Poppler** — macOS `brew install poppler` · Ubuntu `sudo apt install poppler-utils` · Windows: download poppler and add `bin` to PATH

Without them the server still runs; it just reports OCR/ELA-on-PDF as unavailable.
The included **Dockerfile** installs both automatically.

## Connect the frontend

Edit `config.js` in the site root:

```js
window.BLACKLIGHT_API = "http://localhost:8000";
```

Or open the site with `?api=http://localhost:8000`. When reachable, the console shows
**“Backend engine”**; if it can’t be reached it silently falls back to the in-browser engine.

## Run with Docker

```bash
cd backend
docker build -t blacklight-api .
docker run -p 8000:8000 blacklight-api
```

## Deploy free

- **Render / Railway:** new Web Service from the repo, root `backend/`, it detects the Dockerfile. Set the frontend’s `BLACKLIGHT_API` to the service URL.
- **Vercel:** create a project from the repository root. The root `pyproject.toml` points Vercel to `backend.app:app` and lists the Python dependencies.
- CORS is open (`*`) so a static frontend on any host can call it.

## API

`POST /analyze` — multipart form, field `file`. Returns the forensic report JSON
(hash, metadata, checks, findings, ELA, risk, graph, audit) consumed directly by the frontend.
`GET /health` — status and which optional features are active.

## Files

- `app.py` — FastAPI app, CORS, `/analyze` + `/health`
- `forensics.py` — the analysis engine (pure-Python core + optional OCR/ELA)
- `requirements.txt`, `Dockerfile`
