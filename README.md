# BLACKLIGHT AI

> **Illuminate the evidence hidden in plain sight.**
> AI-powered document forensics & contextual intelligence — OCR reads the words; BLACKLIGHT checks if they are true.

A web-based **forensic console** that goes beyond OCR and field validation to investigate submitted documents: it reads structure, examines visual characteristics, correlates information **across** related documents, and produces an evidence-backed, sealed investigation dossier.

Built for the **DataOps Innovation Hackathon** by **Team Table For Two** (Aaradhya Jain · Aaditya Kore).

---

## What it does

Drop a **real** PDF or image and the engine analyses it live, entirely in your browser — nothing is uploaded to any server.

- **Real SHA-256 seal** — a genuine hash of the actual file, taken at ingest (chain of custody).
- **PDF metadata forensics** — reads the real Producer, Creator, Creation/Modification dates, hidden incremental-save count, font families, embedded JavaScript and encryption straight from the file bytes. Flags consumer editors on "scanned" documents, post-creation edits and hidden revisions.
- **Text extraction** — via pdf.js, then **deterministic checks on the real text**: PAN format, **Aadhaar Verhoeff checksum**, IFSC format, future-date logic, and salary arithmetic (gross − deductions = net).
- **Error-Level Analysis** — genuine ELA computed with canvas on images and rendered PDF pages, shown as a heatmap beside the original.
- **Entity graph** — extracted fields become nodes; a link turns red when a field fails a check or the source looks edited. Hover to isolate.
- **Evidence ladder** — every finding sits on Observed → Inconsistent → Possible manipulation → Needs human verification. "Fraud" is never asserted; a human decides.
- **Investigation dossier + audit trail** — generated from the real findings, mapped to the required report sections, with a time-stamped log.
- **Public overview** — a landing page that launches into the console.
- **Load sample analysis** — an optional, clearly-marked sample for a quick populated view without uploading a file.

## Architecture

Full-stack, but the frontend runs on its own. The in-browser engine does the full
analysis client-side; the optional **FastAPI backend** adds OCR for scanned documents
and server-side PDF-page rendering. The frontend calls the backend when it's configured
and **falls back to the in-browser engine** when it isn't reachable.

```
Browser (static site)  ──POST /analyze──▶  FastAPI backend (optional)
  in-browser engine  ◀──fallback if offline──┘
```

## Run the frontend

No build step, no dependencies.

```bash
cd blacklight-ai
python3 -m http.server 8000      # then open http://localhost:8000
```

> Serve over `http://localhost` or HTTPS rather than opening `index.html` as a `file://` —
> the SHA-256 seal uses the browser's Web Crypto API, which needs a secure context.

## Run the backend (optional)

```bash
cd backend
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

Then set the frontend to use it — edit `config.js`:

```js
window.BLACKLIGHT_API = "http://localhost:8000";
```

See `backend/README.md` for OCR/Poppler setup and Docker. When connected, the console
header reads **“Backend engine”**.

## Deploy (free)

- **Frontend:** drag the folder onto Netlify Drop, or push to GitHub and enable Pages.
- **Backend:** Render/Railway Web Service from `backend/` (Dockerfile included), then point `config.js` at its URL.

## Project structure

```
blacklight-ai/
├── index.html          # frontend shell
├── config.js           # set BLACKLIGHT_API to use the backend (blank = in-browser)
├── css/styles.css      # theme tokens + styles
├── js/app.js           # engine, views, canvas animations, router
├── backend/
│   ├── app.py          # FastAPI app (/analyze, /health)
│   ├── forensics.py    # analysis engine (PDF, OCR, ELA, checks)
│   ├── requirements.txt
│   ├── Dockerfile
│   └── README.md
├── README.md
└── LICENSE
```

## Tech

**Frontend:** vanilla JS · [pdf.js](https://mozilla.github.io/pdf.js/) · HTML Canvas (ELA + entity graph) · Web Crypto (SHA-256).
**Backend:** FastAPI · pypdf · Pillow (ELA) · pytesseract (OCR) · pdf2image. The same forensic
logic (metadata, Verhoeff checksum, arithmetic/date checks, ELA) exists on both sides.

## Capability status (honest)

| Implemented (real) | Partial | Planned |
|---|---|---|
| SHA-256 chain of custody | ELA scoring threshold tuning | OCR for scanned PDFs (backend has it; add to browser) |
| PDF metadata & font forensics | Name/address extraction (heuristic) | Handwriting recognition |
| Document classification (type detection) | Signature placement analysis | Multilingual documents |
| PAN / **Aadhaar-Verhoeff** / IFSC / date / arithmetic checks | Confidence calibration | AI-generated-document detection |
| **Cross-document entity graph + conflict detection** | — | Retest / change comparison |
| Error-Level Analysis (images + PDF pages) | | |
| Evidence ladder, audit trail, **downloadable PDF dossier** | | |

**Honesty notes:** the SHA-256, PDF metadata, text-based checks and ELA are computed from the file you drop — they are real. Text-based checks need an embedded text layer; for scanned image-only PDFs the engine says so (OCR is on the roadmap). ELA is a heuristic and is reported as an observation, never a verdict. A "Load sample analysis" button provides a clearly-labelled demo case for presentations.

## Standards referenced

ISO/IEC 27037 · 27041 · 27042 · NIST SP 800-86 · OWASP ML Top 10 — cited as inspiration, not a claim of formal compliance.

## AI assistance

The application code was generated with AI assistance (Claude) and then reviewed, tested and integrated by the team. The team's contribution: problem selection, product design, case/data modelling, feature decisions, testing and the demo. Starter scaffold is permitted under the hackathon rules.

## Team

**Table For Two** — Aaradhya Jain · Aaditya Kore
