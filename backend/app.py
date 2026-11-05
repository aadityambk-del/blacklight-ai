"""
BLACKLIGHT AI — FastAPI backend.
Run:  uvicorn app:app --reload --port 8000
Then point the frontend at it:  config.js -> window.BLACKLIGHT_API = "http://localhost:8000"
(or open the site with ?api=http://localhost:8000)
"""
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

if __package__:
    from . import forensics
else:
    import forensics

app = FastAPI(title="BLACKLIGHT AI — Document Forensics API", version="1.0")

# allow the static frontend (any origin) to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=False,
    allow_methods=["*"], allow_headers=["*"],
)

_SEQ = {"n": 0}
MAX_BYTES = 25 * 1024 * 1024  # 25 MB


@app.get("/")
def root():
    return {
        "name": "BLACKLIGHT AI — Document Forensics API",
        "endpoints": {"POST /analyze": "multipart file -> forensic report JSON", "GET /health": "status"},
        "capabilities": {
            "pdf_metadata": forensics.HAS_PYPDF,
            "ela": forensics.HAS_PIL,
            "ocr": forensics.HAS_OCR,
            "pdf_page_render": forensics.HAS_PDF2IMG,
        },
    }


@app.get("/health")
def health():
    return {"status": "ok", "ocr": forensics.HAS_OCR, "pdf_render": forensics.HAS_PDF2IMG}


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    data = await file.read()
    if not data:
        raise HTTPException(400, "Empty file")
    if len(data) > MAX_BYTES:
        raise HTTPException(413, "File too large (max 25 MB)")
    _SEQ["n"] += 1
    try:
        report = forensics.analyze(file.filename or "document", file.content_type or "", data, _SEQ["n"])
    except Exception as e:
        raise HTTPException(500, "Analysis failed: %s" % e)
    return JSONResponse(report)
