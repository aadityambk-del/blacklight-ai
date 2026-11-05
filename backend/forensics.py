"""
BLACKLIGHT AI — forensic analysis engine (server-side).
Real document forensics: SHA-256, PDF metadata, text extraction, OCR (optional),
deterministic ID/arithmetic checks, and Error-Level Analysis.
"""
import io, re, hashlib, base64, datetime

# ---- optional heavy deps (graceful if missing) ----
try:
    from pypdf import PdfReader
    HAS_PYPDF = True
except Exception:
    HAS_PYPDF = False
try:
    from PIL import Image, ImageChops, ImageStat
    HAS_PIL = True
except Exception:
    HAS_PIL = False
try:
    import pytesseract
    HAS_OCR = True
except Exception:
    HAS_OCR = False
try:
    from pdf2image import convert_from_bytes
    HAS_PDF2IMG = True
except Exception:
    HAS_PDF2IMG = False

EDITOR = re.compile(r"ilovepdf|pdfescape|photoshop|gimp|canva|smallpdf|sejda|foxit phantom|microsoft.*word|libreoffice|pdf24|nitro|wps", re.I)

# ---------- Verhoeff (real Aadhaar checksum) ----------
_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
      [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
      [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,9,1,6,7,3,2,4],[8,9,1,6,0,4,3,5,2,7],
      [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]

def verhoeff(num: str) -> bool:
    if not re.fullmatch(r"\d{12}", num or ""):
        return False
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0

# ---------- helpers ----------
def _hex_to_str(h):
    try:
        return bytes.fromhex(h).decode("utf-16-be", "ignore").replace("\x00", "").strip()
    except Exception:
        return None

def _dec_date(s):
    if not s:
        return None
    m = re.match(r"(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?(\d{2})?", s)
    if not m:
        return None
    try:
        return datetime.datetime(int(m[1]), int(m[2] or 1), int(m[3] or 1),
                                 int(m[4] or 0), int(m[5] or 0), int(m[6] or 0))
    except Exception:
        return None

def _fmt_date(d):
    return d.strftime("%d %b %Y") if d else None

# ---------- raw PDF metadata (library-free, from bytes) ----------
def raw_pdf_meta(data: bytes):
    s = data.decode("latin1", "ignore")
    def lit(key):
        m = re.search(r"/%s\s*\(((?:[^()\\]|\\.)*)\)" % key, s)
        if m:
            return re.sub(r"\\([()\\])", r"\1", m.group(1)).strip()
        h = re.search(r"/%s\s*<([0-9A-Fa-f]+)>" % key, s)
        if h:
            return _hex_to_str(h.group(1))
        return None
    cd = re.search(r"/CreationDate\s*\(D:(\d{8,14})", s)
    md = re.search(r"/ModDate\s*\(D:(\d{8,14})", s)
    fonts = sorted({re.sub(r"^[A-Z]{6}\+", "", x.split("/")[-1])
                    for x in re.findall(r"/BaseFont\s*/([A-Za-z0-9+\-,.]+)", s)})
    return {
        "producer": lit("Producer"), "creator": lit("Creator"),
        "created": cd.group(1) if cd else None, "modified": md.group(1) if md else None,
        "eof": len(re.findall(r"%%EOF", s)), "fonts": fonts,
        "hasJS": bool(re.search(r"/JavaScript|/JS[\s>/]", s)),
        "acro": "/AcroForm" in s, "enc": bool(re.search(r"/Encrypt[\s/]", s)),
    }

# ---------- text extraction (+ optional OCR) ----------
def extract_text(data: bytes):
    text, ocr_used = "", False
    if HAS_PYPDF:
        try:
            r = PdfReader(io.BytesIO(data))
            text = " ".join((pg.extract_text() or "") for pg in r.pages[:8])
        except Exception:
            text = ""
    if len(text.strip()) < 20 and HAS_PDF2IMG and HAS_OCR:
        try:
            for img in convert_from_bytes(data, first_page=1, last_page=3):
                text += " " + pytesseract.image_to_string(img)
            ocr_used = True
        except Exception:
            pass
    return re.sub(r"\s+", " ", text).strip(), ocr_used

# ---------- Error-Level Analysis ----------
def ela_from_image(img):
    if not HAS_PIL:
        return None
    img = img.convert("RGB")
    if max(img.size) > 1100:
        img.thumbnail((1100, 1100))
    buf = io.BytesIO(); img.save(buf, "JPEG", quality=90); buf.seek(0)
    re_img = Image.open(buf).convert("RGB")
    diff = ImageChops.difference(img, re_img)
    scale = 18
    amp = diff.point(lambda p: min(255, p * scale))
    stat = ImageStat.Stat(diff)
    score = sum(stat.mean) / 3 * scale
    out = io.BytesIO(); amp.save(out, "PNG"); out.seek(0)
    orig = io.BytesIO(); img.save(orig, "PNG"); orig.seek(0)
    return {
        "score": round(score, 1),
        "dataURL": "data:image/png;base64," + base64.b64encode(out.read()).decode(),
        "origURL": "data:image/png;base64," + base64.b64encode(orig.read()).decode(),
    }

# ---------- deterministic checks ----------
def classify_doc(t):
    s = (t or "").lower()
    if re.search(r"payslip|salary slip|net pay|pay period", s): return "Salary slip"
    if re.search(r"account statement|statement of account|closing balance|transaction date", s): return "Bank statement"
    if re.search(r"permanent account number|income tax department", s): return "PAN card"
    if re.search(r"uidai|aadhaar|unique identification", s): return "Aadhaar card"
    if re.search(r"tax invoice|invoice no|gstin|bill to", s): return "Invoice"
    if re.search(r"application form|know your customer|\bkyc\b|applicant name", s): return "KYC / application form"
    return "Document"


def run_checks(text, add, bump):
    checks, fields, extracted = [], {}, []
    def ex(field, value, conf, status="ok"):
        extracted.append({"field": field, "value": value, "conf": conf, "status": status, "src": "text layer · pg 1"})
    U = text.upper()
    nm = re.search(r"\b(?:Name|Employee|Applicant|Account Holder)\s*[:\-]?\s*([A-Z][a-zA-Z.]+(?:\s+[A-Z][a-zA-Z.]+){1,3})", text)
    ad = re.search(r"\bAddress\s*[:\-]?\s*([A-Za-z0-9#,.\-/ ]{6,60})", text, re.I)
    if nm: fields["name"] = nm.group(1).strip(); ex("Name", fields["name"], "Medium")
    if ad: fields["address"] = re.sub(r"\s+", " ", ad.group(1).strip()); ex("Address", fields["address"], "Medium")
    pan = (re.search(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", U) or [None])
    pan = pan.group(0) if hasattr(pan, "group") else None
    aad = re.search(r"\b\d{4}\s?\d{4}\s?\d{4}\b", text)
    ifsc = re.search(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", U)
    if pan:
        fields["pan"] = pan
        checks.append({"ok": True, "t": "PAN format", "m": "AAAAA0000A pattern", "v": "Found · " + pan})
        add("obs", "PAN " + pan + " — format valid"); ex("PAN", pan, "High")
    if aad:
        d = re.sub(r"\s", "", aad.group(0)); ok = verhoeff(d); fields["aadhaar"] = d
        checks.append({"ok": ok, "t": "Aadhaar checksum", "m": "12 digits · Verhoeff",
                       "v": ("Valid · " if ok else "FAILS · ") + aad.group(0)})
        if ok: add("obs", "Aadhaar checksum valid")
        else: add("inc", "Aadhaar checksum fails — transcription error or forgery"); bump(20)
        ex("Aadhaar", aad.group(0), "High", "ok" if ok else "bad")
    if ifsc:
        fields["ifsc"] = ifsc.group(0)
        checks.append({"ok": True, "t": "IFSC format", "m": "4 letters + 0 + 6", "v": "Found · " + ifsc.group(0)})
        ex("IFSC", ifsc.group(0), "High")
    # future dates
    dates = re.findall(r"\b(\d{1,2})[/\-.](\d{1,2})[/\-.](\d{2,4})\b", text)
    future = None; today = datetime.datetime.now()
    for dd, mm, yy in dates:
        y = int(yy) + (2000 if len(yy) == 2 else 0)
        try:
            d = datetime.datetime(y, int(mm), int(dd))
            if d > today and y < 2100: future = d
        except Exception: pass
    if dates:
        checks.append({"ok": not future, "t": "Date logic", "m": "No future-dated fields",
                       "v": ("Future date " + _fmt_date(future)) if future else (str(len(dates)) + " date(s) consistent")})
        if future: add("inc", "Future-dated field " + _fmt_date(future) + " — impossible on a genuine document"); bump(15)
    # salary arithmetic
    def num(x): return int(re.sub(r"[,]", "", x))
    g = re.search(r"gross[^0-9]{0,24}([\d,]{3,})", text, re.I)
    de = re.search(r"deduction[s]?[^0-9]{0,24}([\d,]{3,})", text, re.I)
    ne = re.search(r"net[^0-9]{0,24}([\d,]{3,})", text, re.I)
    if g and de and ne:
        G, D, N = num(g[1]), num(de[1]), num(ne[1]); ok = abs((G - D) - N) < 1; fields["amount"] = str(N)
        checks.append({"ok": ok, "t": "Salary arithmetic", "m": "Gross − deductions = net",
                       "v": "₹%s − ₹%s %s ₹%s" % (f"{G:,}", f"{D:,}", "=" if ok else "≠", f"{N:,}")})
        if ok: add("obs", "Salary arithmetic balances")
        else: add("inc", "Salary arithmetic does not balance"); bump(20)
        ex("Net amount", "₹" + f"{N:,}", "High", "ok" if ok else "bad")
    else:
        amts = [num(m) for m in re.findall(r"(?:₹|rs\.?|inr)\s*([\d,]{3,}(?:\.\d{1,2})?)", text, re.I)]
        if amts:
            fields["amount"] = str(amts[0])
            checks.append({"ok": True, "t": "Amounts extracted", "m": str(len(amts)) + " monetary value(s)",
                           "v": " · ".join("₹" + f"{a:,}" for a in amts[:3])})
            ex("Amount", "₹" + f"{amts[0]:,}", "High")
    if not checks:
        checks.append({"ok": None, "t": "Known fields", "m": "No PAN / Aadhaar / IFSC / salary pattern found",
                       "v": "Nothing to validate in this document"})
    return checks, fields, extracted

def build_graph(fields, checks, anomalies, fname, producer_bad):
    bad = anomalies > 0
    nodes = [{"id": "doc", "x": .16, "y": .5, "r": 36,
              "lab": (re.sub(r"\.[^.]+$", "", fname) or "Document")[:11], "type": "doc", "s": "c" if bad else "ok"}]
    ents = []
    if fields.get("pan"): ents.append(["PAN", "ok"])
    if fields.get("aadhaar"):
        c = next((x for x in checks if x["t"] == "Aadhaar checksum"), None)
        ents.append(["Aadhaar", "c" if c and c["ok"] is False else "ok"])
    if fields.get("ifsc"): ents.append(["IFSC", "ok"])
    ar = next((x for x in checks if x["t"] == "Salary arithmetic"), None)
    if ar: ents.append(["Amount", "ok" if ar["ok"] else "c"])
    dl = next((x for x in checks if x["t"] == "Date logic"), None)
    if dl: ents.append(["Dates", "ok" if dl["ok"] else "c"])
    ents.append(["Source", "c" if producer_bad else "ok"])
    edges = []
    n = len(ents)
    for i, e in enumerate(ents):
        y = .5 if n == 1 else (.14 + i * (.72 / (n - 1)))
        nodes.append({"id": "e%d" % i, "x": .85, "y": y, "r": 27, "lab": e[0], "type": "ent", "s": e[1]})
        edges.append(["doc", "e%d" % i, e[1]])
    return {"nodes": nodes, "edges": edges}

# ---------- main entry ----------
def analyze(filename: str, content_type: str, data: bytes, seq: int = 1):
    now = lambda: datetime.datetime.now().strftime("%H:%M:%S")
    rep = {"file": {"name": filename, "size": len(data), "type": content_type or ""},
           "findings": [], "checks": [], "meta": [], "fields": {}, "audit": [], "ela": None, "text": ""}
    findings = rep["findings"]
    add = lambda rung, t: findings.append({"rung": rung, "t": t})
    risk = {"v": 0}; bump = lambda n: risk.__setitem__("v", risk["v"] + n)
    rep["hash"] = hashlib.sha256(data).hexdigest()
    rep["audit"].append([now(), "Document ingested · SHA-256 " + rep["hash"][:12] + "…"])

    name = (filename or "").lower()
    is_pdf = content_type and "pdf" in content_type or name.endswith(".pdf") or data[:4] == b"%PDF"
    is_img = (content_type or "").startswith("image/") or re.search(r"\.(png|jpe?g|webp|bmp|gif)$", name)
    rep["kind"] = "pdf" if is_pdf else "image" if is_img else "other"

    producer_bad = False
    if is_pdf:
        m = raw_pdf_meta(data); rep["fonts"] = m["fonts"]
        cdt, mdt = _dec_date(m["created"]), _dec_date(m["modified"])
        mod_ne = cdt and mdt and abs((mdt - cdt).total_seconds()) > 60
        producer_bad = bool(m["producer"] and EDITOR.search(m["producer"]))
        rep["meta"] += [
            ["Producer", m["producer"] or "—", "var(--red)" if producer_bad else "var(--green)"],
            ["Creator", m["creator"] or "—", "var(--mut)"],
            ["Created", _fmt_date(cdt) or "—", "var(--mut)"],
            ["Modified", _fmt_date(mdt) or "—", "var(--amber)" if mod_ne else "var(--green)"],
            ["Incremental saves", str(max(0, m["eof"] - 1)), "var(--amber)" if m["eof"] > 1 else "var(--green)"],
            ["Font families", str(len(m["fonts"])), "var(--amber)" if len(m["fonts"]) > 6 else "var(--green)"],
        ]
        if m["hasJS"]: rep["meta"].append(["Embedded JavaScript", "present", "var(--red)"])
        if m["enc"]: rep["meta"].append(["Encryption", "present", "var(--amber)"])
        rep["audit"].append([now(), 'PDF metadata parsed · producer "%s"' % (m["producer"] or "unknown")])
        if producer_bad: add("man", 'Produced/edited by "%s" — consumer editor, not a scanner' % m["producer"]); bump(25)
        if mod_ne: add("inc", "Modified %s, after creation %s" % (_fmt_date(mdt), _fmt_date(cdt))); bump(15)
        if m["eof"] > 1: add("man", "%d incremental save(s) — hidden revision history" % (m["eof"] - 1)); bump(15)
        if m["hasJS"]: add("man", "Embedded JavaScript present in document"); bump(15)
        if len(m["fonts"]) > 6: add("man", "%d font families — possible splice/paste" % len(m["fonts"])); bump(8)
        text, ocr = extract_text(data); rep["text"] = text
        if ocr: rep["audit"].append([now(), "Text layer empty — OCR fallback used"])
        elif text: rep["audit"].append([now(), "Text extracted (%d chars)" % len(text)])
        else: rep["audit"].append([now(), "No text layer (scanned/protected)"])
        # ELA on first rendered page (needs pdf2image)
        if HAS_PDF2IMG and HAS_PIL:
            try:
                pages = convert_from_bytes(data, first_page=1, last_page=1)
                if pages:
                    e = ela_from_image(pages[0])
                    if e: rep["ela"] = {"score": e["score"], "dataURL": e["dataURL"]}; rep["origURL"] = e["origURL"]
            except Exception:
                pass
    elif is_img and HAS_PIL:
        img = Image.open(io.BytesIO(data))
        rep["dims"] = list(img.size)
        rep["meta"] += [["Type", content_type or "image", "var(--mut)"],
                        ["Dimensions", "%d × %d" % img.size, "var(--mut)"]]
        e = ela_from_image(img)
        if e: rep["ela"] = {"score": e["score"], "dataURL": e["dataURL"]}; rep["origURL"] = e["origURL"]
        rep["audit"].append([now(), "Image decoded %dx%d · ELA computed" % img.size])
    else:
        rep["meta"].append(["Type", content_type or "unknown", "var(--mut)"])
        add("obs", "Unsupported type — hash + custody only")

    rep["docType"] = classify_doc(rep["text"]) if rep["text"] else ("Image" if is_img else ("Scanned PDF" if is_pdf else "Document"))
    rep["extracted"] = []
    if rep["text"]:
        checks, fields, extracted = run_checks(rep["text"], add, bump)
        rep["checks"] += checks; rep["fields"].update(fields); rep["extracted"] = extracted
    elif is_pdf:
        rep["checks"].append({"ok": None, "t": "Text-based checks", "m": "No embedded text layer",
                              "v": "Scanned PDF — install Tesseract for OCR"})

    if rep["ela"]:
        if rep["ela"]["score"] > 12: add("man", "ELA energy high (%.1f) — inspect highlighted regions" % rep["ela"]["score"]); bump(12)
        else: add("obs", "ELA energy low (%.1f) — no strong splice signal" % rep["ela"]["score"])
    add("obs", "SHA-256 sealed at ingest — chain of custody is live")
    if any(f["rung"] == "man" for f in findings):
        add("rev", "Manipulation signals present → route to a human reviewer")

    rep["risk"] = min(100, risk["v"])
    rep["anomalies"] = sum(1 for f in findings if f["rung"] in ("man", "inc"))
    rep["conflicts"] = sum(1 for f in findings if f["rung"] == "inc")
    rep["confidence"] = (97 if all(f["rung"] == "obs" for f in findings)
                         else max(58, 94 - rep["anomalies"] * 5))
    rep["graph"] = build_graph(rep["fields"], rep["checks"], rep["anomalies"], filename, producer_bad)
    rep["seal"] = "SHA-256 · %s…%s · audit log #%s" % (rep["hash"][:10], rep["hash"][-8:], str(1000 + seq))
    rep["audit"].append([now(), "Risk ranked · %d / 100 · %d anomalies" % (rep["risk"], rep["anomalies"])])
    rep["engine"] = "backend"
    return rep
