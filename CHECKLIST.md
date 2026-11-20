# BLACKLIGHT AI — Requirements Checklist

Mapped to the DataOps Innovation Hackathon problem statement (AI-Powered Document Forensics).
✅ done · ◐ partial · ⟡ advanced/bonus

## Functional requirements (§5)
| # | Requirement | Status |
|---|---|---|
| 5.1 | Ingestion, multiple documents, **classification**, identifiers | ✅ |
| 5.2 | OCR + extraction, **field-level confidence**, source references | ✅ (OCR via backend for scanned docs) |
| 5.3 | Document structure understanding | ◐ fields + type; deep layout partial |
| 5.4 | Visual forensics — ELA, fonts, metadata, **signature zone** | ✅ |
| 5.5 | Contextual verification within a document | ✅ |
| 5.6 | **Cross-document correlation** (entity graph + conflicts) | ✅ |
| 5.7 | Evidence mapping, potential vs confirmed | ✅ |
| 5.8 | Investigation dossier generation | ✅ (+ downloadable PDF) |
| 5.9 | Audit trail | ✅ |

## Investigation dossier (§7)
| Section | Status |
|---|---|
| 7.1 Document overview (type, source, status) | ✅ |
| 7.2 Extracted information (values, confidence, refs) | ✅ |
| 7.3 Contextual analysis (in-doc + cross-doc) | ✅ |
| 7.4 Visual forensic findings | ✅ |
| 7.5 Evidence & traceability | ✅ |
| 7.6 Investigation summary | ✅ |
| Exportable PDF | ✅ |

## Judges' live-demo checklist (§10)
| Item | Status |
|---|---|
| Upload multiple documents | ✅ |
| Classification + OCR extraction | ✅ |
| Structured representation | ✅ |
| Highlight suspicious regions | ✅ ELA + mapped text regions |
| Inconsistencies within a document | ✅ |
| Cross-document comparison + conflicts | ✅ |
| Relationships between findings | ✅ entity graph |
| Inspect evidence | ✅ Document Viewer |
| Generate dossier | ✅ |
| **Trace findings to origin** | ✅ click-to-region |
| Potential vs confirmed | ✅ evidence ladder |
| Safe failure handling | ✅ graceful fallbacks |

## Killer features
| Feature | Status |
|---|---|
| Deterministic logic & ID checks (PAN / Aadhaar-Verhoeff / IFSC / date / arithmetic) | ✅ |
| PDF & metadata forensics (producer, dates, incremental saves, fonts, JS) | ✅ |
| Cross-document entity graph + conflict detection | ✅ |
| Evidence ladder (never asserts "fraud") | ✅ |
| Chain of custody (real SHA-256 + append-only audit) | ✅ |
| Privacy by design (in-browser) + **PII masking toggle** | ✅ |
| Reviewer workbench (accept / dismiss, recorded) | ✅ |
| Error-Level Analysis (images + PDF pages) | ✅ |
| Signature-zone detection | ✅ basic |
| Possible AI-generated / computer-generated flag | ✅ heuristic |
| **Real-world context advisor** (risk → action → framework) | ✅ |

## Roles (genuinely distinct)
| Role | Capabilities |
|---|---|
| Analyst | Ingest, run all engines, explore every view |
| Reviewer | Review queue + accept/dismiss each finding (logged); no ingest |
| Auditor | Read-only: audit trail, chain of custody, reviewer decisions; no changes |

## Deliverables (§9)
| Deliverable | Where |
|---|---|
| Working prototype | frontend (in-browser) + FastAPI backend |
| Architecture overview | README (architecture section) |
| Sample investigation dossier | downloadable PDF from the app |
| Source repository | this repo |
| Demonstration dataset | synthetic sample + any file you drop |
| Technical documentation | README + backend/README |
| Evidence-traceability demo | Document Viewer (click-to-region) |
| Limitations & assumptions | README (honest capability table) |

## Known limitations (stated, per §13)
- OCR for scanned/image-only PDFs runs on the **backend**; the pure in-browser mode needs an embedded text layer.
- ELA is a heuristic — reported as an observation, never a verdict.
- Name/address extraction is heuristic and may over-capture nearby words.
- Signature analysis is zone-location only (not specimen matching).
- Synthetic / authorized documents only; every finding requires human review.
