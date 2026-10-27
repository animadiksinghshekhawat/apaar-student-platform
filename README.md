# AICTE-SVP: APAAR-Based Student Data Management and Verification Platform (v2)

Working prototype for the problem statement "APAAR ID-Based Student Data Management and Verification Platform for AICTE-Approved Institutions".

Flow: Institution -> Student Data Upload -> APAAR Validation -> Data Verification -> AICTE Central Repository -> Analytics and Monitoring -> Authorised Verification

## Run it (2 minutes)

Requires Python 3.10+.

```bash
cd aicte-svp
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python test_core.py                # 27 checks of the core logic (no extra packages needed)
uvicorn app:app --reload
```

Open http://127.0.0.1:8000 (API docs at /docs). Optional: `python test_api.py` runs an end-to-end API test.
If you ran an older version, delete any old `.db` file first.

First start creates a SQLite database with 10 institutions, a mock APAAR registry of 800 students and about 660 demo enrolments with planted problems (one over-admitting institution, cross-institution duplicates, near-duplicate identities, bad IDs, quota anomalies). Set `LOAD_DEMO=0` for an empty start.

## Demo accounts

| Role | Sign in | Password |
|---|---|---|
| AICTE officer | aicte | aicte123 |
| Verifier | verifier | verifier123 |
| Institution | rj001, mh014, ka022, dl009, up031, gj007, tn018, wb011, pb005, mp026 | inst123 |
| Student | "Student" tab: APAAR ID and date of birth (a sample is pre-filled) | - |

## 6-minute demo script

1. **rj001**: Upload data, "Load sample with errors", "Validate and submit". Show rejections and flags. Open "Certificate APAAR" for `RJ-001-0001` (line to print plus QR). Open "ERP integration" and create an API key.
2. **aicte**: National dashboard. Nandi Hills (KA-022) is red: 122% of intake, 23% quota seats, year-on-year jump. Point at the "ML" line (Isolation Forest against peers) next to the rule-based reasons. Open Flags: cross-institution duplicates, potential duplicate identities (same DOB, name differs by a letter), excess enrolment. Open "Rules and limits": switch "intake exceeded" to reject and show admissions being blocked. Download the CSV report. Open the Audit log.
3. **verifier**: request verification for the sample APAAR ID (use the one pre-filled on the Student tab).
4. **Student tab**: the student sees the pending request, approves it. Back on the verifier: "Check whether the student approved" releases a minimal signed record with a QR. "Tamper with record" then "Check signature" fails.
5. Back as the student: revoke access. The verifier can no longer read the record. Back in the Audit log: every step is recorded, and the hash chain is intact.

## What makes it different

- **Explainable anomaly detection:** a pure-Python Isolation Forest scores institutions against peers on enrolment/intake, quota-seat share, open flags and year-on-year growth. Robust z-scores turn that into plain sentences. The final risk is the higher of the rule score and the ML score.
- **Rules AICTE can change without code:** each validation rule can be set to reject, flag or off, with parameters (minimum age, name-similarity threshold); approved intake and supernumerary share are editable. A "flag" setting for unknown APAAR IDs gives a grace period for students who do not have an APAAR ID yet. A "reject" setting on intake blocks over-admission.
- **Fuzzy duplicate identity detection** across institutions, not only exact APAAR matches.
- **Student-controlled consent:** the student approves, denies or revokes access in a portal and sees who asked. One-time code is the alternative path. Verifier lookups are rate-limited, and repeated unknown-ID lookups lock the verifier and raise an audit alert.
- **Tamper-evident records:** signed records with QR codes, signed with a key separate from the login-token key; hash-chained audit log that detects edits.
- **Integration-ready:** per-institution API keys, bulk JSON endpoint, CSV upload and template, OpenAPI at `/docs`.
- **Privacy by design:** masked identities in AICTE lists, minimal fields on verification, data-retention anonymisation, audit of every read.
- **Adoption workflow:** institutions get a data-quality score, a downloadable template and can respond to each flag with an explanation.

## Requirements coverage

| # | Requirement | Where |
|---|---|---|
| 1 | Secure upload/update keyed on APAAR ID | `POST /api/upload`, `/api/students/bulk` |
| 2 | Intake, enrolment, supernumerary, NRI, OCI, FN | `intake` table, CSV columns, dashboards |
| 3 | Automated validation | `core.process_rows`, `core.recompute_flags`, `ml.py` |
| 4 | Dashboards | `GET /api/dashboard`, web UI |
| 5 | Secure verification | `/api/verify/*`, student portal |
| 6 | Verifiable records | signed record + QR, `/api/record/check` |
| 7 | Integration | API keys, REST, OpenAPI |
| 8 | Security, privacy, RBAC, audit, consent | roles, tokens, hash-chained audit, consent ledger |
| 9 | Reports | `GET /api/report.csv` |
| 10 | APAAR on certificates | `GET /api/certificate/{student_id}` |

## Layout

```
app.py            FastAPI endpoints, roles, API keys
core.py           database, rules, validation, flags, consent, signing (standard library)
ml.py             Isolation Forest and explanations (pure Python)
static/index.html web UI (no build step), four roles
test_core.py      27 checks of the core logic
test_api.py       end-to-end API test (needs httpx)
scripts_backup.py consistent database backup
docker-compose.yml  app + automatic-HTTPS proxy for deployment
```

## Configuration

`SECRET_KEY` (required, 32+ characters, when `ENV=production`), `DB_PATH`, `LOAD_DEMO`, `SHOW_DEMO_OTP` (set 0 in production so codes are never shown on screen).

## Honest limitations (say these in the viva)

- The APAAR/ABC lookup is a mock registry table because the real service is not public. In production, replace the `registry` lookups in `core.process_rows` with the real API (the rest of the flow is unchanged).
- OTP delivery and student sign-in (APAAR + date of birth) are simulated. Production would use DigiLocker or Aadhaar-based authentication and an SMS gateway.
- SQLite with write-ahead logging is used for easy setup. Scaling to millions of records needs PostgreSQL, a background job queue for large uploads and horizontal scaling. The SQL is standard and the data layer is isolated in `core.py`.
- Stored personal data is not encrypted at the field level. Production should use disk or database encryption (for example PostgreSQL with TDE or SQLCipher) and keys in a KMS.
- Records are signed with HMAC (a keyed hash). A production system should use asymmetric signatures (for example Ed25519) so third parties can verify without holding a secret.
- The Isolation Forest runs on 10 demo institutions. It needs real multi-year data before its scores are trustworthy.
- The API and web page were verified by calling handlers directly and checking JavaScript syntax. Run `python test_api.py` and click through the demo script on your machine before presenting.
- Legal basis, consent wording and retention periods under the DPDP Act 2023 need review by AICTE's legal team.
