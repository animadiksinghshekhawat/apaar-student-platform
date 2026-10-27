"""FastAPI layer for AICTE-SVP. Run: uvicorn app:app --reload"""
import os, csv, json, time, hmac, base64, hashlib
from contextlib import asynccontextmanager
from typing import List
from fastapi import FastAPI, Depends, Header, HTTPException, UploadFile, File
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import core

try:
    import segno
except ImportError:  # QR codes are optional
    segno = None


@asynccontextmanager
async def lifespan(app):
    core.init()
    yield

app = FastAPI(title="AICTE-SVP: APAAR Student Data Management and Verification", version="2.0", lifespan=lifespan)
FAILS = {}


def get_db():
    c = core.db()
    try:
        yield c
    finally:
        c.close()


def mk_token(u):
    p = base64.urlsafe_b64encode(json.dumps({"u": u["u"], "r": u["r"], "i": u["i"], "e": time.time() + 28800}).encode()).decode()
    return p + "." + hmac.new(core.TOKEN_KEY, p.encode(), hashlib.sha256).hexdigest()


def auth(authorization: str = Header(None), x_api_key: str = Header(None), c=Depends(get_db)):
    if x_api_key:
        u = core.api_key_user(c, x_api_key)
        if u:
            return u
        raise HTTPException(401, "Invalid API key")
    try:
        p, s = authorization.split(" ", 1)[1].split(".")
        if not hmac.compare_digest(s, hmac.new(core.TOKEN_KEY, p.encode(), hashlib.sha256).hexdigest()):
            raise ValueError
        d = json.loads(base64.urlsafe_b64decode(p))
        if d["e"] < time.time():
            raise ValueError
        return {"u": d["u"], "r": d["r"], "i": d["i"]}
    except Exception:
        raise HTTPException(401, "Invalid or expired token")


def need(*roles):
    def dep(u=Depends(auth)):
        if u["r"] not in roles:
            raise HTTPException(403, "Your role cannot do this")
        return u
    return dep


def guard(fn, *a):
    try:
        return fn(*a)
    except core.Denied as e:
        raise HTTPException(429 if "limit" in str(e).lower() or "paused" in str(e).lower() else 400, str(e))


def qr(payload, sig):
    return segno.make(json.dumps({"p": payload, "s": sig}), error="m").svg_inline(scale=4) if segno else None


def mask(r):
    r = dict(r)
    r["apaar"] = "********" + r["apaar"][-4:]
    r["name"] = " ".join(w[0] + "." for w in r["name"].split())
    return r


class Login(BaseModel):
    username: str
    password: str


class StudentLogin(BaseModel):
    apaar: str
    dob: str


class VReq(BaseModel):
    apaar: str


class VConfirm(BaseModel):
    request_id: int
    otp: str = ""


class Check(BaseModel):
    payload: str
    sig: str


class Note(BaseModel):
    note: str


class RuleIn(BaseModel):
    action: str
    param: str = ""


class IntakeIn(BaseModel):
    inst: str
    prog: str
    intake: int
    sup_pct: float


class KeyIn(BaseModel):
    label: str = "ERP"


class Years(BaseModel):
    years: int


class Bulk(BaseModel):
    rows: List[dict]


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/demo/hint")
def hint(c=Depends(get_db)):
    if not core.SHOW_DEMO_OTP:
        return {}
    r = c.execute("SELECT e.apaar, g.dob FROM enrol e JOIN registry g ON g.apaar=e.apaar WHERE e.student_id='MH-014-0020'").fetchone()
    return dict(r) if r else {}


@app.post("/api/login")
def login(b: Login, c=Depends(get_db)):
    name = b.username.strip().lower()
    f = FAILS.get(name, [0, 0])
    if f[0] >= 5 and time.time() < f[1]:
        raise HTTPException(429, "Too many failed attempts. Try again in a minute.")
    u = c.execute("SELECT * FROM users WHERE username=?", (name,)).fetchone()
    if not u or not hmac.compare_digest(u["pw"], core.hash_pw(name, b.password)):
        FAILS[name] = [f[0] + 1, time.time() + 60]
        core.audit(c, name, "Failed login"); c.commit()
        raise HTTPException(401, "Wrong username or password")
    FAILS.pop(name, None)
    core.audit(c, name, "Login"); c.commit()
    me = {"u": name, "r": u["role"], "i": u["inst"]}
    return {"token": mk_token(me), "role": u["role"], "inst": u["inst"], "username": name}


@app.post("/api/student/login")
def student_login(b: StudentLogin, c=Depends(get_db)):
    key = "s:" + b.apaar
    f = FAILS.get(key, [0, 0])
    if f[0] >= 5 and time.time() < f[1]:
        raise HTTPException(429, "Too many failed attempts. Try again in a minute.")
    if not core.student_login(c, b.apaar, b.dob):
        FAILS[key] = [f[0] + 1, time.time() + 60]
        raise HTTPException(401, "APAAR ID and date of birth do not match")
    FAILS.pop(key, None)
    core.audit(c, "student-" + b.apaar[-4:], "Student portal login"); c.commit()
    return {"token": mk_token({"u": b.apaar, "r": "student", "i": b.apaar}), "role": "student", "inst": None, "username": b.apaar}


def run_rows(rows, u, c):
    return core.process_rows(c, u["i"], rows, u["u"])


@app.post("/api/upload")
def upload(file: UploadFile = File(...), u=Depends(need("institution")), c=Depends(get_db)):
    raw = file.file.read(5_000_001).decode("utf-8-sig", errors="replace")
    if len(raw) > 5_000_000:
        raise HTTPException(413, "File too large (5 MB max)")
    lines = raw.splitlines()
    if len(lines) < 2:
        raise HTTPException(400, "CSV needs a header line and at least one row")
    head = next(csv.reader([lines[0]]))
    rows = list(csv.DictReader(lines[1:], fieldnames=[h.strip().lower() for h in head]))
    if "apaar" not in [h.strip().lower() for h in head]:
        raise HTTPException(400, "CSV header must include the 'apaar' column")
    return run_rows(rows, u, c)


@app.post("/api/students/bulk")
def bulk(b: Bulk, u=Depends(need("institution")), c=Depends(get_db)):
    if len(b.rows) > 20000:
        raise HTTPException(413, "At most 20,000 rows per request")
    return run_rows(b.rows, u, c)


@app.get("/api/sample")
def sample(u=Depends(need("institution")), c=Depends(get_db)):
    return Response(core.sample_csv(c, u["i"]), media_type="text/csv")


@app.get("/api/template.csv")
def template():
    return Response(core.template_csv(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=student_upload_template.csv"})


@app.get("/api/dashboard")
def dashboard(u=Depends(need("aicte", "institution")), c=Depends(get_db)):
    return core.dashboard(c, u["i"] if u["r"] == "institution" else None)


@app.get("/api/flags")
def flags(u=Depends(need("aicte", "institution")), c=Depends(get_db)):
    sql, a = "SELECT * FROM flags", ()
    if u["r"] == "institution":
        sql, a = sql + " WHERE inst=?", (u["i"],)
    return [dict(r) for r in c.execute(sql + " ORDER BY resolved, type, inst", a)]


@app.post("/api/flags/{fid}/toggle")
def toggle(fid: int, u=Depends(need("aicte")), c=Depends(get_db)):
    c.execute("UPDATE flags SET resolved=1-resolved WHERE id=?", (fid,))
    core.audit(c, u["u"], f"Toggled flag {fid}"); c.commit()
    return {"ok": True}


@app.post("/api/flags/{fid}/respond")
def respond(fid: int, b: Note, u=Depends(need("institution")), c=Depends(get_db)):
    guard(core.respond_flag, c, u["i"], fid, b.note, u["u"])
    return {"ok": True}


@app.get("/api/rules")
def rules(u=Depends(need("aicte", "institution")), c=Depends(get_db)):
    return {"rules": [dict(r, fixed=r["code"] in core.FIXED) for r in c.execute("SELECT * FROM rules")],
            "intake": [dict(r) for r in c.execute("SELECT * FROM intake ORDER BY inst, prog")]}


@app.put("/api/rules/{code}")
def put_rule(code: str, b: RuleIn, u=Depends(need("aicte")), c=Depends(get_db)):
    guard(core.set_rule, c, code, b.action, b.param, u["u"])
    return {"ok": True}


@app.put("/api/intake")
def put_intake(b: IntakeIn, u=Depends(need("aicte")), c=Depends(get_db)):
    guard(core.set_intake, c, b.inst, b.prog, b.intake, b.sup_pct, u["u"])
    return {"ok": True}


@app.post("/api/admin/retention")
def retention(b: Years, u=Depends(need("aicte")), c=Depends(get_db)):
    return {"anonymised": core.anonymise_old(c, max(0, b.years), u["u"])}


@app.get("/api/students")
def students(q: str = "", u=Depends(need("aicte", "institution")), c=Depends(get_db)):
    sql, args = "SELECT apaar,name,student_id,inst,prog,adm,sup,nri,oci,fn,status FROM enrol WHERE 1=1", []
    if u["r"] == "institution":
        sql += " AND inst=?"; args.append(u["i"])
    if q:
        sql += " AND (apaar LIKE ? OR name LIKE ? OR student_id LIKE ?)"; args += [f"%{q}%"] * 3
    core.audit(c, u["u"], "Viewed student list"); c.commit()
    rows = [dict(r) for r in c.execute(sql + " ORDER BY id DESC LIMIT 200", args)]
    return [mask(r) for r in rows] if u["r"] == "aicte" else rows   # AICTE sees masked identities in lists


@app.post("/api/apikey")
def apikey(b: KeyIn, u=Depends(need("institution")), c=Depends(get_db)):
    if u["u"].startswith("api:"):
        raise HTTPException(403, "API keys cannot create API keys")
    return {"api_key": core.create_api_key(c, u["i"], b.label, u["u"]), "note": "Shown once. Send it as the X-API-Key header."}


@app.get("/api/certificate/{student_id}")
def certificate(student_id: str, u=Depends(need("institution")), c=Depends(get_db)):
    rec = core.make_record(c, student_id=student_id, inst=u["i"])
    if not rec:
        raise HTTPException(404, "No active student with this ID at your institution")
    p = json.loads(rec["payload"])
    core.audit(c, u["u"], f"Certificate APAAR lookup for {student_id}"); c.commit()
    return {"line": f"Student ID: {p['student_id']}   |   APAAR ID: {p['apaar']}", "payload": rec["payload"], "sig": rec["sig"], "qr_svg": qr(rec["payload"], rec["sig"])}


@app.post("/api/verify/request")
def vrequest(b: VReq, u=Depends(need("verifier")), c=Depends(get_db)):
    r = guard(core.request_consent, c, u["u"], b.apaar.strip())
    if not r:
        raise HTTPException(404, "No active enrolment found for this APAAR ID")
    out = {"request_id": r[0], "message": "The student was asked to approve in the student portal, or to share the one-time code."}
    if core.SHOW_DEMO_OTP:
        out["demo_otp"] = r[1]
    return out


@app.post("/api/verify/confirm")
def vconfirm(b: VConfirm, u=Depends(need("verifier")), c=Depends(get_db)):
    if b.otp:
        rec, err = core.confirm_consent(c, u["u"], b.request_id, b.otp)
    else:
        rec, err = core.consent_result(c, u["u"], b.request_id)
    if err:
        raise HTTPException(400, err)
    return {"record": json.loads(rec["payload"]), "payload": rec["payload"], "sig": rec["sig"], "qr_svg": qr(rec["payload"], rec["sig"])}


@app.post("/api/record/check")
def rcheck(b: Check, c=Depends(get_db)):
    return core.check_record(c, b.payload, b.sig)


@app.get("/api/student/me")
def smine(u=Depends(need("student")), c=Depends(get_db)):
    return core.student_view(c, u["i"])


@app.post("/api/student/consent/{cid}/{decision}")
def sdecide(cid: int, decision: str, u=Depends(need("student")), c=Depends(get_db)):
    guard(core.student_decide, c, u["i"], cid, decision)
    return {"ok": True}


@app.get("/api/audit")
def audit(u=Depends(need("aicte")), c=Depends(get_db)):
    return {"chain_ok": core.audit_chain_ok(c), "rows": [dict(r) for r in c.execute("SELECT ts,actor,action FROM audit ORDER BY id DESC LIMIT 150")]}


@app.get("/api/report.csv")
def report(u=Depends(need("aicte")), c=Depends(get_db)):
    return Response(core.report_csv(c), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=aicte_enrolment_report.csv"})


app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(os.path.abspath(__file__)), "static"), html=True), name="static")
