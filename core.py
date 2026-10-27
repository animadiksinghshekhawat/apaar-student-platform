"""Core logic for AICTE-SVP (standard library plus ml.py): database, rules, validation, flags, consent, signing."""
import os, re, io, csv, json, hmac, time, random, hashlib, sqlite3, secrets, difflib
import ml

DB_PATH = os.environ.get("DB_PATH", "aicte_svp_v2.db")
_RAW = os.environ.get("SECRET_KEY", "")
if os.environ.get("ENV") == "production" and len(_RAW) < 32:
    raise RuntimeError("Set SECRET_KEY (at least 32 characters) when ENV=production")
_RAW = _RAW or "dev-secret-change-me"
TOKEN_KEY = hashlib.sha256(_RAW.encode() + b"|token").digest()      # signs login tokens
RECORD_KEY = hashlib.sha256(_RAW.encode() + b"|record").digest()    # signs student records (separate key)
SHOW_DEMO_OTP = os.environ.get("SHOW_DEMO_OTP", "1") == "1"
LOAD_DEMO = os.environ.get("LOAD_DEMO", "1") == "1"
COLS = ["apaar", "name", "dob", "student_id", "programme", "admission_date",
        "supernumerary", "nri", "oci", "fn", "nationality", "status"]
STATUSES = {"Active", "Withdrawn", "Transferred", "Graduated", "Discontinued"}
SUP_PCT = 0.05
INSTS = {
    "RJ-001": ("Aravali Institute of Technology", "Rajasthan", [("B.Tech CSE", 35), ("MBA", 30)]),
    "MH-014": ("Sahyadri College of Engineering", "Maharashtra", [("B.Tech CSE", 35), ("B.Pharm", 30)]),
    "KA-022": ("Nandi Hills Institute of Management", "Karnataka", [("B.Tech CSE", 35), ("MBA", 30)]),
    "DL-009": ("Yamuna Polytechnic and Technology", "Delhi", [("Diploma Mech", 35), ("B.Tech ECE", 30)]),
    "UP-031": ("Gomti Engineering University", "Uttar Pradesh", [("B.Tech CSE", 35), ("B.Arch", 30)]),
    "GJ-007": ("Sabarmati Technical Institute", "Gujarat", [("B.Tech CSE", 35), ("MBA", 30)]),
    "TN-018": ("Kaveri College of Engineering", "Tamil Nadu", [("B.Tech ECE", 35), ("B.Tech CSE", 30)]),
    "WB-011": ("Hooghly Institute of Management", "West Bengal", [("MBA", 35), ("B.Tech CSE", 30)]),
    "PB-005": ("Sutlej Pharmacy College", "Punjab", [("B.Pharm", 35), ("D.Pharm", 30)]),
    "MP-026": ("Narmada Valley Polytechnic", "Madhya Pradesh", [("Diploma Civil", 35), ("B.Tech Civil", 30)]),
}
# code, label, default action (reject / flag / off), parameter
RULES = [
    ("missing_apaar", "APAAR ID is missing", "reject", ""),
    ("bad_format", "APAAR ID is not 12 digits", "reject", ""),
    ("not_in_registry", "APAAR ID not found in registry (use flag during the APAAR grace period)", "reject", ""),
    ("identity_mismatch", "Name or DOB differs from the APAAR record", "flag", ""),
    ("dup_in_file", "Same APAAR twice in one file", "reject", ""),
    ("already_enrolled", "Already enrolled at this institution", "reject", ""),
    ("cross_inst_dup", "Student active at another institution", "flag", ""),
    ("programme_not_approved", "Programme not approved for the institution", "reject", ""),
    ("intake_exceeded", "Enrolment above intake plus supernumerary allowance (reject blocks the admission)", "flag", ""),
    ("category_conflict", "Conflicting NRI/OCI/FN flags", "flag", ""),
    ("nationality_missing", "Nationality missing for an NRI/OCI/FN seat", "flag", ""),
    ("min_age", "Admission before minimum age (parameter = years)", "flag", "16"),
    ("fuzzy_identity", "Same DOB and near-identical name under different APAAR IDs (parameter = similarity 0 to 1)", "flag", "0.88"),
]
FIXED = {"missing_apaar", "bad_format", "programme_not_approved", "dup_in_file", "already_enrolled"}
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, pw TEXT, role TEXT, inst TEXT);
CREATE TABLE IF NOT EXISTS institutions(id TEXT PRIMARY KEY, name TEXT, state TEXT);
CREATE TABLE IF NOT EXISTS intake(inst TEXT, prog TEXT, intake INT, sup_pct REAL, PRIMARY KEY(inst, prog));
CREATE TABLE IF NOT EXISTS history(inst TEXT, year INT, enrolled INT, PRIMARY KEY(inst, year));
CREATE TABLE IF NOT EXISTS rules(code TEXT PRIMARY KEY, label TEXT, action TEXT, param TEXT);
CREATE TABLE IF NOT EXISTS registry(apaar TEXT PRIMARY KEY, name TEXT, dob TEXT);
CREATE TABLE IF NOT EXISTS enrol(id INTEGER PRIMARY KEY AUTOINCREMENT, apaar TEXT, name TEXT, dob TEXT,
  student_id TEXT, inst TEXT, prog TEXT, adm TEXT, sup TEXT, nri TEXT, oci TEXT, fn TEXT, nat TEXT,
  status TEXT DEFAULT 'Active', warn TEXT DEFAULT '[]');
CREATE INDEX IF NOT EXISTS ix_enrol_apaar ON enrol(apaar);
CREATE INDEX IF NOT EXISTS ix_enrol_ip ON enrol(inst, prog, status);
CREATE TABLE IF NOT EXISTS flags(id INTEGER PRIMARY KEY AUTOINCREMENT, k TEXT UNIQUE, type TEXT, inst TEXT,
  detail TEXT, resolved INT DEFAULT 0, note TEXT DEFAULT '', responded INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS consent(id INTEGER PRIMARY KEY AUTOINCREMENT, apaar TEXT, verifier TEXT, otp TEXT,
  state TEXT, ts REAL, tries INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS api_keys(key_hash TEXT PRIMARY KEY, inst TEXT, label TEXT, created TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, action TEXT, prev TEXT, h TEXT);
"""


class Denied(Exception):
    """Raised for policy refusals (rate limits, lockouts, invalid settings)."""


def db():
    c = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c


def hash_pw(user, pw):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), ("svp:" + user).encode(), 100_000).hex()


def audit(c, actor, action):
    last = c.execute("SELECT h FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    prev = last["h"] if last else "0"
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO audit(ts,actor,action,prev,h) VALUES(?,?,?,?,?)",
              (ts, actor, action, prev, hashlib.sha256((prev + ts + actor + action).encode()).hexdigest()))


def audit_chain_ok(c):
    prev = "0"
    for r in c.execute("SELECT * FROM audit ORDER BY id"):
        if r["prev"] != prev or r["h"] != hashlib.sha256((prev + r["ts"] + r["actor"] + r["action"]).encode()).hexdigest():
            return False
        prev = r["h"]
    return True


def init():
    c = db()
    c.executescript(SCHEMA)
    if not c.execute("SELECT 1 FROM users").fetchone():
        users = [("aicte", "aicte123", "aicte", None), ("verifier", "verifier123", "verifier", None)]
        rng = random.Random(7)
        for iid, (name, state, progs) in INSTS.items():
            c.execute("INSERT INTO institutions VALUES(?,?,?)", (iid, name, state))
            for p, n in progs:
                c.execute("INSERT INTO intake VALUES(?,?,?,?)", (iid, p, n, SUP_PCT))
            total = sum(n for _, n in progs)
            c.execute("INSERT INTO history VALUES(?,?,?)", (iid, 2024, 60 if iid == "KA-022" else round(total * rng.uniform(.9, 1.0))))
            users.append((iid.replace("-", "").lower(), "inst123", "institution", iid))
        for u, p, r, i in users:
            c.execute("INSERT INTO users VALUES(?,?,?,?)", (u, hash_pw(u, p), r, i))
        for code, label, act, par in RULES:
            c.execute("INSERT INTO rules VALUES(?,?,?,?)", (code, label, act, par))
        F = "Aarav Ananya Rohan Priya Kabir Meera Vihaan Isha Arjun Diya Karan Sneha Rahul Nisha".split()
        L = "Sharma Verma Singh Patel Iyer Nair Gupta Khan Reddy Joshi Mehta Das".split()
        seen = set()
        while len(seen) < 800:
            a = str(rng.randint(10**11, 10**12 - 1))
            if a in seen:
                continue
            seen.add(a)
            dob = f"{rng.randint(2003, 2006)}-{rng.randint(1, 9):02d}-{rng.randint(10, 27)}"
            c.execute("INSERT INTO registry VALUES(?,?,?)", (a, f"{rng.choice(F)} {rng.choice(L)}", dob))
        c.commit()
    if LOAD_DEMO and not c.execute("SELECT 1 FROM enrol").fetchone():
        load_demo(c)
    c.close()


def load_demo(c):
    pool = [dict(r) for r in c.execute("SELECT * FROM registry ORDER BY rowid")]
    rng, k, by = random.Random(11), 0, {}
    for iid, (_, _, progs) in INSTS.items():
        rows = []
        for pi, (pn, n) in enumerate(progs):
            extra = 14 if (iid == "KA-022" and pi == 0) else 0
            for j in range(n + extra):
                q = pool[k]; k += 1
                nri = "Y" if (j >= n or rng.random() < .05) else "N"
                rows.append(dict(apaar=q["apaar"], name=q["name"], dob=q["dob"], student_id=f"{iid}-{len(rows)+1:04d}",
                                 programme=pn, admission_date=f"2025-08-{10 + j % 15}",
                                 supernumerary="Y" if rng.random() < .04 else "N", nri=nri, oci="N", fn="N",
                                 nationality="Indian" if nri == "Y" else "", status="Active"))
        by[iid] = rows
    by["DL-009"][0:6] = [dict(r, programme="Diploma Mech", student_id=f"DL-009-{i+1:04d}") for i, r in enumerate(by["MH-014"][:6])]
    for i in (0, 1, 2):
        by["UP-031"][i]["apaar"] = by["UP-031"][i]["apaar"][1:]
    by["UP-031"][3]["apaar"], by["UP-031"][4]["apaar"] = "555555555501", "555555555502"
    for i in (10, 11):
        by["DL-009"][i].update(oci="Y", fn="Y", nationality="Other")
    for i in (2, 3, 4):
        by["RJ-001"][i]["name"] = "Unknown Person"
    for i in range(3):   # near-identical identities under different APAAR IDs (same DOB, name differs by one letter)
        base = pool[-1 - i]
        twin = str(int(base["apaar"]) + 7)
        c.execute("INSERT OR IGNORE INTO registry VALUES(?,?,?)", (twin, base["name"] + "a", base["dob"]))
        by["GJ-007"][20 + i].update(apaar=base["apaar"], name=base["name"], dob=base["dob"])
        by["MP-026"][20 + i].update(apaar=twin, name=base["name"] + "a", dob=base["dob"])
    for iid in INSTS:
        process_rows(c, iid, by[iid], "system-demo-loader")
    c.commit()


def load_rules(c):
    return {r["code"]: (r["action"], r["param"]) for r in c.execute("SELECT * FROM rules")}


def set_rule(c, code, action, param, actor):
    if code not in {r[0] for r in RULES}:
        raise Denied("Unknown rule")
    if action not in ("reject", "flag", "off") or (code in FIXED and action != "reject"):
        raise Denied("This rule must stay on 'reject'" if code in FIXED else "Action must be reject, flag or off")
    if code in ("min_age", "fuzzy_identity"):
        try:
            v = float(param)
            assert (0 < v <= 1) if code == "fuzzy_identity" else (10 <= v <= 40)
        except Exception:
            raise Denied("Parameter out of range")
    c.execute("UPDATE rules SET action=?, param=? WHERE code=?", (action, str(param), code))
    recompute_flags(c)
    audit(c, actor, f"Rule {code} set to {action} {param}".strip())
    c.commit()


def set_intake(c, inst, prog, intake, sup_pct, actor):
    if not (0 < int(intake) <= 5000 and 0 <= float(sup_pct) <= 0.25):
        raise Denied("Intake must be 1-5000 and supernumerary share 0-25%")
    n = c.execute("UPDATE intake SET intake=?, sup_pct=? WHERE inst=? AND prog=?", (int(intake), float(sup_pct), inst, prog)).rowcount
    if not n:
        raise Denied("Unknown institution or programme")
    recompute_flags(c)
    audit(c, actor, f"Approved intake for {inst} {prog} set to {intake} (+{round(float(sup_pct)*100)}%)")
    c.commit()


def process_rows(c, inst, rows, actor):
    R, issues, seen, ok = load_rules(c), [], set(), 0
    intake = {r["prog"]: int(r["intake"] * (1 + r["sup_pct"])) for r in c.execute("SELECT * FROM intake WHERE inst=?", (inst,))}
    cnt = {p: c.execute("SELECT COUNT(*) FROM enrol WHERE inst=? AND prog=? AND status='Active'", (inst, p)).fetchone()[0] for p in intake}
    for n, r in enumerate(rows, start=2):
        g = lambda k: (r.get(k) or "").strip()
        Y = lambda k: g(k).upper() == "Y"
        a, st, e, w = g("apaar"), (g("status").title() or "Active"), [], []

        def add(code, msg):
            act = R[code][0]
            if act == "reject":
                e.append(msg)
            elif act == "flag":
                w.append(msg)
        if st not in STATUSES:
            e.append("Invalid status")
        if not a:
            add("missing_apaar", "Missing APAAR ID")
        elif not re.fullmatch(r"\d{12}", a):
            add("bad_format", "Invalid APAAR format (12 digits required)")
        else:
            ex = c.execute("SELECT id FROM enrol WHERE apaar=? AND inst=? AND status='Active'", (a, inst)).fetchone()
            if st != "Active" and ex and not e:
                c.execute("UPDATE enrol SET status=? WHERE id=?", (st, ex["id"]))
                ok += 1
                continue
            p = c.execute("SELECT * FROM registry WHERE apaar=?", (a,)).fetchone()
            if not p:
                add("not_in_registry", "APAAR not found in registry")
            elif p["name"].lower() != g("name").lower() or p["dob"] != g("dob"):
                add("identity_mismatch", "Name or DOB does not match APAAR record")
            if a in seen:
                add("dup_in_file", "Duplicate APAAR in this file")
            elif ex:
                add("already_enrolled", "Already enrolled at this institution")
            seen.add(a)
            o = c.execute("SELECT inst FROM enrol WHERE apaar=? AND inst!=? AND status='Active'", (a, inst)).fetchone()
            if o and st == "Active":
                add("cross_inst_dup", f"Also active at {o['inst']} (cross-institution duplicate)")
        prog = g("programme")
        if prog not in intake:
            add("programme_not_approved", "Programme not approved for this institution")
        elif st == "Active" and not e and cnt[prog] + 1 > intake[prog] and R["intake_exceeded"][0] == "reject":
            e.append(f"Programme is full: {intake[prog]} seats allowed including supernumerary")
        if Y("fn") and (Y("oci") or Y("nri")):
            add("category_conflict", "Conflicting NRI/OCI/FN flags")
        if (Y("nri") or Y("oci") or Y("fn")) and not g("nationality"):
            add("nationality_missing", "Nationality missing for NRI/OCI/FN seat")
        try:
            if g("dob") and g("admission_date") and g("admission_date") < str(int(g("dob")[:4]) + int(float(R["min_age"][1] or 16))) + g("dob")[4:]:
                add("min_age", "Admission date before minimum age")
        except ValueError:
            w.append("Invalid DOB format")
        issues += [dict(row=n, apaar=a, result="Rejected", issue=m) for m in e]
        issues += [dict(row=n, apaar=a, result="Flagged", issue=m) for m in w]
        if not e:
            ok += 1
            if st == "Active" and prog in cnt:
                cnt[prog] += 1
            c.execute("INSERT INTO enrol(apaar,name,dob,student_id,inst,prog,adm,sup,nri,oci,fn,nat,status,warn) "
                      "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (a, g("name"), g("dob"), g("student_id"), inst, prog, g("admission_date"),
                       "Y" if Y("supernumerary") else "N", "Y" if Y("nri") else "N", "Y" if Y("oci") else "N",
                       "Y" if Y("fn") else "N", g("nationality"), st,
                       json.dumps([m for m in w if not m.startswith("Also active")])))
    recompute_flags(c)
    summary = dict(rows=len(rows), accepted=ok,
                   rejected=len({i["row"] for i in issues if i["result"] == "Rejected"}),
                   flagged=len({i["row"] for i in issues if i["result"] == "Flagged"}), issues=issues)
    audit(c, actor, f"Upload to {inst}: {len(rows)} rows, {ok} accepted, {summary['rejected']} rejected")
    c.commit()
    return summary


def recompute_flags(c):
    R, cur = load_rules(c), []
    active = c.execute("SELECT * FROM enrol WHERE status='Active'").fetchall()
    groups, bydob = {}, {}
    for r in active:
        for w in json.loads(r["warn"]):
            cur.append((f"w|{r['id']}|{w}", "Data inconsistency", r["inst"], f"{r['name']} ({r['apaar']}): {w}"))
        groups.setdefault(r["apaar"], []).append(r)
        bydob.setdefault(r["dob"], []).append(r)
    if R["cross_inst_dup"][0] != "off":
        for a, lst in groups.items():
            s = sorted({x["inst"] for x in lst})
            if len(s) > 1:
                for x in lst:
                    cur.append((f"d|{a}|{x['inst']}", "Cross-institution duplicate", x["inst"],
                                f"{x['name']} ({a}) active at {' and '.join(s)}"))
    if R["fuzzy_identity"][0] != "off":
        thr = float(R["fuzzy_identity"][1] or .88)
        for dob, lst in bydob.items():
            for i in range(len(lst)):
                for j in range(i + 1, len(lst)):
                    x, y = lst[i], lst[j]
                    if dob and x["apaar"] != y["apaar"] and difflib.SequenceMatcher(None, x["name"].lower(), y["name"].lower()).ratio() >= thr:
                        for z in (x, y):
                            cur.append((f"f|{'|'.join(sorted([x['apaar'], y['apaar']]))}|{z['inst']}", "Potential duplicate identity", z["inst"],
                                        f"{x['name']} ({x['apaar']}) and {y['name']} ({y['apaar']}) share a DOB and a near-identical name"))
    if R["intake_exceeded"][0] != "off":
        for r in c.execute("SELECT i.inst,i.prog,i.intake,i.sup_pct,(SELECT COUNT(*) FROM enrol e WHERE e.inst=i.inst "
                           "AND e.prog=i.prog AND e.status='Active') n FROM intake i"):
            allowed = int(r["intake"] * (1 + r["sup_pct"]))
            if r["n"] > allowed:
                cur.append((f"x|{r['inst']}|{r['prog']}", "Excess enrolment", r["inst"],
                            f"{r['prog']}: {r['n']} enrolled vs {allowed} allowed (intake {r['intake']} + {round(r['sup_pct']*100)}% supernumerary)"))
    for k, t, i, d in cur:
        c.execute("INSERT INTO flags(k,type,inst,detail) VALUES(?,?,?,?) ON CONFLICT(k) DO UPDATE SET detail=excluded.detail", (k, t, i, d))
    keys = {x[0] for x in cur}
    for r in c.execute("SELECT k FROM flags").fetchall():
        if r["k"] not in keys:
            c.execute("DELETE FROM flags WHERE k=?", (r["k"],))


def _stats(c, i):
    info = c.execute("SELECT name,state FROM institutions WHERE id=?", (i,)).fetchone()
    progs = [dict(prog=r["prog"], intake=r["intake"], allowed=int(r["intake"] * (1 + r["sup_pct"])),
                  enrolled=c.execute("SELECT COUNT(*) FROM enrol WHERE inst=? AND prog=? AND status='Active'", (i, r["prog"])).fetchone()[0])
             for r in c.execute("SELECT * FROM intake WHERE inst=?", (i,))]
    rs = c.execute("SELECT sup,nri,oci,fn FROM enrol WHERE inst=? AND status='Active'", (i,)).fetchall()
    n, intake = len(rs), sum(p["intake"] for p in progs)
    fl = c.execute("SELECT COUNT(*) FROM flags WHERE inst=? AND resolved=0", (i,)).fetchone()[0]
    prev = c.execute("SELECT enrolled FROM history WHERE inst=? ORDER BY year DESC LIMIT 1", (i,)).fetchone()
    return dict(id=i, name=info["name"], state=info["state"], progs=progs, n=n, intake=intake, fl=fl,
                util=n / intake if intake else 0, quota=(sum(1 for r in rs if "Y" in tuple(r)) / n) if n else 0,
                flag_rate=fl / max(1, n) * 100, yoy=(n / prev[0]) if prev and prev[0] else 1.0)


def dashboard(c, inst=None):
    ids = [r["id"] for r in c.execute("SELECT id FROM institutions ORDER BY id")]
    S = [_stats(c, i) for i in ids]
    M = ml.analyze([[s["util"], s["quota"], s["flag_rate"], s["yoy"]] for s in S])
    out = []
    for s, (mls, mlr) in zip(S, M):
        if inst and s["id"] != inst:
            continue
        rule_score = max(0, s["util"] - 1.05) * 300 + max(0, s["quota"] - .15) * 150 + s["flag_rate"] * 2
        rr = []
        if s["util"] > 1.05: rr.append(f"Enrolment is {round(s['util']*100)}% of approved intake")
        if s["quota"] > .15: rr.append(f"Quota seats are {round(s['quota']*100)}% of enrolment")
        if s["fl"]: rr.append(f"{s['fl']} open flag{'s' if s['fl'] > 1 else ''}")
        score = min(100, max(round(rule_score), mls))
        out.append(dict(id=s["id"], name=s["name"], state=s["state"], intake=s["intake"], enrolled=s["n"],
                        quota_share=round(s["quota"], 3), open_flags=s["fl"], yoy=round(s["yoy"], 2),
                        quality=max(0, 100 - round(s["flag_rate"])), risk=score,
                        level="High" if score >= 50 else "Medium" if score >= 20 else "Low",
                        ml_score=mls, ml_reasons=mlr, reasons="; ".join(rr) or "No concerns", programmes=s["progs"]))
    where = "WHERE resolved=0" + (" AND inst=?" if inst else "")
    args = (inst,) if inst else ()
    return dict(totals=dict(
        records=c.execute("SELECT COUNT(*) FROM enrol" + (" WHERE inst=?" if inst else ""), args).fetchone()[0],
        institutions=len(out), open_flags=c.execute("SELECT COUNT(*) FROM flags " + where, args).fetchone()[0],
        over_intake=c.execute("SELECT COUNT(*) FROM flags " + where + " AND type='Excess enrolment'", args).fetchone()[0]),
        institutions=out)


def sign(payload: str):
    return hmac.new(RECORD_KEY, payload.encode(), hashlib.sha256).hexdigest()


def make_record(c, apaar=None, student_id=None, inst=None):
    q, a = ("e.apaar=?", (apaar,)) if apaar else ("e.student_id=? AND e.inst=?", (student_id, inst))
    r = c.execute(f"SELECT e.*, i.name iname FROM enrol e JOIN institutions i ON i.id=e.inst WHERE {q} AND e.status='Active'", a).fetchone()
    if not r:
        return None
    payload = json.dumps(dict(apaar=r["apaar"], student_id=r["student_id"], institution=r["iname"], programme=r["prog"],
                              status=r["status"], admitted=r["adm"], issuer="AICTE-SVP", kid="v1"), sort_keys=True, separators=(",", ":"))
    return dict(payload=payload, sig=sign(payload))


def check_record(c, payload, sig):
    valid = hmac.compare_digest(sign(payload), sig or "")
    cur = None
    if valid:
        r = c.execute("SELECT status FROM enrol WHERE apaar=? ORDER BY (status='Active') DESC, id DESC LIMIT 1", (json.loads(payload)["apaar"],)).fetchone()
        cur = r["status"] if r else "Unknown"
    return dict(valid=valid, current_status=cur)


_NF = {}


def request_consent(c, verifier, apaar):
    now = time.time()
    nf = [t for t in _NF.get(verifier, []) if now - t < 900]
    if len(nf) >= 5:
        raise Denied("Too many lookups for unknown IDs. Access paused for 15 minutes.")
    if c.execute("SELECT COUNT(*) FROM consent WHERE verifier=? AND ts>?", (verifier, now - 60)).fetchone()[0] >= 10:
        raise Denied("Rate limit: at most 10 verification requests per minute")
    if c.execute("SELECT COUNT(*) FROM consent WHERE verifier=? AND ts>?", (verifier, now - 86400)).fetchone()[0] >= 200:
        raise Denied("Daily verification limit reached")
    if not c.execute("SELECT 1 FROM enrol WHERE apaar=? AND status='Active'", (apaar,)).fetchone():
        _NF[verifier] = nf + [now]
        if len(nf) + 1 >= 5:
            audit(c, verifier, "ALERT: repeated lookups for unknown APAAR IDs (possible scraping)"); c.commit()
        return None
    otp = f"{random.SystemRandom().randint(0, 999999):06d}"
    cur = c.execute("INSERT INTO consent(apaar,verifier,otp,state,ts) VALUES(?,?,?,?,?)", (apaar, verifier, otp, "pending", now))
    audit(c, verifier, f"Verification requested for APAAR ending {apaar[-4:]}")
    c.commit()
    return cur.lastrowid, otp


def confirm_consent(c, verifier, req_id, otp):
    r = c.execute("SELECT * FROM consent WHERE id=? AND verifier=?", (req_id, verifier)).fetchone()
    if not r or r["state"] != "pending" or time.time() - r["ts"] > 600:
        return None, "Request not found, expired or already handled"
    c.execute("UPDATE consent SET tries=tries+1 WHERE id=?", (req_id,))
    if not hmac.compare_digest(r["otp"], (otp or "").strip()):
        if r["tries"] + 1 >= 3:
            c.execute("UPDATE consent SET state='locked' WHERE id=?", (req_id,))
        c.commit()
        return None, "Wrong code"
    c.execute("UPDATE consent SET state='granted' WHERE id=?", (req_id,))
    audit(c, "student-" + r["apaar"][-4:], f"Consent granted to {verifier} using one-time code")
    c.commit()
    return make_record(c, apaar=r["apaar"]), None


def consent_result(c, verifier, req_id):
    r = c.execute("SELECT * FROM consent WHERE id=? AND verifier=?", (req_id, verifier)).fetchone()
    if not r:
        return None, "Request not found"
    if r["state"] == "granted" and time.time() - r["ts"] < 86400:
        audit(c, verifier, f"Read consented record, APAAR ending {r['apaar'][-4:]}"); c.commit()
        return make_record(c, apaar=r["apaar"]), None
    return None, {"pending": "Waiting for the student to approve", "denied": "The student denied this request",
                  "revoked": "The student revoked access", "locked": "Too many wrong codes",
                  "granted": "Consent expired (24 hours)"}.get(r["state"], "Request expired")


def student_login(c, apaar, dob):
    r = c.execute("SELECT 1 FROM registry WHERE apaar=? AND dob=?", (apaar.strip(), dob.strip())).fetchone()
    return bool(r)


def student_view(c, apaar):
    reg = c.execute("SELECT name FROM registry WHERE apaar=?", (apaar,)).fetchone()
    enr = [dict(r) for r in c.execute("SELECT e.student_id,e.prog,e.adm,e.status,i.name institution FROM enrol e JOIN institutions i ON i.id=e.inst WHERE e.apaar=? ORDER BY e.id", (apaar,))]
    cons = [dict(id=r["id"], verifier=r["verifier"], state=r["state"], when=time.strftime("%Y-%m-%d %H:%M", time.localtime(r["ts"])))
            for r in c.execute("SELECT * FROM consent WHERE apaar=? ORDER BY id DESC LIMIT 50", (apaar,))]
    return dict(apaar=apaar, name=reg["name"] if reg else "", enrolments=enr, consents=cons)


def student_decide(c, apaar, cid, decision):
    r = c.execute("SELECT state FROM consent WHERE id=? AND apaar=?", (cid, apaar)).fetchone()
    nxt = {"approve": ("pending", "granted"), "deny": ("pending", "denied"), "revoke": ("granted", "revoked")}.get(decision)
    if not r or not nxt or r["state"] != nxt[0]:
        raise Denied("This request cannot be changed")
    c.execute("UPDATE consent SET state=? WHERE id=?", (nxt[1], cid))
    audit(c, "student-" + apaar[-4:], f"Consent request {cid} {nxt[1]}")
    c.commit()


def create_api_key(c, inst, label, actor):
    key = "svp_" + secrets.token_urlsafe(24)
    c.execute("INSERT INTO api_keys VALUES(?,?,?,?)", (hashlib.sha256(key.encode()).hexdigest(), inst, label or "ERP", time.strftime("%Y-%m-%d")))
    audit(c, actor, "API key created"); c.commit()
    return key


def api_key_user(c, key):
    r = c.execute("SELECT inst FROM api_keys WHERE key_hash=?", (hashlib.sha256((key or "").encode()).hexdigest(),)).fetchone()
    return {"u": f"api:{r['inst']}", "r": "institution", "i": r["inst"]} if r else None


def respond_flag(c, inst, fid, note, actor):
    n = c.execute("UPDATE flags SET note=?, responded=1 WHERE id=? AND inst=?", (note[:500], fid, inst)).rowcount
    if not n:
        raise Denied("Flag not found for your institution")
    audit(c, actor, f"Responded to flag {fid}"); c.commit()


def anonymise_old(c, years, actor):
    cut = f"{int(time.strftime('%Y')) - int(years)}-01-01"
    ids = [r["id"] for r in c.execute("SELECT id FROM enrol WHERE status!='Active' AND adm<?", (cut,))]
    for i in ids:
        c.execute("UPDATE enrol SET name='ANONYMISED', apaar='ANON'||substr(?,1,8), dob=substr(dob,1,4)||'-01-01' WHERE id=?",
                  (hashlib.sha256(str(i).encode()).hexdigest(), i))
    audit(c, actor, f"Retention: anonymised {len(ids)} closed records older than {years} years"); c.commit()
    return len(ids)


def template_csv():
    return ",".join(COLS) + "\n123456789012,Student Name,2005-04-17,STU-0001,B.Tech CSE,2025-08-12,N,N,N,N,,Active\n"


def sample_csv(c, inst):
    prog = c.execute("SELECT prog FROM intake WHERE inst=? LIMIT 1", (inst,)).fetchone()["prog"]
    free = c.execute("SELECT * FROM registry WHERE apaar NOT IN (SELECT apaar FROM enrol) AND apaar NOT LIKE '5555%' LIMIT 3").fetchall()
    other = c.execute("SELECT apaar,name,dob FROM enrol WHERE inst!=? AND status='Active' LIMIT 1", (inst,)).fetchone()
    base = dict(programme=prog, admission_date="2025-08-20", supernumerary="N", nri="N", oci="N", fn="N", nationality="", status="Active")
    rows = [dict(base, apaar=free[0]["apaar"], name=free[0]["name"], dob=free[0]["dob"], student_id="S-1"),
            dict(base, apaar=free[1]["apaar"], name=free[1]["name"], dob=free[1]["dob"], student_id="S-2"),
            dict(base, apaar=free[1]["apaar"], name=free[1]["name"], dob=free[1]["dob"], student_id="S-3"),
            dict(base, apaar="12345", name="Test Student", dob="2004-01-01", student_id="S-4"),
            dict(base, apaar="", name="No Id", dob="2004-02-02", student_id="S-5"),
            dict(base, apaar="999999999999", name="Ghost Student", dob="2004-03-03", student_id="S-6"),
            dict(base, apaar=free[2]["apaar"], name=free[2]["name"], dob=free[2]["dob"], student_id="S-7", oci="Y", fn="Y", nationality="Other")]
    if other:
        rows.append(dict(base, apaar=other["apaar"], name=other["name"], dob=other["dob"], student_id="S-8"))
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=COLS)
    w.writeheader(); w.writerows(rows)
    return buf.getvalue()


def report_csv(c):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["institution_id", "institution", "state", "programme", "approved_intake", "allowed_with_supernumerary",
                "enrolled", "supernumerary", "nri", "oci", "foreign_national", "open_flags_for_institution"])
    for r in c.execute("SELECT i.id,i.name,i.state,t.prog,t.intake,t.sup_pct FROM intake t JOIN institutions i ON i.id=t.inst ORDER BY i.id"):
        cnt = lambda col: c.execute(f"SELECT COUNT(*) FROM enrol WHERE inst=? AND prog=? AND status='Active' AND {col}='Y'", (r["id"], r["prog"])).fetchone()[0]
        n = c.execute("SELECT COUNT(*) FROM enrol WHERE inst=? AND prog=? AND status='Active'", (r["id"], r["prog"])).fetchone()[0]
        fl = c.execute("SELECT COUNT(*) FROM flags WHERE inst=? AND resolved=0", (r["id"],)).fetchone()[0]
        w.writerow([r["id"], r["name"], r["state"], r["prog"], r["intake"], int(r["intake"] * (1 + r["sup_pct"])), n,
                    cnt("sup"), cnt("nri"), cnt("oci"), cnt("fn"), fl])
    return buf.getvalue()
