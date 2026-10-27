"""Automated checks for the core logic. Run: python test_core.py"""
import os, tempfile, csv, io, time
os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "t.db")
import core
core.init()
c = core.db()
ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg) or (cond or exit(1))

d = core.dashboard(c); t = d["totals"]
ok(t["records"] > 600 and t["institutions"] == 10, f"demo loaded: {t}")
top = max(d["institutions"], key=lambda i: i["risk"])
ok(top["id"] == "KA-022" and top["risk"] >= 50 and top["ml_reasons"], f"riskiest is KA-022 with ML reasons: {top['ml_reasons'][:2]}")
types = {r["type"] for r in c.execute("SELECT type FROM flags")}
ok({"Excess enrolment", "Cross-institution duplicate", "Data inconsistency", "Potential duplicate identity"} <= types, f"flag types {types}")

rows = list(csv.DictReader(io.StringIO(core.sample_csv(c, "RJ-001"))))
rep = core.process_rows(c, "RJ-001", rows, "rj001")
msgs = " | ".join(i["issue"] for i in rep["issues"])
for m in ["Invalid APAAR format", "Missing APAAR", "not found in registry", "Duplicate APAAR in this file", "Conflicting NRI", "cross-institution"]:
    ok(m in msgs, "upload catches: " + m)

# configurable rules: block admissions beyond allowed seats
core.set_rule(c, "intake_exceeded", "reject", "", "aicte")
free = c.execute("SELECT * FROM registry WHERE apaar NOT IN (SELECT apaar FROM enrol) AND apaar NOT LIKE '5555%' LIMIT 2").fetchall()
row = lambda r: dict(apaar=r["apaar"], name=r["name"], dob=r["dob"], student_id="Z", programme="B.Tech CSE", admission_date="2025-08-20", status="Active")
rep = core.process_rows(c, "KA-022", [row(free[0])], "ka022")   # KA-022 B.Tech CSE is already above its limit
ok(rep["rejected"] == 1 and "Programme is full" in rep["issues"][0]["issue"], "full programme blocks new admission when rule = reject")
core.set_rule(c, "intake_exceeded", "flag", "", "aicte")
try: core.set_rule(c, "bad_format", "off", "", "aicte"); ok(False, "fixed rule cannot be disabled")
except core.Denied: ok(True, "fixed rule cannot be disabled")
core.set_rule(c, "not_in_registry", "flag", "", "aicte")
rep = core.process_rows(c, "RJ-001", [dict(row(free[1]), apaar="888888888888")], "rj001")
ok(rep["accepted"] == 1, "APAAR grace period: unknown ID accepted with a flag when rule = flag")
core.set_rule(c, "not_in_registry", "reject", "", "aicte")

# consent, student portal, revocation
apaar = c.execute("SELECT apaar FROM enrol WHERE student_id='MH-014-0020'").fetchone()[0]
dob = c.execute("SELECT dob FROM registry WHERE apaar=?", (apaar,)).fetchone()[0]
ok(core.student_login(c, apaar, dob) and not core.student_login(c, apaar, "1999-01-01"), "student login needs APAAR + DOB")
rid, otp = core.request_consent(c, "verifier", apaar)
ok(core.consent_result(c, "verifier", rid)[0] is None, "no record before consent")
ok(core.confirm_consent(c, "verifier", rid, "000000")[1] == "Wrong code", "wrong OTP rejected")
core.student_decide(c, apaar, rid, "approve")
rec, err = core.consent_result(c, "verifier", rid)
ok(rec and core.check_record(c, rec["payload"], rec["sig"])["valid"], "student approval releases signed record")
core.student_decide(c, apaar, rid, "revoke")
ok(core.consent_result(c, "verifier", rid)[1] == "The student revoked access", "revocation blocks the verifier")
ok(not core.check_record(c, rec["payload"].replace("Active", "Graduated"), rec["sig"])["valid"], "tampered record fails")
ok(len(core.student_view(c, apaar)["consents"]) == 1, "student sees who requested access")

# scraping defence
for i in range(5): core.request_consent(c, "scraper", f"00000000000{i}")
try: core.request_consent(c, "scraper", "000000000009"); ok(False, "scraper locked")
except core.Denied: ok(True, "repeated unknown-ID lookups lock the verifier")
ok("ALERT" in " ".join(r["action"] for r in c.execute("SELECT action FROM audit")), "scraping alert in audit log")

# API key, flag response, status update, retention, audit chain
key = core.create_api_key(c, "RJ-001", "ERP", "rj001")
ok(core.api_key_user(c, key)["i"] == "RJ-001" and core.api_key_user(c, "nope") is None, "API key authenticates institution only")
fid = c.execute("SELECT id FROM flags WHERE inst='KA-022' LIMIT 1").fetchone()[0]
core.respond_flag(c, "KA-022", fid, "Checked with registrar", "ka022")
try: core.respond_flag(c, "RJ-001", fid, "x", "rj001"); ok(False, "other institution blocked")
except core.Denied: ok(True, "institution cannot answer another institution's flag")
core.process_rows(c, "MH-014", [dict(apaar=apaar, status="Graduated")], "mh014")
ok(core.anonymise_old(c, 0, "aicte") >= 1, "retention anonymises closed records")
ok(core.audit_chain_ok(c), "audit hash chain intact")
c.execute("UPDATE audit SET action='tampered' WHERE id=3"); c.commit()
ok(not core.audit_chain_ok(c), "audit tampering is detected")
ok(core.report_csv(c).count("\n") == 21 and "apaar,name" in core.template_csv(), "report and template generated")
print("ALL TESTS PASSED")
