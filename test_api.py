"""End-to-end API test (needs: pip install httpx). Run: python test_api.py"""
import os, tempfile
os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "api.db")
from fastapi.testclient import TestClient
from app import app

with TestClient(app) as c:
    tok = lambda u, p: {"Authorization": "Bearer " + c.post("/api/login", json={"username": u, "password": p}).json()["token"]}
    assert c.get("/api/health").json()["status"] == "ok"
    assert c.post("/api/login", json={"username": "aicte", "password": "wrong"}).status_code == 401
    assert c.get("/api/dashboard").status_code == 401
    adm, inst, ver = tok("aicte", "aicte123"), tok("rj001", "inst123"), tok("verifier", "verifier123")
    d = c.get("/api/dashboard", headers=adm).json()
    assert d["totals"]["institutions"] == 10 and max(i["risk"] for i in d["institutions"]) >= 50
    assert c.get("/api/dashboard", headers=inst).json()["institutions"][0]["id"] == "RJ-001"
    assert c.get("/api/audit", headers=inst).status_code == 403
    sample = c.get("/api/sample", headers=inst).text
    rep = c.post("/api/upload", headers=inst, files={"file": ("u.csv", sample, "text/csv")}).json()
    assert rep["rejected"] >= 3 and rep["flagged"] >= 1
    h = c.get("/api/demo/hint").json()
    s = c.post("/api/student/login", json={"apaar": h["apaar"], "dob": h["dob"]}).json()
    sh = {"Authorization": "Bearer " + s["token"]}
    r = c.post("/api/verify/request", headers=ver, json={"apaar": h["apaar"]}).json()
    assert c.post("/api/verify/confirm", headers=ver, json={"request_id": r["request_id"]}).status_code == 400
    assert c.post(f"/api/student/consent/{r['request_id']}/approve", headers=sh).status_code == 200
    rec = c.post("/api/verify/confirm", headers=ver, json={"request_id": r["request_id"]}).json()
    assert c.post("/api/record/check", json={"payload": rec["payload"], "sig": rec["sig"]}).json()["valid"]
    assert c.get("/api/report.csv", headers=adm).text.startswith("institution_id")
    assert c.get("/").status_code == 200
print("API END-TO-END TEST PASSED")
