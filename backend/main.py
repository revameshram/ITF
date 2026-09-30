"""AegisVision HTTP API + static UI server (localhost only).

    python -m backend.main            # http://127.0.0.1:8000
"""
from __future__ import annotations

from . import netguard

netguard.install()  # before anything else can open a socket

import argparse  # noqa: E402
import mimetypes  # noqa: E402
import socket  # noqa: E402
from typing import Optional  # noqa: E402

from fastapi import Body, FastAPI, HTTPException, Request  # noqa: E402
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402

from . import config  # noqa: E402
from .adapters.models import available_formats  # noqa: E402
from .core import STREAM, AegisApp  # noqa: E402
from .coverage import coverage_doc  # noqa: E402
from .demo.scenarios import SCENARIOS, run_scenario, scorecard  # noqa: E402
from .evidence.graph import EvidenceGraph  # noqa: E402
from .reports.report import build_report, list_reports  # noqa: E402

# Windows sometimes maps .js to text/plain in the registry, which breaks ES modules.
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("application/javascript", ".mjs")
mimetypes.add_type("text/css", ".css")

CSP = ("default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
       "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'")

_app_state: dict[str, AegisApp] = {}


def aegis() -> AegisApp:
    if "app" not in _app_state:
        _app_state["app"] = AegisApp()
    return _app_state["app"]


api = FastAPI(title="AegisVision", version=config.APP_VERSION, docs_url="/api/docs", redoc_url=None)


@api.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _sev_rank(s):
    return ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(s)


# ----------------------------------------------------------------------------- status / dashboard
@api.get("/api/status")
def status():
    a = aegis()
    run = a.last_run()
    return {"app": config.APP_NAME, "version": config.APP_VERSION, "network": netguard.status(),
            "signer": a.key.public_info(), "overall": run["overall"] if run else "NOT ASSESSED",
            "last_run": run["run_id"] if run else None, "demo_mode": True}


@api.get("/api/dashboard")
def dashboard():
    a = aegis()
    run = a.last_run()
    findings = []
    if run:
        findings = sorted(run["finding_summary"], key=lambda f: -_sev_rank(f["severity"]))
    cases = [{k: c[k] for k in ("id", "title", "severity", "status", "risk_score", "created_at", "recommended_disposition")}
             for c in a.cases()]
    ds = a.load_workspace_dataset()
    reg = a.registry.active()
    recs = a.prov.records()
    graph_counts = None
    if run:
        g = EvidenceGraph.load(a.store, run["run_id"])
        graph_counts = {"nodes": len(g["nodes"]), "edges": len(g["edges"])}
    return {
        "overall": run["overall"] if run else "NOT ASSESSED",
        "run": None if not run else {k: run[k] for k in ("run_id", "started", "finished", "seconds", "statuses", "case_id")},
        "pending_scenarios": a.store.kv_get("pending_scenarios", []),
        "pipeline": {
            "dataset": {"name": ds.name, "format": ds.format, "samples": len(ds.samples),
                        "contributors": len({s.contributor for s in ds.samples if s.contributor}),
                        "batches": len({s.batch for s in ds.samples if s.batch})},
            "model": {"active": reg["model_id"] if reg else None, "version": reg["version"] if reg else None,
                      "access": a.model_access(), "sha256": a.adapter().digest(),
                      "versions": [{k: v[k] for k in ("model_id", "active", "manifest_valid")} for v in a.registry.summary()]},
            "inference": {"stream": STREAM, "records": len(recs)},
        },
        "findings": findings[:10],
        "cases": cases[:6],
        "timeline": a.audit.records(limit=18),
        "graph": graph_counts,
        "network": netguard.status(),
        "audit_head": a.store.kv_get("audit_head"),
        "scorecard": scorecard(run) if run else [],
    }


@api.post("/api/system/netcheck")
def netcheck():
    """Prove the offline guard: try to open an outbound TCP connection (it must be blocked)."""
    a = aegis()
    target = ("203.0.113.10", 443)  # TEST-NET-3 documentation address; never routed
    try:
        s = socket.create_connection(target, timeout=1)
        s.close()
        result = {"blocked": False, "detail": "outbound connection succeeded — guard NOT active"}
    except netguard.NetworkBlocked as e:
        result = {"blocked": True, "detail": str(e)}
    except OSError as e:
        result = {"blocked": False, "detail": f"connection failed for another reason: {e}"}
    a.audit.append("network.egress_test", "analyst", "assurance:core", result)
    return result | {"status": netguard.status()}


# ----------------------------------------------------------------------------- assurance runs
@api.post("/api/assurance/run")
def run_assurance():
    run = aegis().run_assurance(actor="analyst")
    return {k: run[k] for k in ("run_id", "overall", "statuses", "finding_summary", "case_id", "seconds", "checks")} | \
        {"scorecard": scorecard(run)}


@api.get("/api/runs")
def runs():
    return aegis().runs()


@api.get("/api/runs/{run_id}")
def get_run(run_id: str):
    r = aegis()._get_run(run_id)
    if not r:
        raise HTTPException(404)
    return r


@api.get("/api/runs/latest/full")
def latest_run():
    r = aegis().last_run()
    return r or {}


# ----------------------------------------------------------------------------- findings / evidence / graph
@api.get("/api/findings")
def findings(run_id: Optional[str] = None):
    a = aegis()
    run_id = run_id or a.store.kv_get("last_run_id")
    if not run_id:
        return []
    return sorted(a.store.list_docs("findings", "run_id=?", (run_id,)), key=lambda f: (-_sev_rank(f["severity"]), f["id"]))


@api.get("/api/findings/{fid}")
def finding(fid: str):
    a = aegis()
    f = a.store.get_doc("findings", fid)
    if not f:
        raise HTTPException(404)
    f["evidence_docs"] = [a.store.get_doc("evidence", e) for e in f["evidence"]]
    return f


@api.get("/api/evidence")
def evidence_list(run_id: Optional[str] = None):
    a = aegis()
    run_id = run_id or a.store.kv_get("last_run_id")
    if not run_id:
        return []
    return [{k: e[k] for k in ("id", "finding_id", "kind", "title", "summary", "sha256", "assets")}
            for e in a.store.list_docs("evidence", "run_id=?", (run_id,))]


@api.get("/api/evidence/{eid}")
def evidence(eid: str):
    e = aegis().store.get_doc("evidence", eid)
    if not e:
        raise HTTPException(404)
    return e


@api.get("/api/graph")
def graph(run_id: Optional[str] = None):
    a = aegis()
    run_id = run_id or a.store.kv_get("last_run_id")
    if not run_id:
        return {"nodes": [], "edges": []}
    return EvidenceGraph.load(a.store, run_id)


# ----------------------------------------------------------------------------- cases
@api.get("/api/cases")
def cases():
    return [{k: c.get(k) for k in ("id", "title", "severity", "status", "risk_score", "created_at", "run_id",
                                   "recommended_disposition", "disposition", "findings")} for c in aegis().cases()]


@api.get("/api/cases/{case_id}")
def case(case_id: str):
    c = aegis().case(case_id)
    if not c:
        raise HTTPException(404)
    return c


@api.post("/api/cases/{case_id}/disposition")
def disposition(case_id: str, body: dict = Body(...)):
    try:
        return aegis().set_disposition(case_id, body.get("disposition", ""), body.get("note", ""), "analyst")
    except (KeyError, ValueError) as e:
        raise HTTPException(400, str(e))


# ----------------------------------------------------------------------------- dataset / model / inference
@api.get("/api/dataset")
def dataset():
    a = aegis()
    ds = a.load_workspace_dataset()
    run = a.last_run()
    samples = [{"sample_id": s.sample_id, "path": s.path.relative_to(a.ws).as_posix(), "label": s.label,
                "contributor": s.contributor, "batch": s.batch} for s in ds.samples]
    return {"summary": ds.summary(), "manifest_digest": a.dataset_manifest()["digest"],
            "registered_manifest_digest": (a.store.kv_get("dataset_manifest") or {}).get("digest"),
            "samples": samples, "last_run": (run or {}).get("stats", {}).get("dataset"),
            "findings": [f for f in (findings() if run else []) if f["pillar"] == "dataset"],
            "checks": [c for c in (run or {}).get("checks", []) if c["pillar"] == "dataset"]}


@api.get("/api/models")
def models():
    a = aegis()
    run = a.last_run()
    ad = a.adapter()
    return {"registry": a.registry.summary(), "deployed": ad.describe() | {"sha256": ad.digest()},
            "access": a.model_access(), "formats": available_formats(),
            "last_run": (run or {}).get("stats", {}).get("model"),
            "findings": [f for f in (findings() if run else []) if f["pillar"] == "model"],
            "checks": [c for c in (run or {}).get("checks", []) if c["pillar"] == "model"]}


@api.post("/api/models/access")
def set_access(body: dict = Body(...)):
    acc = body.get("access")
    if acc not in ("white-box", "black-box"):
        raise HTTPException(400, "access must be white-box or black-box")
    aegis().set_model_access(acc)
    return {"access": acc}


@api.get("/api/inferences")
def inferences():
    a = aegis()
    ver = a.prov.verify_stream(input_root=a.ws, registered_models=a.registry.all())
    vmap = {r["record_id"]: r for r in ver["results"]}
    out = []
    for r in a.prov.records():
        v = vmap[r["record_id"]]
        out.append({"record_id": r["record_id"], "seq": r["seq"], "stream": r["stream"], "timestamp": r["timestamp"],
                    "label": r["output"].get("label"), "confidence": r["output"].get("confidence"),
                    "input_ref": r["input_ref"], "model_sha256": r["bindings"]["model_sha256"],
                    "signer": r["signer"]["key_id"], "verdict": v["verdict"], "failures": v["failure_categories"]})
    run = a.last_run()
    return {"records": out, "ingest_log": a.prov.ingest_log(), "trusted_keys": list(a.prov.trusted_keys),
            "summary": {"total": ver["total"], "valid": ver["valid"], "invalid": ver["invalid"]},
            "last_run": (run or {}).get("stats", {}).get("inference"),
            "distribution": (run or {}).get("stats", {}).get("distribution")}


@api.get("/api/inferences/{record_id}")
def inference(record_id: str):
    r = aegis().prov.get(record_id)
    if not r:
        raise HTTPException(404)
    return r


@api.post("/api/inferences/{record_id}/verify")
def verify(record_id: str):
    return aegis().verify_one(record_id)


@api.post("/api/inferences/ingest")
def ingest(record: dict = Body(...)):
    a = aegis()
    res = a.prov.ingest(record)
    a.audit.append("ingest.accepted" if res["accepted"] else "ingest.rejected", "edge:client", f"stream:{record.get('stream')}",
                   {"record_id": res["record_id"], "reasons": res["reasons"]})
    return res


@api.post("/api/inferences/run")
def run_frames(body: dict = Body(...)):
    a = aegis()
    kind = body.get("frames", "day")
    count = int(body.get("count", 10))
    folder = {"day": "day", "night": "night", "triggered": "triggered"}.get(kind)
    if not folder:
        raise HTTPException(400, "frames must be day|night|triggered")
    files = sorted((a.ws / "observation" / folder).glob("*.png"))
    start = int(a.store.kv_get(f"frame_cursor_{folder}", 0))
    pick = [files[(start + i) % len(files)] for i in range(min(count, 60))]
    a.store.kv_set(f"frame_cursor_{folder}", start + len(pick))
    recs = a.run_inferences([p.relative_to(a.ws).as_posix() for p in pick], actor="edge:cam-01")
    return {"created": len(recs), "records": [{"record_id": r["record_id"], "seq": r["seq"], "label": r["output"]["label"]} for r in recs]}


# ----------------------------------------------------------------------------- audit
@api.get("/api/audit")
def audit(limit: int = 300):
    return aegis().audit.records(limit=limit)


@api.post("/api/audit/verify")
def audit_verify():
    a = aegis()
    v = a.audit.verify()
    return v


# ----------------------------------------------------------------------------- attack lab / demo
@api.get("/api/attacklab/scenarios")
def scenarios():
    return [{"id": s.id, "name": s.name, "pillar": s.pillar, "description": s.description, "expected": s.expected,
             "featured": s.featured} for s in SCENARIOS]


@api.post("/api/attacklab/run/{scenario_id}")
def attack(scenario_id: str):
    if scenario_id not in {s.id for s in SCENARIOS}:
        raise HTTPException(404)
    return run_scenario(aegis(), scenario_id)


@api.post("/api/demo/reset")
def reset():
    return aegis().reset_demo()


# ----------------------------------------------------------------------------- reports / coverage
@api.post("/api/reports")
def make_report(body: dict = Body(default={})):
    try:
        r = build_report(aegis(), body.get("case_id"))
    except (KeyError, ValueError) as e:
        raise HTTPException(400, str(e))
    return {"report_id": r["report_id"], "sha256": r["integrity"]["report_sha256"]}


@api.get("/api/reports")
def reports():
    return list_reports()


@api.get("/api/reports/{name}")
def report_file(name: str):
    p = (config.REPORTS_DIR / name).resolve()
    if p.parent != config.REPORTS_DIR.resolve() or not p.exists() or p.suffix not in (".json", ".html"):
        raise HTTPException(404)
    if p.suffix == ".html":
        return HTMLResponse(p.read_text(encoding="utf-8"),
                            headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
    return FileResponse(p, media_type="application/json", filename=p.name)


@api.get("/api/coverage")
def coverage():
    return coverage_doc() | {"formats": available_formats()}


# ----------------------------------------------------------------------------- images
@api.get("/api/image")
def image(path: str):
    a = aegis()
    for root in (a.ws, config.DEMO_DIR):
        p = (root / path).resolve()
        if str(p).startswith(str(root.resolve())) and p.is_file() and p.suffix.lower() in (".png", ".jpg", ".jpeg"):
            return FileResponse(p, media_type="image/png", headers={"Cache-Control": "no-store"})
    raise HTTPException(404)


# ----------------------------------------------------------------------------- UI
api.mount("/static", StaticFiles(directory=str(config.FRONTEND)), name="static")


@api.get("/")
def index():
    return FileResponse(config.FRONTEND / "index.html")


@api.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):  # pragma: no cover
    return JSONResponse({"error": type(exc).__name__, "detail": str(exc)}, status_code=500)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="AegisVision — offline AI assurance workbench")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--open", action="store_true", help="open the UI in the default browser")
    args = ap.parse_args(argv)
    import uvicorn
    print(f"\n  AegisVision {config.APP_VERSION} - OFFLINE / AIR-GAPPED MODE")
    print("  Preparing demo assets and workspace (first start may take ~20 s)...")
    aegis()
    url = f"http://127.0.0.1:{args.port}"
    print(f"  Ready: {url}   (press Ctrl+C to stop)\n")
    if args.open:
        import threading
        import webbrowser
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    uvicorn.run(api, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()

