"""AegisVision core: the assurance pipeline orchestrator.

    Load dataset/model -> run audit -> findings -> evidence -> correlate
    -> case -> verify inference -> report

`AegisApp` owns every service (store, keys, audit log, provenance, model
registry, analyzers) and the live *workspace* that the Attack Lab mutates.
"""
from __future__ import annotations

import json
import shutil
import threading
import time
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image

from . import config
from .adapters.datasets import load_dataset
from .adapters.models import load_model
from .analyzers.dataset import DatasetAnalyzer
from .analyzers.findings import REAL, SEVERITIES, CheckRecord, Evidence, Finding
from .analyzers.model import ModelAnalyzer
from .analyzers.shift import ShiftAnalyzer
from .cases.cases import DISPOSITIONS, build_case
from .crypto.audit import AuditLog, utcnow
from .crypto.keys import SigningKey, sha256_file, sha256_json
from .crypto.provenance import ProvenanceService
from .evidence.graph import EvidenceGraph, chains, correlate, subgraph
from .registry import ModelRegistry
from .store import Store

STREAM = "cam-01"
WINDOW = 60
MODEL_FILES = {
    "clean": "aegis-classifier-v1.onnx",
    "backdoored": "aegis-classifier-v1-backdoored.onnx",
    "substitute": "aegis-classifier-v1-substitute.onnx",
}


def _load_img(path: Path) -> np.ndarray:
    with Image.open(path) as im:
        return np.asarray(im.convert("RGB"), dtype=np.uint8)


class AegisApp:
    def __init__(self, generated_dir: Path | None = None):
        if generated_dir is not None:
            config.GENERATED = Path(generated_dir)
            config.WORKSPACE = config.GENERATED / "workspace"
            config.KEYS_DIR = config.GENERATED / "keys"
            config.REPORTS_DIR = config.GENERATED / "reports"
            config.DB_PATH = config.GENERATED / "aegis.db"
        config.ensure_dirs()
        from .demo.generate import ensure_demo_assets
        ensure_demo_assets()
        self.ws = config.WORKSPACE
        self.store = Store(config.DB_PATH)
        self.key = SigningKey.load_or_create(config.KEYS_DIR / "signer.pem", "aegis-local-signer")
        self.audit = AuditLog(self.store, self.key)
        self.prov = ProvenanceService(self.store, self.key)
        self.registry = ModelRegistry(self.store, self.key)
        self.lock = threading.RLock()
        # trusted reference battery (read-only, never touched by the Attack Lab)
        self.reference = load_dataset(config.DEMO_REFERENCE, "reference-battery")
        self.ref_imgs = [s.load() for s in self.reference.samples]
        self.battery = np.stack(self.ref_imgs)
        self.battery_labels = np.array([config.CLASSES.index(s.label) for s in self.reference.samples])
        self.battery_digest = sha256_json(sorted(sha256_file(s.path) for s in self.reference.samples))
        self._dataset_analyzer: DatasetAnalyzer | None = None
        self._shift_analyzer: ShiftAnalyzer | None = None
        self._adapter_cache: dict[tuple, Any] = {}
        if not self.store.kv_get("initialized"):
            self.reset_demo(actor="system")

    # ================================================================ workspace
    @property
    def deployed_model_path(self) -> Path:
        return self.ws / "models" / "deployed.onnx"

    def model_access(self) -> str:
        return self.store.kv_get("model_access", "white-box")

    def set_model_access(self, access: str, actor: str = "analyst") -> None:
        assert access in ("white-box", "black-box")
        self.store.kv_set("model_access", access)
        self.audit.append("model.access_level_changed", actor, "model:deployed", {"access": access})

    def adapter(self, path: Path | None = None, access: str | None = None):
        path = path or self.deployed_model_path
        access = access or self.model_access()
        key = (str(path), sha256_file(path), access)
        if key not in self._adapter_cache:
            self._adapter_cache[key] = load_model(path, access=access)
        return self._adapter_cache[key]

    def deploy_model(self, source: Path, actor: str, note: str = "") -> str:
        dst = self.deployed_model_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dst)
        card = source.with_suffix(".card.json")
        if card.exists():
            shutil.copyfile(card, dst.with_suffix(".card.json"))
        digest = sha256_file(dst)
        self.audit.append("model.deployed", actor, f"modelver:{digest[:12]}",
                          {"file": source.name, "sha256": digest, "note": note})
        return digest

    def dataset_root(self) -> Path:
        return self.ws / "dataset"

    def dataset_manifest(self) -> dict:
        root = self.dataset_root()
        files = {p.name: sha256_file(p) for p in sorted((root / "images").iterdir())}
        ann = sha256_file(root / "annotations.coco.json")
        return {"files": files, "annotations_sha256": ann,
                "digest": sha256_json({"files": files, "annotations": ann}), "count": len(files)}

    def load_workspace_dataset(self):
        return load_dataset(self.dataset_root(), "contributed-dataset")

    def append_to_dataset(self, payload_dir: Path, items: list[dict]) -> None:
        """Add a contributed batch (COCO entries + images) to the workspace dataset."""
        root = self.dataset_root()
        coco_p = root / "annotations.coco.json"
        coco = json.loads(coco_p.read_text(encoding="utf-8"))
        cid = {c["name"]: c["id"] for c in coco["categories"]}
        next_img = max(i["id"] for i in coco["images"]) + 1
        next_ann = max(a["id"] for a in coco["annotations"]) + 1
        for it in items:
            shutil.copyfile(payload_dir / "images" / it["file"], root / "images" / it["file"])
            coco["images"].append({"id": next_img, "file_name": it["file"], "width": 48, "height": 48,
                                   "aegis_source": {"contributor": it["contributor"], "batch": it["batch"]}})
            coco["annotations"].append({"id": next_ann, "image_id": next_img, "category_id": cid[it["label"]],
                                        "bbox": it["bbox"], "area": it["bbox"][2] * it["bbox"][3], "iscrowd": 0})
            next_img += 1
            next_ann += 1
        coco_p.write_text(json.dumps(coco, indent=1), encoding="utf-8")

    # ================================================================ reset / demo
    def reset_demo(self, actor: str = "analyst") -> dict:
        with self.lock:
            t0 = time.time()
            if self.ws.exists():
                shutil.rmtree(self.ws)
            self.ws.mkdir(parents=True)
            shutil.copytree(config.DEMO_DATASET, self.ws / "dataset")
            shutil.copytree(config.DEMO_OBSERVATION, self.ws / "observation")
            self.store.reset_all()
            self._adapter_cache.clear()
            self.audit.append("system.demo_initialized", actor, "assurance:core",
                              {"mode": "DEMO / SIMULATED", "signer_key_id": self.key.key_id,
                               "note": "workspace restored to the clean demo pipeline"})
            man = self.dataset_manifest()
            self.store.kv_set("dataset_manifest", man)
            ds = self.load_workspace_dataset()
            self.audit.append("dataset.imported", actor, "dataset:contributed-dataset",
                              {"format": ds.format, "samples": len(ds.samples), "manifest_digest": man["digest"],
                               "contributors": sorted({s.contributor for s in ds.samples if s.contributor})})
            src = config.DEMO_MODELS / MODEL_FILES["clean"]
            digest = self.deploy_model(src, actor, "initial approved model")
            reg = self.registry.register(self.adapter(src, "white-box"), model_id="M-v1.0", battery=self.battery,
                                         battery_labels=self.battery_labels, battery_digest=self.battery_digest,
                                         lineage={"trained_on_dataset_digest": man["digest"],
                                                  "trained_on_sources": sorted({s.batch for s in ds.samples if s.batch}),
                                                  "previous_version": None},
                                         notes="Approved baseline model (DEMO)",
                                         artifact=str(src.relative_to(config.ROOT).as_posix()))
            self.audit.append("model.registered", actor, "model:M-v1.0",
                              {"sha256": digest, "manifest_sha256": reg["manifest_sha256"],
                               "fingerprint": reg["fingerprint"]["fingerprint_sha256"],
                               "reference_accuracy": reg["fingerprint"]["accuracy"]})
            self.store.kv_set("model_access", "white-box")
            self.run_inferences([f"observation/day/day_{i:04d}.png" for i in range(40)], actor="edge:cam-01")
            self.store.kv_set("initialized", True)
            self.store.kv_set("pending_scenarios", [])
            self.store.kv_set("last_run_id", None)
            return {"reset": True, "seconds": round(time.time() - t0, 2)}

    # ================================================================ inference service
    def run_inferences(self, rel_paths: list[str], actor: str = "edge:cam-01", stream: str = STREAM) -> list[dict]:
        adapter = self.adapter()
        digest = adapter.digest()
        imgs = [_load_img(self.ws / p) for p in rel_paths]
        probs = adapter.predict(np.stack(imgs))
        recs = []
        classes = adapter.classes or config.CLASSES
        for p, pr in zip(rel_paths, probs):
            out = {"label": classes[int(pr.argmax())], "confidence": round(float(pr.max()), 4),
                   "scores": {c: round(float(v), 4) for c, v in zip(classes, pr)}}
            rec = self.prov.create_record(
                input_bytes=(self.ws / p).read_bytes(), input_ref=p, model_sha256=digest,
                model_ref={"file": adapter.path.name, "name": adapter.card.get("name"), "version": adapter.card.get("version")},
                preprocess=adapter.preprocess_cfg,
                inference_config={"task": "classification", "top_k": 1, "threshold": 0.0, "runtime": adapter.format_name},
                output=out, stream=stream)
            recs.append(rec)
        if recs:
            self.audit.append("inference.batch_recorded", actor, f"stream:{stream}",
                              {"count": len(recs), "first": recs[0]["record_id"], "last": recs[-1]["record_id"],
                               "first_seq": recs[0]["seq"], "last_seq": recs[-1]["seq"], "model_sha256": digest})
        return recs

    def registered_artifact(self, digest: str) -> Path | None:
        for m in self.registry.all().values():
            if m["sha256"] == digest:
                p = config.ROOT / m["artifact"]
                if p.exists() and sha256_file(p) == digest:
                    return p
        return None

    def verify_records(self, record_ids: list[str] | None = None, reexecute: bool = True) -> dict:
        res = self.prov.verify_stream(input_root=self.ws, registered_models=self.registry.all())
        if record_ids:
            res["results"] = [r for r in res["results"] if r["record_id"] in record_ids]
        if reexecute:
            recs = {r["record_id"]: r for r in self.prov.records()}
            groups: dict[str, list] = {}
            for r in res["results"]:
                rec = recs[r["record_id"]]
                inp = next((c for c in r["checks"] if c["check"] == "input_binding"), None)
                if inp and inp["status"] == "pass":
                    groups.setdefault(rec["bindings"]["model_sha256"], []).append((r, rec))
            for digest, items in groups.items():
                art = self.registered_artifact(digest)
                if art is None:
                    for r, _ in items:
                        r["checks"].append({"check": "re_execution", "status": "skipped", "category": "REEXEC_MISMATCH",
                                            "detail": "no trusted registered artefact with this digest to re-execute"})
                    continue
                ad = self.adapter(art, "white-box")
                probs = ad.predict(np.stack([_load_img(self.ws / rec["input_ref"]) for _, rec in items]))
                for (r, rec), pr in zip(items, probs):
                    lab = (ad.classes or config.CLASSES)[int(pr.argmax())]
                    ok = lab == rec["output"].get("label")
                    r["checks"].append({"check": "re_execution", "status": "pass" if ok else "fail",
                                        "category": "REEXEC_MISMATCH",
                                        "detail": f"re-ran registered model on the bound input: '{lab}' "
                                                  f"vs recorded '{rec['output'].get('label')}'"})
            for r in res["results"]:
                failed = [c for c in r["checks"] if c["status"] == "fail"]
                r["verdict"] = "INVALID" if failed else "VALID"
                r["failure_categories"] = sorted({c["category"] for c in failed})
            res["invalid"] = sum(r["verdict"] == "INVALID" for r in res["results"])
            res["valid"] = len(res["results"]) - res["invalid"]
            res["total"] = len(res["results"])
        return res

    def verify_one(self, record_id: str, actor: str = "analyst") -> dict:
        res = self.verify_records([record_id])
        out = res["results"][0] if res["results"] else {"record_id": record_id, "verdict": "NOT_FOUND", "checks": []}
        out["record"] = self.prov.get(record_id)
        self.audit.append("inference.verified", actor, f"inference:{record_id}",
                          {"verdict": out["verdict"], "failures": out.get("failure_categories", [])})
        return out

    # ================================================================ assurance run
    def _analyzers(self):
        if self._dataset_analyzer is None:
            self._dataset_analyzer = DatasetAnalyzer(self.reference, self.ws)
        if self._shift_analyzer is None:
            self._shift_analyzer = ShiftAnalyzer(self.ref_imgs)
        return self._dataset_analyzer, self._shift_analyzer

    def run_assurance(self, actor: str = "analyst") -> dict:
        with self.lock:
            return self._run_assurance(actor)

    def _run_assurance(self, actor: str) -> dict:
        t0 = time.time()
        run_id = self.store.next_id("run", "RUN-", 4)
        prev_run_id = self.store.kv_get("last_run_id")
        since_seq = 0
        if prev_run_id:
            prev = self._get_run(prev_run_id)
            since_seq = (prev or {}).get("audit_seq_end", 0)
        started = self.audit.append("assurance.run_started", actor, "assurance:core", {"run_id": run_id})
        dsa, sha = self._analyzers()
        all_findings: list[Finding] = []
        checks: list[CheckRecord] = []
        stats: dict[str, Any] = {}

        # ------------------------------------------------ 1 dataset
        ds = self.load_workspace_dataset()
        dres = dsa.run(ds)
        man_now = self.dataset_manifest()
        man_reg = self.store.kv_get("dataset_manifest") or man_now
        added = sorted(set(man_now["files"]) - set(man_reg["files"]))
        removed = sorted(set(man_reg["files"]) - set(man_now["files"]))
        modified = sorted(f for f in set(man_now["files"]) & set(man_reg["files"]) if man_now["files"][f] != man_reg["files"][f])
        by_batch: dict[str, int] = {}
        smap = {s.path.name: s for s in ds.samples}
        for f in added:
            b = smap[f].batch if f in smap else "unknown"
            by_batch[b] = by_batch.get(b, 0) + 1
        checks.append(CheckRecord("dataset", "manifest_integrity", "ran", REAL,
                                  f"+{len(added)} added, -{len(removed)} removed, {len(modified)} modified since import"))
        if modified or removed:
            all_findings.append(Finding(
                "dataset", "dataset.silent_modification", f"{len(modified)} existing images modified / {len(removed)} removed",
                what=f"Files already accepted into the dataset changed after import: {', '.join((modified + removed)[:6])}…",
                why="Accepted training data should be immutable; silent edits bypass contribution review.",
                severity="HIGH", confidence=1.0, confidence_basis="Deterministic SHA-256 manifest comparison.",
                method="SHA-256 dataset manifest diff", method_status=REAL, affected=["dataset:contributed-dataset"],
                limitations=["Shows that files changed, not who changed them."],
                evidence=[Evidence("manifest_diff", "Dataset manifest diff", "changed files",
                                   {"modified": modified[:50], "removed": removed[:50]})],
                recommendation="Restore the affected files from the signed manifest snapshot."))
        stats["dataset"] = dres.stats | {"manifest": {"digest": man_now["digest"], "registered_digest": man_reg["digest"],
                                                      "added": len(added), "added_by_batch": by_batch,
                                                      "removed": len(removed), "modified": len(modified)}}
        all_findings += dres.findings
        checks += dres.checks
        self.audit.append("assurance.dataset_checked", "aegis:dataset-analyzer", "dataset:contributed-dataset",
                          {"run_id": run_id, "samples": len(ds.samples), "findings": len(dres.findings),
                           "counts": dres.stats["counts"]})

        # ------------------------------------------------ 2 model
        adapter = self.adapter()
        digest = adapter.digest()
        reg = self.registry.active()
        model_node = f"model:{reg['model_id']}" if reg and reg["sha256"] == digest else f"modelver:{digest[:12]}"
        mres = ModelAnalyzer(self.registry, self.battery, self.battery_labels, config.CLASSES).run(
            adapter, model_node, dres.stats["trigger_candidates"])
        lineage_sources = (reg or {}).get("lineage", {}).get("new_sources", [])
        for f in mres.findings:
            f.tags.setdefault("model_digest", digest)
            f.tags["lineage_sources"] = lineage_sources
        stats["model"] = mres.stats | {"model_node": model_node, "active_registered": reg["model_id"] if reg else None}
        all_findings += mres.findings
        checks += mres.checks
        self.audit.append("assurance.model_checked", "aegis:model-analyzer", model_node,
                          {"run_id": run_id, "sha256": digest, "access": adapter.access, "findings": len(mres.findings)})

        # ------------------------------------------------ 3 inference provenance
        ver = self.verify_records()
        invalid = [r for r in ver["results"] if r["verdict"] == "INVALID"]
        recs = {r["record_id"]: r for r in self.prov.records()}
        cat_groups: dict[str, list] = {}
        priority = ["FORGED_RECORD", "TAMPERED_OUTPUT", "TAMPERED_RECORD", "TAMPERED_CONFIG", "REPLAY",
                    "MODEL_MISMATCH", "INPUT_MISMATCH", "REEXEC_MISMATCH", "CHAIN_BROKEN"]
        for r in invalid:
            primary = next(c for c in priority if c in r["failure_categories"])
            cat_groups.setdefault(primary, []).append(r)
        meta = {
            "FORGED_RECORD": ("inference.record_replacement", "Forged / replaced inference record", "CRITICAL",
                              "Record is not signed by a trusted key — it was replaced or fabricated."),
            "TAMPERED_OUTPUT": ("inference.tampering", "Inference output tampered", "HIGH",
                                "The stored output no longer matches the output digest that was signed at inference time."),
            "TAMPERED_RECORD": ("inference.tampering", "Inference record modified", "HIGH",
                                "Record contents no longer match the signed record hash."),
            "TAMPERED_CONFIG": ("inference.tampering", "Inference configuration tampered", "HIGH",
                                "Pre-processing / inference configuration differs from the signed digest."),
            "REPLAY": ("inference.replay", "Replayed inference record in the log", "HIGH",
                       "A nonce appears in more than one record: an old record was re-inserted."),
            "MODEL_MISMATCH": ("inference.unregistered_model", "Inferences produced by an unregistered model", "HIGH",
                               "Records are validly signed but bind a model digest that is not in the trusted registry."),
            "INPUT_MISMATCH": ("inference.input_mismatch", "Input image does not match the signed input digest", "HIGH",
                               "The image referenced by the record was altered after inference."),
            "REEXEC_MISMATCH": ("inference.reexecution_mismatch", "Re-execution does not reproduce the recorded output", "MEDIUM",
                                "Running the registered model on the bound input gives a different result."),
            "CHAIN_BROKEN": ("inference.chain_broken", "Inference record chain broken", "HIGH",
                             "A record's link to its predecessor is broken — a record was removed, inserted or replaced."),
        }
        for cat, items in cat_groups.items():
            fcat, title, sev, why = meta[cat]
            ids = [r["record_id"] for r in items]
            seqs = [r["seq"] for r in items]
            all_findings.append(Finding(
                "inference", fcat, f"{title} — {len(items)} record(s)",
                what=f"{len(items)} record(s) in stream {STREAM} fail verification (seq {', '.join(map(str, seqs[:8]))}"
                     f"{'…' if len(seqs) > 8 else ''}). Failed checks: " +
                     ", ".join(sorted({c['check'] for r in items for c in r['checks'] if c['status'] == 'fail'})) + ".",
                why=why + " Verification is cryptographic, so this is proof of modification — not a heuristic.",
                severity=sev, confidence=1.0,
                confidence_basis="Deterministic: SHA-256 / Ed25519 verification is either valid or not.",
                method="Recompute all SHA-256 bindings, record hash, Ed25519 signature, hash-chain link, nonce uniqueness",
                method_status=REAL, affected=[f"stream:{STREAM}"] + [f"inference:{i}" for i in ids[:10]],
                limitations=["Proves the record changed after signing; does not identify who changed it.",
                             "A compromised signing key would allow valid forgeries (key is a file in this prototype)."],
                evidence=[Evidence("verification", f"Verification of {len(items)} record(s)", f"{len(items)} INVALID",
                                   {"results": items[:10]}, [f"inference:{i}" for i in ids[:10]])],
                tags={"record_ids": ids, "record_seqs": seqs, "record_model_digests": sorted({recs[i]["bindings"]["model_sha256"] for i in ids if i in recs})},
                recommendation="Treat affected outputs as untrusted; restore records from a trusted replica and "
                               "investigate write access to the inference log."))
        rejected = [r for r in self.prov.ingest_log() if not r["accepted"]]
        if rejected:
            all_findings.append(Finding(
                "inference", "inference.replay_blocked", f"{len(rejected)} replay / invalid submission(s) rejected at ingest",
                what=f"{len(rejected)} submitted record(s) were rejected: " + "; ".join((r["reason"] or "")[:90] for r in rejected[:3]),
                why="Someone submitted a previously used or invalid record. Protection worked, but the attempt itself is a signal.",
                severity="MEDIUM", confidence=1.0, confidence_basis="Deterministic nonce / sequence / signature checks.",
                method="Nonce registry + monotonic sequence + signature check at ingest", method_status=REAL,
                affected=[f"stream:{STREAM}"],
                limitations=["Replay window is unbounded in this prototype (all nonces are stored)."],
                evidence=[Evidence("ingest_log", "Rejected submissions", f"{len(rejected)} rejected", {"rejected": rejected[-10:]})],
                tags={"record_ids": [r["record_id"] for r in rejected]},
                recommendation="Identify the submitting client; rotate its credentials."))
        checks.append(CheckRecord("inference", "record_verification", "ran", REAL,
                                  f"{ver['valid']}/{ver['total']} records valid"))
        checks.append(CheckRecord("inference", "re_execution", "ran", REAL,
                                  "re-ran the registered model on bound inputs to reproduce outputs"))
        stats["inference"] = {"total": ver["total"], "valid": ver["valid"], "invalid": ver["invalid"],
                              "by_category": {k: len(v) for k, v in cat_groups.items()},
                              "rejected_submissions": len(rejected),
                              "invalid_records": [{"record_id": r["record_id"], "seq": r["seq"],
                                                   "categories": r["failure_categories"]} for r in invalid]}
        self.audit.append("assurance.inference_verified", "aegis:provenance-verifier", f"stream:{STREAM}",
                          {"run_id": run_id, "total": ver["total"], "invalid": ver["invalid"]})

        # ------------------------------------------------ 4 distribution shift (latest window of inputs)
        window = [r for r in self.prov.records(STREAM)][-WINDOW:]
        cur = []
        for r in window:
            p = self.ws / r["input_ref"]
            if p.exists():
                cur.append({"img": _load_img(p), "record_id": r["record_id"], "path": r["input_ref"]})
        sres = sha.run(cur, "window:current", adapter, dres.stats["trigger_candidates"])
        stats["distribution"] = sres.stats
        all_findings += sres.findings
        checks += sres.checks
        self.audit.append("assurance.shift_assessed", "aegis:shift-analyzer", "window:current",
                          {"run_id": run_id, "window": len(cur), "status": sres.stats.get("status")})

        # ------------------------------------------------ 5 governance: audit chain
        av = self.audit.verify()
        stats["audit"] = av
        checks.append(CheckRecord("governance", "audit_chain", "ran", REAL,
                                  "hash chain intact" if av["valid"] else f"chain broken at seq {av['first_break_seq']}"))
        if not av["valid"]:
            all_findings.append(Finding(
                "governance", "governance.audit_tampering", f"Audit log tampering detected at record #{av['first_break_seq']}",
                what=f"{len(av['problems'])} integrity problem(s) in the audit hash chain, first at seq {av['first_break_seq']}: "
                     + av["problems"][0]["detail"],
                why="Historical audit records were altered; the investigation record itself cannot be fully trusted.",
                severity="CRITICAL", confidence=1.0, confidence_basis="Deterministic SHA-256 hash-chain verification.",
                method="SHA-256 hash chain + signed head", method_status=REAL, affected=["assurance:core"],
                limitations=["Detects modification; the original content cannot be recovered from the chain itself."],
                evidence=[Evidence("audit_verification", "Audit chain verification", "chain broken", av)],
                recommendation="Preserve the database for forensics; restore the audit log from a trusted backup."))

        # ------------------------------------------------ assign IDs + persist findings/evidence
        fdocs = []
        for f in all_findings:
            fid = self.store.next_id("finding", "F-")
            d = f.to_dict()
            d["id"] = fid
            d["run_id"] = run_id
            d["detected_at"] = utcnow()
            ev_ids = []
            for e in d["evidence"]:
                eid = self.store.next_id("evidence", "E-")
                e["id"] = eid
                e["finding_id"] = fid
                e["run_id"] = run_id
                e["sha256"] = sha256_json({k: v for k, v in e.items() if k != "sha256"})
                self.store.put_doc("evidence", eid, e, run_id=run_id)
                ev_ids.append(eid)
            d["evidence"] = ev_ids
            self.store.put_doc("findings", fid, d, run_id=run_id)
            fdocs.append(d)
            if d["severity"] != "INFO":
                self.audit.append("finding.created", "aegis:assurance-engine", (d["affected"] or [None])[0],
                                  {"run_id": run_id, "finding": fid, "severity": d["severity"], "title": d["title"],
                                   "method_status": d["method_status"]})

        # ------------------------------------------------ correlate + graph + case
        links = correlate(fdocs)
        chain_ids = chains(fdocs, links)
        if any(l["strength"] == "strong" for l in links):
            self.audit.append("evidence.correlated", "aegis:correlation-engine", "assurance:core",
                              {"run_id": run_id, "strong_links": sum(l["strength"] == "strong" for l in links),
                               "rules": sorted({l["rule"] for l in links if l["strength"] == "strong"})})
        scenarios = self.store.kv_get("pending_scenarios", [])
        graph = self._build_graph(ds, fdocs, links, scenarios, invalid, stats)
        statuses = self._statuses(fdocs, stats)
        overall = self._overall(statuses)
        case_doc = None
        if any(SEVERITIES.index(f["severity"]) >= SEVERITIES.index("MEDIUM") for f in fdocs):
            case_id = self.store.next_id("case", "CASE-", 4)
            run_stub = {"run_id": run_id}
            timeline = self._timeline(since_seq)
            case_doc = build_case(case_id, run_stub, fdocs, links, chain_ids, timeline, scenarios)
            graph.node(f"case:{case_id}", "Case", case_id, severity=case_doc["severity"], status=case_doc["status"])
            for fid in case_doc["findings"]:
                graph.edge(f"finding:{fid}", f"case:{case_id}", "belongs_to")
            ev = self.audit.append("case.created", "aegis:case-manager", f"case:{case_id}",
                                   {"run_id": run_id, "severity": case_doc["severity"], "findings": case_doc["findings"],
                                    "recommended_disposition": case_doc["recommended_disposition"],
                                    "risk_score": case_doc["risk_score"]})
            case_doc["timeline"].append(self._tl(ev))
            seeds = {f"case:{case_id}"} | {f"finding:{x}" for x in case_doc["findings"]}
            case_doc["graph_nodes"] = [n["id"] for n in subgraph({"nodes": [n for n in graph.nodes.values() if n["type"] != "Sample"], "edges": graph.edges}, seeds, 1)["nodes"]]
            self.store.put_doc("cases", case_id, case_doc, run_id=run_id)
        graph.save(self.store, run_id)

        done = self.audit.append("assurance.run_completed", actor, "assurance:core",
                                 {"run_id": run_id, "overall": overall, "statuses": {k: v["status"] for k, v in statuses.items()},
                                  "findings": len(fdocs), "case": case_doc["id"] if case_doc else None,
                                  "seconds": round(time.time() - t0, 2)})
        run = {"run_id": run_id, "started": started["ts"], "finished": done["ts"], "seconds": round(time.time() - t0, 2),
               "actor": actor, "overall": overall, "statuses": statuses, "findings": [f["id"] for f in fdocs],
               "finding_summary": [{k: f[k] for k in ("id", "pillar", "category", "title", "severity", "confidence", "method_status")}
                                   for f in fdocs],
               "case_id": case_doc["id"] if case_doc else None, "checks": [c.to_dict() for c in checks],
               "stats": _jsonable(stats), "scenarios": scenarios, "audit_seq_start": started["seq"],
               "audit_seq_end": done["seq"], "correlations": links}
        self.store.execute("INSERT OR REPLACE INTO runs(run_id, started, doc) VALUES(?,?,?)",
                           (run_id, run["started"], json.dumps(run)))
        self.store.kv_set("last_run_id", run_id)
        self.store.kv_set("pending_scenarios", [])
        return run

    # ---------------------------------------------------------------- helpers
    def _get_run(self, run_id: str) -> dict | None:
        rows = self.store.query("SELECT doc FROM runs WHERE run_id=?", (run_id,))
        return json.loads(rows[0]["doc"]) if rows else None

    def last_run(self) -> dict | None:
        rid = self.store.kv_get("last_run_id")
        return self._get_run(rid) if rid else None

    def runs(self) -> list[dict]:
        return [{k: d[k] for k in ("run_id", "started", "overall", "case_id", "seconds")} | {"statuses": {k: v["status"] for k, v in d["statuses"].items()}}
                for d in (json.loads(r["doc"]) for r in self.store.query("SELECT doc FROM runs ORDER BY started"))]

    @staticmethod
    def _tl(ev: dict) -> dict:
        return {"seq": ev["seq"], "ts": ev["ts"], "event_type": ev["event_type"], "actor": ev["actor"],
                "asset": ev["asset"], "details": ev["details"]}

    def _timeline(self, since_seq: int) -> list[dict]:
        keep = ("dataset.", "model.", "attacklab.", "assurance.", "finding.", "evidence.", "inference.", "case.", "ingest.")
        return [self._tl(e) for e in self.audit.records(since_seq=since_seq) if e["event_type"].startswith(keep)]

    def _statuses(self, fdocs: list[dict], stats: dict) -> dict:
        def by(p):
            return [f for f in fdocs if f["pillar"] == p and f["severity"] != "INFO"]
        sev = lambda fs: max((SEVERITIES.index(f["severity"]) for f in fs), default=-1)
        out = {}
        d = by("dataset")
        if any(f["method_status"] == REAL and f["severity"] in ("HIGH", "CRITICAL") for f in d) or sev(d) >= 4:
            ds = "FAIL"
        elif sev(d) >= 2:
            ds = "WARNING"
        else:
            ds = "PASS"
        out["dataset"] = {"status": ds, "findings": len(d), "label": "Training-data integrity"}
        m = by("model")
        if any(f["category"] in ("model.substitution", "model.manifest_tampered") for f in m):
            ms = "FAIL"
        elif sev(m) >= 2:
            ms = "REVIEW"
        else:
            ms = "PASS"
        caps = stats["model"]["deployed"]["capabilities"]
        coverage = "full" if caps["parameters"] and caps["activations"] else "partial (black-box)"
        out["model"] = {"status": ms, "findings": len(m), "coverage": coverage, "label": "Model integrity"}
        i = by("inference")
        if any(f["category"] != "inference.replay_blocked" for f in i):
            ist = "FAILED"
        elif i:
            ist = "WARNING"
        else:
            ist = "PASS"
        out["inference"] = {"status": ist, "findings": len(i), "label": "Inference provenance",
                            "valid": stats["inference"]["valid"], "total": stats["inference"]["total"]}
        out["distribution"] = {"status": stats["distribution"].get("status", "INSUFFICIENT_DATA"),
                               "attribution": stats["distribution"].get("attribution"), "findings": len(by("distribution")),
                               "label": "Distribution shift"}
        out["governance"] = {"status": "PASS" if stats["audit"]["valid"] else "FAIL", "findings": len(by("governance")),
                             "label": "Audit-trail integrity"}
        return out

    @staticmethod
    def _overall(st: dict) -> str:
        vals = [v["status"] for v in st.values()]
        if any(v in ("FAIL", "FAILED") for v in vals):
            return "UNTRUSTED"
        if all(v == "PASS" for v in vals):
            return "TRUSTED"
        return "REVIEW REQUIRED"

    def _build_graph(self, ds, fdocs, links, scenarios, invalid, stats) -> EvidenceGraph:
        g = EvidenceGraph()
        g.node("assurance:core", "AssuranceCore", "Assurance Core")
        dsn = g.node("dataset:contributed-dataset", "Dataset", "Contributed dataset", samples=len(ds.samples), format=ds.format)
        g.edge(dsn, "assurance:core", "verified_by")
        batches: dict[str, str] = {}
        for s in ds.samples:
            if s.contributor:
                c = g.node(f"contributor:{s.contributor}", "Contributor", s.contributor)
                b = g.node(f"batch:{s.batch}", "Batch", s.batch)
                g.edge(b, c, "contributed_by")
                g.edge(b, dsn, "belongs_to")
                batches[s.sample_id] = b
        # models (registry) + lineage
        reg_all = self.registry.all()
        for m in reg_all.values():
            n = g.node(f"model:{m['model_id']}", "Model", f"{m['model_id']}", sha256=m["sha256"][:16], version=m["version"])
            g.edge(n, "assurance:core", "verified_by")
            lin = m.get("lineage") or {}
            if lin.get("previous_version"):
                g.edge(n, f"model:{lin['previous_version']}", "derived_from")
            g.edge(n, dsn, "derived_from")
            for b in lin.get("new_sources", []):
                g.ensure_asset(f"batch:{b}")
                g.edge(n, f"batch:{b}", "derived_from", note="trained on this batch")
        dep = stats["model"]["deployed"]["sha256"]
        mnode = stats["model"]["model_node"]
        if mnode.startswith("modelver:"):
            g.node(mnode, "ModelVersion", f"unregistered {dep[:10]}", sha256=dep[:16])
            g.edge(mnode, "assurance:core", "verified_by")
        stream = g.node(f"stream:{STREAM}", "Stream", STREAM)
        g.edge(stream, mnode, "produced_by")
        g.edge(stream, "assurance:core", "verified_by")
        win = g.node("window:current", "ObservationWindow", f"current input window ({stats['distribution'].get('window_size', 0)})")
        g.edge(win, stream, "belongs_to")
        by_digest = {m["sha256"]: f"model:{m['model_id']}" for m in reg_all.values()}
        for r in invalid:
            rec = self.prov.get(r["record_id"])
            n = g.node(f"inference:{r['record_id']}", "InferenceRecord", f"#{r['seq']} {r['record_id']}",
                       verdict="INVALID", failures=r["failure_categories"])
            g.edge(n, stream, "belongs_to")
            md = rec["bindings"]["model_sha256"] if rec else None
            tgt = by_digest.get(md) or (mnode if md == dep else None)
            if tgt:
                g.edge(n, tgt, "produced_by")
        # findings / evidence
        for f in fdocs:
            fn = g.node(f"finding:{f['id']}", "Finding", f"{f['id']} {f['title'][:40]}", severity=f["severity"],
                        pillar=f["pillar"], method_status=f["method_status"], confidence=f["confidence"])
            for a in f["affected"]:
                if a.startswith("assurance:"):
                    g.edge(fn, a, "affects")
                    continue
                if g.ensure_asset(a):
                    g.edge(fn, a, "affects")
                    if a.startswith("sample:") and a[7:] in batches:
                        g.edge(a, batches[a[7:]], "belongs_to")
                    if a.startswith("inference:"):
                        g.edge(a, stream, "belongs_to")
                        g.edge(a, fn, "violates")
            for eid in f["evidence"]:
                e = self.store.get_doc("evidence", eid)
                en = g.node(f"evidence:{eid}", "Evidence", f"{eid} {e['title'][:30]}", kind=e["kind"], sha256=e["sha256"][:16])
                g.edge(fn, en, "verified_by")
                for a in e.get("assets", [])[:8]:
                    if g.ensure_asset(a):
                        g.edge(en, a, "derived_from")
                        if a.startswith("sample:") and a[7:] in batches:
                            g.edge(a, batches[a[7:]], "belongs_to")
        for l in links:
            g.edge(f"finding:{l['a']}", f"finding:{l['b']}", "correlates_with", strength=l["strength"], rule=l["rule"], reason=l["reason"])
        for sc in scenarios:
            n = g.node(f"scenario:{sc['id']}:{sc['at']}", "AttackScenario", f"{sc['name']} (DEMO)", demo=True,
                       description=sc.get("summary"))
            for a in sc.get("touched", []):
                if g.ensure_asset(a):
                    g.edge(n, a, "affects", ground_truth=True)
        return g

    # ================================================================ cases
    def cases(self) -> list[dict]:
        out = self.store.list_docs("cases")
        return sorted(out, key=lambda c: c["created_at"], reverse=True)

    def case(self, case_id: str) -> dict | None:
        c = self.store.get_doc("cases", case_id)
        if not c:
            return None
        c["finding_docs"] = [self.store.get_doc("findings", f) for f in c["findings"] + c.get("informational_findings", [])]
        c["evidence_docs"] = [self.store.get_doc("evidence", e) for e in c["evidence"]]
        g = EvidenceGraph.load(self.store, c["run_id"])
        keep = set(c.get("graph_nodes") or [])
        c["graph"] = {"nodes": [n for n in g["nodes"] if n["id"] in keep],
                      "edges": [e for e in g["edges"] if e["source"] in keep and e["target"] in keep]}
        return c

    def set_disposition(self, case_id: str, disposition: str, note: str = "", actor: str = "analyst") -> dict:
        disposition = disposition.upper()
        if disposition not in DISPOSITIONS:
            raise ValueError(f"disposition must be one of {DISPOSITIONS}")
        c = self.store.get_doc("cases", case_id)
        if not c:
            raise KeyError(case_id)
        ev = self.audit.append("case.disposition_set", actor, f"case:{case_id}",
                               {"disposition": disposition, "note": note, "recommended": c["recommended_disposition"]})
        c["disposition"] = disposition
        c["status"] = {"ACCEPT": "CLOSED — ACCEPTED", "REVIEW": "UNDER REVIEW", "QUARANTINE": "QUARANTINED"}[disposition]
        c["disposition_history"].append({"ts": ev["ts"], "actor": actor, "disposition": disposition, "note": note,
                                         "audit_seq": ev["seq"]})
        c["timeline"].append(self._tl(ev))
        self.store.put_doc("cases", case_id, c, run_id=c["run_id"])
        return c


def _jsonable(o):
    if isinstance(o, dict):
        return {str(k): _jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_jsonable(v) for v in o]
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    return o

