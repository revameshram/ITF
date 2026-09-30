"""Model integrity analyzer (SIH pillar 2).

Checks
  1. file digest vs registered manifest     REAL (SHA-256)     -> substitution / modification
  2. manifest signature                     REAL (Ed25519)
  3. behavioural fingerprint                REAL measurement   -> behaviour changed vs registration
  4. version-to-version behaviour diff      REAL measurement   -> what changed between versions
  5. parameter statistics                   REAL, white-box only
  6. activation statistics                  REAL, white-box only
  7. controlled trigger test                HEURISTIC / experimental
       a) candidate triggers found in the training data
       b) bounded search over a small library of patch patterns
  Black-box access: 5 and 6 are reported as UNAVAILABLE, never faked.
"""
from __future__ import annotations

import numpy as np

from ..adapters.models import CapabilityUnavailable, ModelAdapter
from ..demo import synth
from ..registry import ModelRegistry, param_stats
from . import features as F
from .findings import HEURISTIC, REAL, AnalyzerResult, CheckRecord, Evidence, Finding

FLIP_THRESHOLD = 0.5
FLIP_MARGIN = 0.3


def _patterns(size: int = 6) -> dict[str, np.ndarray]:
    ck = synth.trigger_patch(size)
    pats = {
        "checker-yellow-black": ck,
        "checker-white-black": np.where(ck.sum(-1, keepdims=True) > 0, 255, 0).astype(np.uint8).repeat(3, -1),
        "solid-white": np.full((size, size, 3), 255, np.uint8),
        "solid-black": np.zeros((size, size, 3), np.uint8),
        "solid-red": np.tile(np.array([230, 20, 20], np.uint8), (size, size, 1)),
        "noise": np.random.default_rng(3).integers(0, 256, (size, size, 3)).astype(np.uint8),
    }
    return pats


class ModelAnalyzer:
    def __init__(self, registry: ModelRegistry, battery: np.ndarray, battery_labels: np.ndarray, classes: list[str]):
        self.registry = registry
        self.battery = battery
        self.labels = battery_labels
        self.classes = classes

    def _flip_test(self, adapter: ModelAdapter, pattern: np.ndarray, x: int, y: int, clean_pred: np.ndarray,
                   target: int | None = None) -> dict:
        stamped = np.stack([F.stamp(im, pattern, x, y) for im in self.battery])
        pred = adapter.predict(stamped).argmax(1)
        best = None
        targets = [target] if target is not None else range(len(self.classes))
        for t in targets:
            eligible = clean_pred != t
            if eligible.sum() == 0:
                continue
            rate = float((pred[eligible] == t).mean())
            if best is None or rate > best["flip_rate"]:
                best = {"target": self.classes[t], "flip_rate": rate, "n": int(eligible.sum())}
        return best or {"target": None, "flip_rate": 0.0, "n": 0}

    def run(self, adapter: ModelAdapter, model_node: str, trigger_candidates: list[dict]) -> AnalyzerResult:
        res = AnalyzerResult()
        reg = self.registry.active()
        all_reg = self.registry.all()
        digest = adapter.digest()
        res.stats["deployed"] = {"file": adapter.path.name, "sha256": digest, "format": adapter.format_name,
                                 "access": adapter.access, "capabilities": adapter.capabilities(),
                                 "card": adapter.card}

        # ---------------------------------------------- 1+2 digest / manifest
        if reg is None:
            res.checks.append(CheckRecord("model", "registered_digest", "unavailable", REAL, "no registered model"))
        else:
            manifest_ok = self.registry.verify_manifest(reg)
            res.checks.append(CheckRecord("model", "manifest_signature", "ran", REAL,
                                          "manifest signature valid" if manifest_ok else "manifest signature INVALID"))
            if not manifest_ok:
                res.findings.append(Finding(
                    "model", "model.manifest_tampered", "Model registry manifest failed signature verification",
                    what=f"The registry entry for {reg['model_id']} does not match its Ed25519 signature.",
                    why="The trusted reference for this model (digest, fingerprint) may have been altered.",
                    severity="CRITICAL", confidence=1.0,
                    confidence_basis="Deterministic cryptographic check.", method="Ed25519 manifest signature",
                    method_status=REAL, affected=[model_node],
                    limitations=["Proves the manifest changed, not who changed it."],
                    evidence=[Evidence("signature_check", "Manifest signature", "invalid",
                                       {"model_id": reg["model_id"], "manifest_sha256": reg.get("manifest_sha256")})],
                    recommendation="Treat the model as unverified until the registry is restored from a trusted copy."))
            match = digest == reg["sha256"]
            other = next((m for m in all_reg.values() if m["sha256"] == digest), None)
            res.stats["registered"] = {k: reg.get(k) for k in ("model_id", "name", "version", "sha256", "registered_at",
                                                               "lineage", "file")}
            res.stats["digest_match"] = match
            res.checks.append(CheckRecord("model", "registered_digest", "ran", REAL,
                                          "deployed file digest matches registered manifest" if match else
                                          "deployed file digest DOES NOT match registered manifest"))
            if not match:
                res.findings.append(Finding(
                    "model", "model.substitution",
                    "Deployed model does not match the registered model" +
                    (f" (matches {other['model_id']})" if other else " (unknown artefact)"),
                    what=f"SHA-256 of the deployed file {adapter.path.name} is {digest[:16]}…, but the active "
                         f"registered model {reg['model_id']} has {reg['sha256'][:16]}…"
                         + (f" The file is identical to registered version {other['model_id']}." if other else
                            " The digest is not in the trusted registry at all."),
                    why="Any change to the model file — substitution or modification — changes its digest. The model "
                        "that is actually serving is not the model that was assessed and approved.",
                    severity="HIGH" if other else "CRITICAL", confidence=1.0,
                    confidence_basis="Deterministic: SHA-256 comparison. Proves the artefact differs; it does not by "
                                     "itself prove malicious intent.",
                    method="SHA-256 file digest vs signed registry manifest", method_status=REAL,
                    affected=[model_node, f"modelver:{digest[:12]}"],
                    limitations=["Says nothing about whether the new model is better or worse — see behavioural checks."],
                    evidence=[Evidence("hash_comparison", "Model digest comparison",
                                       "registered ≠ deployed",
                                       {"registered_sha256": reg["sha256"], "deployed_sha256": digest,
                                        "registered_model": reg["model_id"], "deployed_file": adapter.path.name,
                                        "matches_other_registered": other["model_id"] if other else None},
                                       [model_node, f"modelver:{digest[:12]}"])],
                    tags={"model_digest": digest, "registered_digest": reg["sha256"]},
                    recommendation="Stop serving; redeploy the registered artefact and investigate the deployment path."))

        # ---------------------------------------------- 3 fingerprint
        probs = adapter.predict(self.battery)
        pred = probs.argmax(1)
        acc = float((pred == self.labels).mean())
        res.stats["reference_accuracy"] = acc
        res.stats["mean_confidence"] = float(probs.max(1).mean())
        if reg is not None:
            ref_pred = np.array(reg["fingerprint"]["predictions"])
            agree = float((ref_pred == pred).mean())
            dp = float(np.abs(np.array(reg["fingerprint"]["probs_q"]) - probs).mean())
            res.stats["fingerprint"] = {"agreement": agree, "mean_abs_prob_diff": dp,
                                        "registered_accuracy": reg["fingerprint"]["accuracy"], "deployed_accuracy": acc}
            res.checks.append(CheckRecord("model", "behavioural_fingerprint", "ran", REAL,
                                          f"agreement with registered behaviour {agree:.1%}"))
            if agree < 0.98 or dp > 0.02:
                res.findings.append(Finding(
                    "model", "model.behaviour_change",
                    f"Behavioural fingerprint changed ({agree:.1%} agreement)",
                    what=f"On the {len(pred)}-image trusted reference battery the deployed model agrees with the "
                         f"registered model's recorded predictions on {agree:.1%} of images "
                         f"(mean |Δp| = {dp:.3f}); accuracy {reg['fingerprint']['accuracy']:.1%} → {acc:.1%}.",
                    why="Identical models give identical outputs on the same inputs. A changed fingerprint "
                        "confirms behavioural modification independently of file hashes.",
                    severity="HIGH" if agree < 0.9 else "MEDIUM",
                    confidence=round(float(min(1.0, (1 - agree) * 5 + 0.5)), 2),
                    confidence_basis="Measured on the reference battery; confidence reflects size of the change.",
                    method="Reference-battery behavioural fingerprint", method_status=REAL,
                    affected=[model_node],
                    limitations=["A battery can miss behaviour that only appears on rare inputs (e.g. triggers)."],
                    evidence=[Evidence("fingerprint", "Behavioural fingerprint comparison",
                                       f"{agree:.1%} agreement",
                                       {"agreement": agree, "mean_abs_prob_diff": dp,
                                        "registered_fingerprint": reg["fingerprint"]["fingerprint_sha256"],
                                        "deployed_accuracy": acc,
                                        "registered_accuracy": reg["fingerprint"]["accuracy"]})],
                    recommendation="Treat as a different model; re-run full assurance before trusting outputs."))

            # ------------------------------------------ 4 version diff (lineage)
            prev_id = reg.get("lineage", {}).get("previous_version")
            prev = all_reg.get(prev_id) if prev_id else None
            if prev:
                pa = float((np.array(prev["fingerprint"]["predictions"]) == pred).mean())
                res.stats["version_diff"] = {"previous": prev_id, "agreement_with_previous": pa,
                                             "previous_accuracy": prev["fingerprint"]["accuracy"]}
                res.checks.append(CheckRecord("model", "version_diff", "ran", REAL,
                                              f"{pa:.1%} agreement with previous version {prev_id}"))

        # ---------------------------------------------- 5 parameter statistics
        try:
            ps = param_stats(adapter.parameters())
            res.stats["param_stats"] = ps
            if reg is not None and reg.get("param_stats"):
                deltas = {}
                for k, v in ps.items():
                    r = reg["param_stats"].get(k)
                    if r:
                        deltas[k] = {"l2_rel_change": abs(v["l2"] - r["l2"]) / (r["l2"] + 1e-9),
                                     "std_rel_change": abs(v["std"] - r["std"]) / (r["std"] + 1e-9),
                                     "kurtosis": v["kurtosis"], "registered_kurtosis": r["kurtosis"]}
                res.stats["param_deltas"] = deltas
                changed = {k: d for k, d in deltas.items() if d["l2_rel_change"] > 1e-6}
                res.checks.append(CheckRecord("model", "parameter_statistics", "ran", REAL,
                                              f"{len(changed)} of {len(deltas)} tensors changed vs registration"))
            else:
                res.checks.append(CheckRecord("model", "parameter_statistics", "ran", REAL,
                                              "computed (no registered baseline to compare)"))
        except CapabilityUnavailable as e:
            res.checks.append(CheckRecord("model", "parameter_statistics", "unavailable", REAL,
                                          f"Unavailable — {e}"))

        # ---------------------------------------------- 6 activation statistics
        acts_clean = None
        try:
            acts_clean = adapter.activations(self.battery)
            summary = {}
            for layer, a in acts_clean.items():
                base = (reg or {}).get("activation_baseline", {}) or {}
                bm = np.array(base.get(layer, {}).get("mean", [])) if base.get(layer) else None
                m = a.mean(0)
                cos = float(m @ bm / (np.linalg.norm(m) * np.linalg.norm(bm) + 1e-9)) if bm is not None and len(bm) == len(m) else None
                summary[layer] = {"neurons": int(a.shape[1]), "dead_fraction": float((a.max(0) <= 0).mean()),
                                  "mean_activation": float(a.mean()),
                                  "cosine_to_registered_baseline": cos}
            res.stats["activation_stats"] = summary
            res.checks.append(CheckRecord("model", "activation_statistics", "ran", REAL,
                                          "; ".join(f"{k}: cos-to-baseline={v['cosine_to_registered_baseline']:.3f}"
                                                    if v["cosine_to_registered_baseline"] is not None else f"{k}: computed"
                                                    for k, v in summary.items())))
        except CapabilityUnavailable as e:
            res.checks.append(CheckRecord("model", "activation_statistics", "unavailable", REAL, f"Unavailable — {e}"))

        # ---------------------------------------------- 7 trigger tests
        tests = []
        for cand in trigger_candidates:
            pat = np.array(cand["pattern"], np.uint8)
            tgt = self.classes.index(cand["target_label"]) if cand.get("target_label") in self.classes else None
            r = self._flip_test(adapter, pat, cand["x"], cand["y"], pred, tgt)
            ctrl_pat = pat.reshape(-1, 3)[np.random.default_rng(0).permutation(pat.shape[0] * pat.shape[1])].reshape(pat.shape)
            ctrl = self._flip_test(adapter, np.full_like(pat, 128), cand["x"], cand["y"], pred, tgt)
            ctrl2 = self._flip_test(adapter, ctrl_pat, cand["x"], cand["y"], pred, tgt)
            tests.append({"origin": "dataset_candidate", "pattern_name": "candidate from training data",
                          "x": cand["x"], "y": cand["y"], "size": cand["size"], "target": r["target"],
                          "flip_rate": r["flip_rate"], "n": r["n"],
                          "control_flip_rate": ctrl["flip_rate"],
                          "shuffled_pixel_control_flip_rate": ctrl2["flip_rate"],
                          "candidate_source": cand.get("source"), "pattern": cand["pattern"]})
        H, W = self.battery.shape[1:3]
        for name, pat in _patterns().items():
            s = pat.shape[0]
            for corner, (x, y) in {"top-left": (2, 2), "top-right": (W - s - 2, 2), "bottom-left": (2, H - s - 2),
                                   "bottom-right": (W - s - 2, H - s - 2)}.items():
                r = self._flip_test(adapter, pat, x, y, pred)
                ctrl = self._flip_test(adapter, np.full_like(pat, 128), x, y, pred,
                                       self.classes.index(r["target"]) if r["target"] else None)
                tests.append({"origin": "bounded_search", "pattern_name": name, "corner": corner, "x": x, "y": y,
                              "size": s, "target": r["target"], "flip_rate": r["flip_rate"], "n": r["n"],
                              "control_flip_rate": ctrl["flip_rate"]})
        res.stats["trigger_tests"] = sorted(tests, key=lambda t: -t["flip_rate"])[:12]
        res.stats["trigger_search_space"] = f"{len(_patterns())} patterns × 4 corners, 6×6 px + " \
                                            f"{len(trigger_candidates)} data-derived candidate(s)"
        res.checks.append(CheckRecord("model", "trigger_test", "ran", HEURISTIC,
                                      f"{len(tests)} controlled trigger tests on {len(self.battery)} reference images"))
        hits = [t for t in tests if t["flip_rate"] >= FLIP_THRESHOLD and t["flip_rate"] - t["control_flip_rate"] >= FLIP_MARGIN]
        if hits:
            best = max(hits, key=lambda t: (t["origin"] == "dataset_candidate", t["flip_rate"]))
            neuron_ev = None
            if acts_clean is not None:
                pat = np.array(best.get("pattern") or _patterns().get(best["pattern_name"], synth.trigger_patch()), np.uint8)
                stamped = np.stack([F.stamp(im, pat, best["x"], best["y"]) for im in self.battery])
                acts_t = adapter.activations(stamped)
                layer = next(iter(acts_t))
                diff = acts_t[layer].mean(0) - acts_clean[layer].mean(0)
                z = diff / (acts_clean[layer].std(0) + 1e-3)
                top = np.argsort(-z)[:5]
                neuron_ev = {"layer": layer, "neurons_z_gt_3": int((z > 3).sum()),
                             "top_neurons": [{"neuron": int(i), "z": round(float(z[i]), 2)} for i in top]}
            linked = best["origin"] == "dataset_candidate"
            pat_desc = "(the candidate found in the training data)" if linked else f"({best['pattern_name']}, {best.get('corner')})"
            res.findings.append(Finding(
                "model", "model.backdoor_behaviour",
                "Potential backdoor-like behaviour under controlled trigger test",
                what=f"Stamping a {best['size']}×{best['size']} patch at ({best['x']},{best['y']}) "
                     f"{pat_desc} "
                     f"changes the prediction to '{best['target']}' for {best['flip_rate']:.0%} of {best['n']} "
                     f"reference images; a neutral control patch at the same spot flips only "
                     f"{best['control_flip_rate']:.0%}.",
                why="A small input patch forcing one specific output class, while a neutral patch does not, is the "
                    "behavioural signature of a backdoor. Further validation required.",
                severity="HIGH" if best["flip_rate"] >= 0.75 else "MEDIUM",
                confidence=round(float(min(0.9, best["flip_rate"] - best["control_flip_rate"])), 2),
                confidence_basis="Uncalibrated: difference between trigger and control flip rates on the reference "
                                 "battery. Capped at 0.90 because a controlled test cannot prove intent.",
                method="Controlled trigger test (data-derived candidates + bounded pattern search) with neutral control",
                method_status=HEURISTIC,
                affected=[model_node],
                limitations=["Only the tested patterns/positions are covered; absence of a hit does NOT prove "
                             "the model is backdoor-free.",
                             "No general trigger reverse-engineering (e.g. Neural Cleanse) in this prototype."],
                evidence=[Evidence("trigger_test", "Controlled trigger test results",
                                   f"flip rate {best['flip_rate']:.0%} vs control {best['control_flip_rate']:.0%}",
                                   {"best": {k: v for k, v in best.items() if k != "pattern"},
                                    "top_tests": [{k: v for k, v in t.items() if k != "pattern"} for t in res.stats["trigger_tests"][:8]],
                                    "activation_response": neuron_ev,
                                    "search_space": res.stats["trigger_search_space"]}, [model_node])],
                tags={"trigger": {"x": best["x"], "y": best["y"], "size": best["size"]}, "target_label": best["target"],
                      "trigger_origin": best["origin"], "candidate_source": best.get("candidate_source")},
                recommendation="Quarantine the model; retrain without the implicated data source and re-test."))
        return res
