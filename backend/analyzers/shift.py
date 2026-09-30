"""Distribution-shift / anomaly assessment (SIH pillar 4).

Compares the images the deployed model is *currently* seeing (the inputs
bound in the latest inference records) with the trusted reference
distribution.

Statistics (REAL):
  - two-sample Kolmogorov-Smirnov test per image statistic (Bonferroni corrected)
  - Population Stability Index on brightness
  - kernel MMD on image embeddings with a permutation test
  - model confidence / predicted-class mix change
Attribution (HEURISTIC, clearly labelled):
  - GLOBAL, coherent change in most frames      -> probable environmental / operational drift
  - LOCALISED pattern in a subset of frames     -> suspicious, possible manipulation
  - significant but neither                     -> shift detected, insufficient evidence to attribute
Distribution shift is never by itself reported as an attack.
"""
from __future__ import annotations

import math

import numpy as np

from . import features as F
from .findings import HEURISTIC, REAL, AnalyzerResult, CheckRecord, Evidence, Finding

STAT_NAMES = ["brightness", "contrast", "saturation", "red_mean", "green_mean", "blue_mean", "edge_density", "noise_level"]
MIN_WINDOW = 20


def ks_2samp(a: np.ndarray, b: np.ndarray) -> tuple[float, float]:
    a, b = np.sort(a), np.sort(b)
    allv = np.concatenate([a, b])
    cdf_a = np.searchsorted(a, allv, side="right") / len(a)
    cdf_b = np.searchsorted(b, allv, side="right") / len(b)
    d = float(np.max(np.abs(cdf_a - cdf_b)))
    ne = len(a) * len(b) / (len(a) + len(b))
    lam = (math.sqrt(ne) + 0.12 + 0.11 / math.sqrt(ne)) * d
    p = 2 * sum((-1) ** (k - 1) * math.exp(-2 * k * k * lam * lam) for k in range(1, 101))
    return d, float(min(max(p, 0.0), 1.0))


def psi(ref: np.ndarray, cur: np.ndarray, bins: int = 10) -> float:
    edges = np.quantile(ref, np.linspace(0, 1, bins + 1))
    edges[0], edges[-1] = -np.inf, np.inf
    r = np.histogram(ref, edges)[0] / len(ref) + 1e-4
    c = np.histogram(cur, edges)[0] / len(cur) + 1e-4
    return float(((c - r) * np.log(c / r)).sum())


def mmd_perm(X: np.ndarray, Y: np.ndarray, perms: int = 200, seed: int = 0) -> tuple[float, float]:
    Z = np.concatenate([X, Y])
    D = ((Z[:, None, :] - Z[None, :, :]) ** 2).sum(-1)
    sigma2 = np.median(D[D > 0])
    K = np.exp(-D / sigma2)
    n = len(X)

    def stat(idx):
        a, b = idx[:n], idx[n:]
        return K[np.ix_(a, a)].mean() + K[np.ix_(b, b)].mean() - 2 * K[np.ix_(a, b)].mean()

    base = np.arange(len(Z))
    s0 = stat(base)
    rng = np.random.default_rng(seed)
    count = sum(stat(rng.permutation(len(Z))) >= s0 for _ in range(perms))
    return float(s0), float((count + 1) / (perms + 1))


class ShiftAnalyzer:
    def __init__(self, reference_imgs: list[np.ndarray]):
        self.ref = reference_imgs
        self.ref_stats = np.array([[F.image_stats(i)[k] for k in STAT_NAMES] for i in reference_imgs])
        self.ref_emb = F.embed_many(reference_imgs)
        self.ref_regions = np.stack([F.region_stats(i) for i in reference_imgs])   # (N,16,2)
        self.reg_mu = self.ref_regions.mean(0)
        self.reg_sd = self.ref_regions.std(0) + 1e-3

    def run(self, current: list[dict], window_node: str, model=None, dataset_triggers: list[dict] | None = None) -> AnalyzerResult:
        """current: [{"img": ndarray, "record_id": str, "path": str}]"""
        res = AnalyzerResult()
        n = len(current)
        res.stats["window_size"] = n
        res.stats["reference_size"] = len(self.ref)
        if n < MIN_WINDOW:
            res.stats["status"] = "INSUFFICIENT_DATA"
            res.checks.append(CheckRecord("distribution", "shift_tests", "skipped", REAL,
                                          f"only {n} current frames (< {MIN_WINDOW}) — not enough evidence to assess shift"))
            return res
        imgs = [c["img"] for c in current]
        cur_stats = np.array([[F.image_stats(i)[k] for k in STAT_NAMES] for i in imgs])

        # ------------------------------------------------ statistical tests
        tests = []
        for j, name in enumerate(STAT_NAMES):
            d, p = ks_2samp(self.ref_stats[:, j], cur_stats[:, j])
            lo, hi = np.percentile(self.ref_stats[:, j], [1, 99])
            outside = float(((cur_stats[:, j] < lo) | (cur_stats[:, j] > hi)).mean())
            rm, cm = float(self.ref_stats[:, j].mean()), float(cur_stats[:, j].mean())
            tests.append({"feature": name, "ks_d": round(d, 3), "p_value": p, "p_bonferroni": min(1.0, p * len(STAT_NAMES)),
                          "reference_mean": round(rm, 2), "current_mean": round(cm, 2),
                          "relative_change": round((cm - rm) / (abs(rm) + 1e-6), 3), "fraction_outside_ref_1_99": round(outside, 3)})
        b_psi = psi(self.ref_stats[:, 0], cur_stats[:, 0])
        cur_emb = F.embed_many(imgs)
        mmd, mmd_p = mmd_perm(self.ref_emb, cur_emb)
        sig = [t for t in tests if t["p_bonferroni"] < 0.01]
        shift_detected = bool(sig) or mmd_p < 0.01
        res.checks.append(CheckRecord("distribution", "ks_tests", "ran", REAL,
                                      f"{len(sig)} of {len(tests)} statistics differ (Bonferroni p<0.01)"))
        res.checks.append(CheckRecord("distribution", "mmd_test", "ran", REAL, f"MMD={mmd:.4f}, permutation p={mmd_p:.3f}"))

        # ------------------------------------------------ model-side view
        model_view = None
        if model is not None:
            pr = model.predict(np.stack(self.ref))
            pc = model.predict(np.stack(imgs))
            rc = np.bincount(pr.argmax(1), minlength=pr.shape[1]) / len(pr)
            cc = np.bincount(pc.argmax(1), minlength=pc.shape[1]) / len(pc)
            model_view = {"reference_mean_confidence": float(pr.max(1).mean()), "current_mean_confidence": float(pc.max(1).mean()),
                          "reference_class_mix": rc.round(3).tolist(), "current_class_mix": cc.round(3).tolist(),
                          "class_mix_tv_distance": float(0.5 * np.abs(rc - cc).sum())}
            res.checks.append(CheckRecord("distribution", "model_confidence_shift", "ran", REAL,
                                          f"mean confidence {model_view['reference_mean_confidence']:.2f} → "
                                          f"{model_view['current_mean_confidence']:.2f}"))

        # ------------------------------------------------ localisation analysis
        regions = np.stack([F.region_stats(i) for i in imgs])
        z = np.abs((regions - self.reg_mu) / self.reg_sd)                  # (n,16,2)
        zmax = z.max(-1)                                                   # (n,16)
        global_z = np.abs((cur_stats - self.ref_stats.mean(0)) / (self.ref_stats.std(0) + 1e-6)).max(1)
        local_frames = [(i, int(zmax[i].argmax()), float(zmax[i].max())) for i in range(n)
                        if zmax[i].max() > 5 and (zmax[i] > 3).sum() <= 3 and global_z[i] < 3]
        region_counts = np.bincount([r for _, r, _ in local_frames], minlength=16)
        top_region = int(region_counts.argmax()) if local_frames else None
        localized = bool(local_frames) and region_counts.max() >= max(4, 0.08 * n)
        patches = F.recurring_patches(imgs, min_count=max(4, n // 15))
        res.checks.append(CheckRecord("distribution", "localized_anomaly_search", "ran", HEURISTIC,
                                      f"{len(local_frames)} frames with a localised anomaly; "
                                      f"{len(patches)} recurring stamped patch(es)"))

        # ------------------------------------------------ attribution
        driver = max(tests, key=lambda t: t["fraction_outside_ref_1_99"])
        global_frac = driver["fraction_outside_ref_1_99"]
        stats_out = {"tests": tests, "brightness_psi": round(b_psi, 3), "mmd": round(mmd, 5), "mmd_p_value": mmd_p,
                     "shift_detected": shift_detected, "model_view": model_view,
                     "localized_frames": len(local_frames), "top_region": top_region,
                     "recurring_patches": [{k: v for k, v in p.items() if k != "members"} | {"count": p["count"]} for p in patches]}
        region_name = None
        if top_region is not None:
            rr, cc_ = divmod(top_region, 4)
            region_name = f"{['top', 'upper-middle', 'lower-middle', 'bottom'][rr]}-{['left', 'centre-left', 'centre-right', 'right'][cc_]}"

        evidence_tests = Evidence("statistical_test", "Distribution tests (reference vs current window)",
                                  f"MMD p={mmd_p:.3f}; {len(sig)} statistics significant",
                                  {"tests": tests, "mmd": mmd, "mmd_p_value": mmd_p, "brightness_psi": b_psi,
                                   "reference": f"trusted reference battery ({len(self.ref)} images)",
                                   "current": f"inputs of the latest {n} inference records", "model_view": model_view},
                                  [window_node])

        if patches or localized:
            p0 = patches[0] if patches else None
            members = p0["members"] if p0 else [i for i, r, _ in local_frames if r == top_region]
            match = None
            if p0 and dataset_triggers:
                for t in dataset_triggers:
                    if abs(t["x"] - p0["x"]) <= 2 and abs(t["y"] - p0["y"]) <= 2:
                        match = t
            status = "SUSPICIOUS"
            where = f"at pixel ({p0['x']},{p0['y']})" if p0 else f"in the {region_name} region"
            res.findings.append(Finding(
                "distribution", "distribution.localized_manipulation",
                f"Localised pattern in {len(members)} of {n} operational frames — possible manipulation",
                what=f"{len(members)} recent input frames share a localised anomaly {where} while the rest of each frame "
                     "looks normal" + (". The patch matches the trigger candidate found in the training data "
                                        f"({match['source']})." if match else "."),
                why="Environmental changes (light, weather, sensor) affect the whole frame; an identical local patch in "
                    "many frames is more consistent with a physical/digital sticker or trigger.",
                severity="HIGH" if match else "MEDIUM", confidence=0.8 if match else 0.5,
                confidence_basis="Heuristic attribution, uncalibrated. Increases when the pattern matches independent "
                                 "evidence from the training-data audit.",
                method="Region z-score localisation + recurring patch search on current inputs", method_status=HEURISTIC,
                affected=[window_node] + [f"inference:{current[i]['record_id']}" for i in members[:10]],
                limitations=["Legitimate overlays (timestamps, logos) look similar.",
                             "Only fixed-position patterns are recognised."],
                evidence=[evidence_tests, Evidence("sample_list", "Frames with the localised pattern", f"{len(members)} frames",
                                                   {"frames": [{"record_id": current[i]["record_id"], "path": current[i]["path"]}
                                                               for i in members[:30]], "patch": {k: v for k, v in (p0 or {}).items() if k != 'members'},
                                                    "matches_dataset_trigger": bool(match)},
                                                   [f"inference:{current[i]['record_id']}" for i in members[:10]])],
                tags={"trigger": {"x": p0["x"], "y": p0["y"], "size": p0["size"]} if p0 else None,
                      "record_ids": [current[i]["record_id"] for i in members], "matches_dataset_trigger": bool(match)},
                recommendation="Inspect the camera/field of view for stickers or overlays; treat affected outputs as untrusted."))
        elif shift_detected and global_frac >= 0.5:
            status = "DRIFT"
            moved = sorted(sig, key=lambda t: -abs(t["relative_change"]))[:3]
            desc = ", ".join(f"{t['feature'].replace('_', ' ')} {t['relative_change']:+.0%}" for t in moved)
            hint = ""
            bright = next(t for t in tests if t["feature"] == "brightness")
            if bright["relative_change"] < -0.3:
                hint = " The pattern (darker frames, changed colour balance / noise) is consistent with low-light or night-time acquisition."
            elif bright["relative_change"] > 0.3:
                hint = " The pattern is consistent with over-exposure / glare."
            res.findings.append(Finding(
                "distribution", "distribution.environmental_drift",
                "Significant distribution shift — probable environmental / operational drift",
                what=f"The current input window differs significantly from the reference distribution ({desc}); "
                     f"{global_frac:.0%} of frames fall outside the reference range.{hint}",
                why="Performance guarantees established on the reference data may not hold. The change is global and "
                    "coherent across most frames, which points to changed operating conditions rather than tampering.",
                severity="MEDIUM", confidence=round(min(0.9, 0.5 + global_frac * 0.4), 2),
                confidence_basis="Shift itself: statistically significant (REAL). Attribution to environment: HEURISTIC.",
                method="KS tests + PSI + MMD permutation test; global-vs-local attribution heuristic",
                method_status=HEURISTIC, affected=[window_node],
                limitations=["Distribution shift ≠ attack. A global adversarial transformation cannot be ruled out.",
                             "Reference battery represents daytime conditions only."],
                evidence=[evidence_tests],
                tags={"drift_type": "environmental", "top_features": [t["feature"] for t in moved]},
                recommendation="Validate model performance under the new conditions before relying on outputs; "
                               "collect representative reference data."))
        elif shift_detected:
            status = "INCONCLUSIVE"
            res.findings.append(Finding(
                "distribution", "distribution.unattributed_shift",
                "Distribution shift detected — insufficient evidence to attribute",
                what="Current inputs differ significantly from the reference distribution, but the change is neither "
                     "clearly global nor clearly localised.",
                why="The available evidence does not allow us to distinguish operational drift from manipulation.",
                severity="MEDIUM", confidence=0.5, confidence_basis="Shift is statistically significant; cause is unknown.",
                method="KS + MMD", method_status=HEURISTIC, affected=[window_node],
                limitations=["Explicitly: cause unknown."], evidence=[evidence_tests],
                recommendation="Collect more data; manual review of a sample of frames."))
        else:
            status = "PASS"
        res.stats.update(stats_out)
        res.stats["status"] = status
        res.stats["attribution"] = {"PASS": "no significant shift", "DRIFT": "probable environmental / operational drift",
                                    "SUSPICIOUS": "localised pattern — possible manipulation",
                                    "INCONCLUSIVE": "shift detected, insufficient evidence to attribute"}[status]
        return res
