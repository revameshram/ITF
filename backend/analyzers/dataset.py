"""Training-data integrity analyzer (SIH pillar 1).

Checks
  1. exact duplicates             REAL      (SHA-256 of pixels)
  2. near-duplicate flooding      HEURISTIC (dHash + pixel MAE confirmation)
  3. label consistency            HEURISTIC (kNN vote from a TRUSTED reference battery)
  4. systematic mislabelling      HEURISTIC (dominant confusion pair per source)
  5. out-of-distribution samples  HEURISTIC (kNN distance + image-statistics Mahalanobis)
  6. trigger / stamp pattern      HEURISTIC (recurring identical high-contrast patch)
  7. source-level aggregation     REAL statistics (binomial tail test vs. calibrated baseline)

Nothing here claims certainty: every finding states its method, its
confidence basis and its limitations.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

from ..adapters.datasets import DatasetView
from . import features as F
from .findings import HEURISTIC, REAL, AnalyzerResult, CheckRecord, Evidence, Finding

K_LABEL = 11
VOTE_SHARE = 0.7
NEAR_DUP_HAMMING = 14   # candidate window; confirmed by shift-tolerant MAE (clean pairs >= 12 MAE)
NEAR_DUP_MAE = 8.0


def binom_tail(k: int, n: int, p: float) -> float:
    """P(X >= k), X ~ Binomial(n, p) - exact, computed in log space."""
    if k <= 0:
        return 1.0
    p = min(max(p, 1e-9), 1 - 1e-9)
    logs = [math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1) + i * math.log(p) +
            (n - i) * math.log(1 - p) for i in range(k, n + 1)]
    m = max(logs)
    return float(min(1.0, math.exp(m) * sum(math.exp(x - m) for x in logs)))


def _src(s) -> str:
    return f"{s.contributor or 'unknown'}/{s.batch or 'unknown'}"


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


class DatasetAnalyzer:
    def __init__(self, reference: DatasetView, workspace_root: Path):
        self.reference = reference
        self.root = workspace_root
        self._ref_imgs = [s.load() for s in reference.samples]
        self._ref_emb = F.embed_many(self._ref_imgs)
        self._ref_labels = np.array([s.label for s in reference.samples])
        # calibration on trusted reference data (leave-one-out)
        idx, d = F.knn(self._ref_emb, self._ref_emb, K_LABEL, exclude_self=True)
        maj, share = self._vote(idx)
        self.baseline_flag_rate = max(0.01, float(((maj != self._ref_labels) & (share >= VOTE_SHARE)).mean()))
        idx5, d5 = F.knn(self._ref_emb, self._ref_emb, 5, exclude_self=True)
        self.ood_emb_threshold = float(np.percentile(d5.mean(1), 99.5) * 1.1)
        S = np.array([list(F.image_stats(i).values()) for i in self._ref_imgs])
        self._stat_mu = S.mean(0)
        self._stat_icov = np.linalg.pinv(np.cov(S.T) + np.eye(S.shape[1]) * 1e-3)
        md = np.sqrt(np.einsum("ij,jk,ik->i", S - self._stat_mu, self._stat_icov, S - self._stat_mu))
        self.ood_stat_threshold = float(np.percentile(md, 99.5) * 1.5)

    def _vote(self, idx):
        votes = self._ref_labels[idx]
        maj, share = [], []
        for v in votes:
            c = Counter(v).most_common(1)[0]
            maj.append(c[0])
            share.append(c[1] / len(v))
        return np.array(maj), np.array(share)

    # ------------------------------------------------------------------
    def run(self, ds: DatasetView) -> AnalyzerResult:
        res = AnalyzerResult()
        samples = ds.samples
        n = len(samples)
        imgs = [s.load() for s in samples]
        labels = np.array([s.label for s in samples])
        emb = F.embed_many(imgs)
        ds_node = f"dataset:{ds.name}"
        sources = [_src(s) for s in samples]
        src_counts = Counter(sources)

        def sample_ref(i: int, **extra) -> dict:
            s = samples[i]
            return {"sample_id": s.sample_id, "path": _rel(s.path, self.root), "label": s.label,
                    "contributor": s.contributor, "batch": s.batch, **extra}

        def src_assets(src: str) -> list[str]:
            c, b = src.split("/")
            return [ds_node, f"contributor:{c}", f"batch:{b}"]

        per_src: dict[str, dict] = defaultdict(lambda: defaultdict(int))
        for s in sources:
            per_src[s]["n"] += 1

        # ---------------------------------------------------- 1+2 duplicates
        sha = [F.pixel_sha256(i) for i in imgs]
        exact_groups = [g for g in _groups(sha) if len(g) > 1]
        hashes = [F.dhash(i) for i in imgs]
        H = F.hamming_matrix(hashes)
        np.fill_diagonal(H, 99)
        parent = list(range(n))

        def find(a):
            while parent[a] != a:
                parent[a] = parent[parent[a]]
                a = parent[a]
            return a

        cand = np.argwhere(np.triu(H <= NEAR_DUP_HAMMING))
        confirmed = 0
        for a, b in cand:
            if _shift_mae(imgs[a], imgs[b]) <= NEAR_DUP_MAE:
                parent[find(a)] = find(b)
                confirmed += 1
        for g in exact_groups:
            for x in g[1:]:
                parent[find(x)] = find(g[0])
        clusters = defaultdict(list)
        for i in range(n):
            clusters[find(i)].append(i)
        dup_clusters = sorted([c for c in clusters.values() if len(c) > 1], key=len, reverse=True)
        dup_members = {i for c in dup_clusters for i in c}
        for i in dup_members:
            per_src[sources[i]]["duplicates"] += 1
        res.checks.append(CheckRecord("dataset", "exact_duplicates", "ran", REAL,
                                      f"{sum(len(g) - 1 for g in exact_groups)} exact duplicate images"))
        res.checks.append(CheckRecord("dataset", "near_duplicates", "ran", HEURISTIC,
                                      f"{len(dup_clusters)} duplicate clusters, {len(dup_members)} images involved"))
        if dup_clusters:
            big = [c for c in dup_clusters if len(c) >= 5]
            src_share = Counter(sources[i] for i in dup_members)
            top_src, top_n = src_share.most_common(1)[0]
            flooding = bool(big) or len(dup_members) / n > 0.05
            sev = "HIGH" if (flooding and len(dup_members) / n > 0.05) else ("MEDIUM" if flooding else "LOW")
            ev = Evidence("duplicate_clusters", "Duplicate / near-duplicate clusters",
                          f"{len(dup_clusters)} clusters; largest has {len(dup_clusters[0])} images",
                          {"clusters": [{"size": len(c), "members": [sample_ref(i, dhash=f'{hashes[i]:016x}') for i in c[:12]]}
                                        for c in dup_clusters[:8]],
                           "by_source": dict(src_share), "method": f"dHash Hamming<={NEAR_DUP_HAMMING} + pixel MAE<={NEAR_DUP_MAE}"},
                          [f"sample:{samples[i].sample_id}" for c in dup_clusters[:3] for i in c[:5]])
            res.findings.append(Finding(
                "dataset", "dataset.duplicate_flooding" if flooding else "dataset.duplicates",
                f"{'Duplicate flooding' if flooding else 'Duplicate samples'} — {len(dup_members)} images in {len(dup_clusters)} clusters",
                what=f"{len(dup_members)} images form {len(dup_clusters)} (near-)duplicate clusters; "
                     f"{top_n} of them come from {top_src}.",
                why="Many copies of the same image over-weight it during training (can bias the model or "
                    "amplify a poisoned sample) and inflate apparent dataset size.",
                severity=sev,
                confidence=0.95 if exact_groups else 0.85,
                confidence_basis="Near-duplicates confirmed by two independent measures (perceptual hash and "
                                 "pixel difference). Score is a heuristic, not a calibrated probability.",
                method="SHA-256 pixel hash + 64-bit dHash + mean-absolute-error confirmation",
                method_status=HEURISTIC,
                affected=src_assets(top_src),
                limitations=["Heavily augmented copies (crops, rotations, colour jitter) may not be caught.",
                             "Legitimate burst captures of a static scene can look like duplicates."],
                evidence=[ev],
                tags={"sources": sorted(src_share), "primary_source": top_src,
                      "sample_ids": [samples[i].sample_id for i in dup_members]},
                recommendation="Remove redundant copies; review why one source submitted repeated images."))

        # ---------------------------------------------------- 3+4 label consistency
        idx, _ = F.knn(emb, self._ref_emb, K_LABEL)
        maj, share = self._vote(idx)
        flag = (maj != labels) & (share >= VOTE_SHARE)
        for i in np.nonzero(flag)[0]:
            per_src[sources[i]]["label_flags"] += 1
        res.checks.append(CheckRecord("dataset", "label_consistency", "ran", HEURISTIC,
                                      f"{int(flag.sum())} samples disagree with trusted-reference kNN vote "
                                      f"(baseline false-flag rate {self.baseline_flag_rate:.1%})"))
        concentrated = []
        for src, cnt in src_counts.items():
            k = sum(1 for i in np.nonzero(flag)[0] if sources[i] == src)
            if k == 0:
                continue
            p = binom_tail(k, cnt, self.baseline_flag_rate)
            per_src[src]["label_p"] = p
            if p < 1e-3 and k / cnt >= 0.1:
                concentrated.append((src, k, cnt, p))
        for src, k, cnt, p in sorted(concentrated, key=lambda x: x[3]):
            members = [i for i in np.nonzero(flag)[0] if sources[i] == src]
            pairs = Counter((labels[i], maj[i]) for i in members)
            (given, predicted), pc = pairs.most_common(1)[0]
            systematic = pc / len(members) >= 0.6
            rate = k / cnt
            sev = "HIGH" if rate >= 0.3 and p < 1e-6 else "MEDIUM"
            conf = float(min(0.95, np.mean(share[members]) * (1.0 if p < 1e-6 else 0.8)))
            ev1 = Evidence("sample_list", f"Label disagreements in {src}",
                           f"{k}/{cnt} samples ({rate:.0%}) disagree with the trusted reference",
                           {"samples": [sample_ref(i, reference_vote=str(maj[i]), vote_share=round(float(share[i]), 2))
                                        for i in members[:40]], "total": k},
                           [f"sample:{samples[i].sample_id}" for i in members[:25]])
            ev2 = Evidence("statistical_test", "Source concentration test",
                           f"Binomial tail p = {p:.2e} (baseline flag rate {self.baseline_flag_rate:.1%} from trusted data)",
                           {"test": "one-sided binomial", "k": k, "n": cnt, "baseline": self.baseline_flag_rate,
                            "p_value": p, "confusion_pairs": {f"{a}->{b}": v for (a, b), v in pairs.items()}})
            c, b = src.split("/")
            res.findings.append(Finding(
                "dataset", "dataset.systematic_mislabelling" if systematic else "dataset.label_inconsistency",
                (f"Systematic mislabelling in {b}: labelled '{given}', looks like '{predicted}'" if systematic
                 else f"Label inconsistencies concentrated in {b}"),
                what=f"{k} of {cnt} samples ({rate:.0%}) from {c} / {b} carry labels that disagree with "
                     f"{K_LABEL} nearest trusted reference images" +
                     (f"; {pc} of them follow the same pattern: labelled '{given}' but look like '{predicted}'."
                      if systematic else "."),
                why=f"Such a rate is very unlikely by chance (p = {p:.1e}) given the {self.baseline_flag_rate:.1%} "
                    "disagreement rate measured on trusted data. Concentration in one source suggests "
                    "systematic labelling error or deliberate label flipping.",
                severity=sev, confidence=round(conf, 2),
                confidence_basis="Uncalibrated score: mean kNN vote share for the alternative label, reduced when "
                                 "statistical significance is weaker.",
                method=f"Reference-anchored kNN label vote (k={K_LABEL}, HOG+colour features) + binomial source test",
                method_status=HEURISTIC,
                affected=src_assets(src),
                limitations=["Depends on the trusted reference battery covering the visual variety of each class.",
                             "Hand-crafted features; a learned embedding would be more robust on real imagery.",
                             "Cannot tell honest mistakes from malicious flipping — intent is not inferred."],
                evidence=[ev1, ev2],
                tags={"sources": [src], "primary_source": src, "given_label": str(given),
                      "suspected_label": str(predicted), "systematic": systematic,
                      "sample_ids": [samples[i].sample_id for i in members]},
                recommendation=f"Quarantine {b} for manual relabelling review before any retraining."))
        isolated = int(flag.sum()) - sum(x[1] for x in concentrated)
        if isolated > 0:
            members = [i for i in np.nonzero(flag)[0] if sources[i] not in {x[0] for x in concentrated}]
            res.findings.append(Finding(
                "dataset", "dataset.isolated_label_review",
                f"{isolated} isolated samples with uncertain labels",
                what=f"{isolated} samples spread across sources disagree with the trusted-reference vote.",
                why="Not concentrated in any source; consistent with ordinary labelling noise / detector false positives "
                    f"(expected ≈{self.baseline_flag_rate * n:.0f} by chance).",
                severity="INFO", confidence=0.3,
                confidence_basis="Individual kNN disagreements are weak evidence on their own.",
                method="Reference-anchored kNN label vote", method_status=HEURISTIC, affected=[ds_node],
                limitations=["Most of these are expected false positives of the heuristic."],
                evidence=[Evidence("sample_list", "Samples for optional review", f"{isolated} samples",
                                   {"samples": [sample_ref(i, reference_vote=str(maj[i])) for i in members[:30]]})],
                tags={"sources": sorted({sources[i] for i in members})},
                recommendation="Optional spot-check; no action required."))

        # ---------------------------------------------------- 5 OOD
        _, d5 = F.knn(emb, self._ref_emb, 5)
        d_emb = d5.mean(1)
        S = np.array([list(F.image_stats(i).values()) for i in imgs])
        md = np.sqrt(np.einsum("ij,jk,ik->i", S - self._stat_mu, self._stat_icov, S - self._stat_mu))
        ood = (d_emb > self.ood_emb_threshold) | (md > self.ood_stat_threshold)
        for i in np.nonzero(ood)[0]:
            per_src[sources[i]]["ood"] += 1
        res.checks.append(CheckRecord("dataset", "out_of_distribution", "ran", HEURISTIC,
                                      f"{int(ood.sum())} samples outside the trusted reference distribution"))
        if ood.sum():
            members = list(np.nonzero(ood)[0])
            src_share = Counter(sources[i] for i in members)
            top_src, top_n = src_share.most_common(1)[0]
            conc = top_n / src_counts[top_src]
            sev = "MEDIUM" if (conc >= 0.2 or len(members) >= 10) else "LOW"
            res.findings.append(Finding(
                "dataset", "dataset.ood_samples",
                f"{len(members)} out-of-distribution samples" + (f" concentrated in {top_src.split('/')[1]}" if conc >= 0.2 else ""),
                what=f"{len(members)} images are far from every trusted reference image in appearance/statistics; "
                     f"{top_n} come from {top_src}.",
                why="Images that do not look like the operational domain (noise, documents, inverted colours, other "
                    "sensors) add no useful signal and can be used to degrade or manipulate training.",
                severity=sev, confidence=round(float(min(0.9, 0.5 + 0.4 * conc)), 2),
                confidence_basis="Uncalibrated: thresholds set at 99.5th percentile of trusted-reference distances × margin.",
                method="kNN cosine distance on HOG+colour + Mahalanobis distance on 8 image statistics",
                method_status=HEURISTIC, affected=src_assets(top_src),
                limitations=["Rare but legitimate conditions (fog, glare) may be flagged.",
                             "Thresholds calibrated only on the reference battery."],
                evidence=[Evidence("sample_list", "OOD samples", f"{len(members)} samples",
                                   {"samples": [sample_ref(i, embed_distance=round(float(d_emb[i]), 3),
                                                           stat_distance=round(float(md[i]), 2)) for i in members[:40]],
                                    "thresholds": {"embedding": self.ood_emb_threshold, "statistics": self.ood_stat_threshold},
                                    "by_source": dict(src_share)},
                                   [f"sample:{samples[i].sample_id}" for i in members[:20]])],
                tags={"sources": sorted(src_share), "primary_source": top_src,
                      "sample_ids": [samples[i].sample_id for i in members]},
                recommendation="Exclude OOD samples from training; confirm the capture source."))

        # ---------------------------------------------------- 6 trigger patterns
        min_count = max(8, n // 100)
        cands = F.recurring_patches(imgs, min_count=min_count)
        # copies of the same image trivially share patches -> count one member per duplicate cluster
        cands = [c for c in cands if len({find(i) for i in c["members"]}) >= min_count]
        res.checks.append(CheckRecord("dataset", "trigger_pattern_search", "ran", HEURISTIC,
                                      f"{len(cands)} recurring stamped-patch candidates"))
        trigger_candidates = []
        for c in cands:
            members = c["members"]
            for i in members:
                per_src[sources[i]]["trigger"] += 1
            lab = Counter(labels[i] for i in members)
            target, tn = lab.most_common(1)[0]
            disagree = sum(1 for i in members if flag[i])
            src_share = Counter(sources[i] for i in members)
            top_src, top_n = src_share.most_common(1)[0]
            dirty = tn / len(members) >= 0.9 and disagree / len(members) >= 0.3
            sev = "HIGH" if dirty else "MEDIUM"
            cand = {"x": c["x"], "y": c["y"], "size": c["size"], "pattern": c["pattern"], "target_label": str(target),
                    "count": len(members), "source": top_src}
            trigger_candidates.append(cand)
            res.findings.append(Finding(
                "dataset", "dataset.trigger_pattern",
                f"Possible trigger patch in {len(members)} samples ({top_src.split('/')[1]})",
                what=f"An identical high-contrast {c['size']}×{c['size']} patch appears at pixel ({c['x']},{c['y']}) in "
                     f"{len(members)} images; {tn} of them are labelled '{target}'"
                     + (f" and {disagree} of those labels disagree with the image content." if disagree else "."),
                why="Natural images practically never repeat an identical patch at the same position. A repeated "
                    "stamp combined with a single target label is consistent with dirty-label data poisoning "
                    "(trigger insertion). It does not establish who added the samples or why." if dirty else
                    "A repeated identical patch may be a watermark, overlay or a poisoning trigger.",
                severity=sev, confidence=0.85 if dirty else 0.55,
                confidence_basis="Uncalibrated: based on exact recurrence count, label concentration and label "
                                 "disagreement. Whether it actually changes model behaviour is tested separately "
                                 "by the model trigger test.",
                method="Recurring quantised-patch search (all positions, 6×6 window) + label concentration",
                method_status=HEURISTIC,
                affected=src_assets(top_src),
                limitations=["Detects stamped, fixed-position triggers only; blended, invisible, warped or "
                             "position-varying triggers are not detected.",
                             "Benign watermarks/overlays produce the same signal (hence 'possible')."],
                evidence=[Evidence("trigger_candidate", "Recurring patch", f"{len(members)} images share the patch",
                                   {"candidate": cand, "label_distribution": dict(lab),
                                    "label_disagreements": disagree, "by_source": dict(src_share),
                                    "samples": [sample_ref(i) for i in members[:40]]},
                                   [f"sample:{samples[i].sample_id}" for i in members[:25]])],
                tags={"sources": sorted(src_share), "primary_source": top_src, "trigger": cand,
                      "target_label": str(target), "sample_ids": [samples[i].sample_id for i in members]},
                recommendation="Quarantine the source batch; run the model trigger test with this candidate."))

        # ---------------------------------------------------- 7 source aggregation table
        table = []
        for src, d in sorted(per_src.items()):
            c, b = src.split("/")
            flagged = d.get("label_flags", 0) + d.get("ood", 0) + d.get("duplicates", 0) + d.get("trigger", 0)
            table.append({"contributor": c, "batch": b, "samples": d["n"], "label_flags": d.get("label_flags", 0),
                          "ood": d.get("ood", 0), "duplicates": d.get("duplicates", 0), "trigger": d.get("trigger", 0),
                          "label_p_value": d.get("label_p"), "anomaly_rate": round(min(1.0, flagged / d["n"]), 3)})
        res.checks.append(CheckRecord("dataset", "source_aggregation", "ran" if ds.has_provenance else "unavailable",
                                      REAL, "per contributor/batch aggregation" if ds.has_provenance else
                                      "dataset has no contributor/batch provenance — aggregation unavailable"))
        res.stats = {
            "summary": ds.summary(),
            "source_table": table,
            "trigger_candidates": trigger_candidates,
            "calibration": {"baseline_label_flag_rate": self.baseline_flag_rate,
                            "ood_embedding_threshold": self.ood_emb_threshold,
                            "ood_statistic_threshold": self.ood_stat_threshold,
                            "calibrated_on": f"trusted reference battery ({len(self._ref_imgs)} images)"},
            "counts": {"label_flags": int(flag.sum()), "ood": int(ood.sum()), "duplicate_images": len(dup_members),
                       "trigger_candidates": len(cands)},
        }
        return res


def _shift_mae(a: np.ndarray, b: np.ndarray, max_shift: int = 1) -> float:
    """Pixel MAE minimised over small translations (tolerates 1-px shifts)."""
    A, B = a.astype(np.int16), b.astype(np.int16)
    best = 1e9
    m = max_shift
    for dy in range(-m, m + 1):
        for dx in range(-m, m + 1):
            sa = A[max(0, dy):A.shape[0] + min(0, dy), max(0, dx):A.shape[1] + min(0, dx)]
            sb = B[max(0, -dy):B.shape[0] + min(0, -dy), max(0, -dx):B.shape[1] + min(0, -dx)]
            best = min(best, float(np.abs(sa - sb).mean()))
    return best


def _groups(keys: list[str]) -> list[list[int]]:
    d: dict[str, list[int]] = defaultdict(list)
    for i, k in enumerate(keys):
        d[k].append(i)
    return list(d.values())
