"""Single source of truth for 'what is real, what is demo, what is missing'.

Used by the Coverage / Limitations page and embedded in every assurance report.
"""

CAPABILITIES = [
    # pillar, capability, status, notes
    ("dataset", "COCO / YOLO dataset parsing", "REAL", "Adapters with a common DatasetView; provenance via aegis_source or sources.csv"),
    ("dataset", "Dataset manifest integrity (SHA-256)", "REAL", "Detects added / removed / silently modified files since import"),
    ("dataset", "Exact duplicate detection", "REAL", "SHA-256 of pixel data"),
    ("dataset", "Near-duplicate / flooding detection", "HEURISTIC", "dHash + shift-tolerant pixel MAE confirmation"),
    ("dataset", "Label-flip / systematic mislabelling", "HEURISTIC", "kNN vote against a trusted reference battery + binomial source test"),
    ("dataset", "Out-of-distribution samples", "HEURISTIC", "kNN embedding distance + Mahalanobis on image statistics"),
    ("dataset", "Trigger / stamped-patch poisoning", "HEURISTIC", "Recurring identical high-contrast patch search; fixed-position stamps only"),
    ("dataset", "Contributor / batch aggregation", "REAL", "Per-source statistics and significance tests"),
    ("model", "Model file digest vs signed registry", "REAL", "SHA-256 + Ed25519-signed manifest"),
    ("model", "Behavioural fingerprint", "REAL", "Predictions on a trusted reference battery"),
    ("model", "Parameter statistics", "REAL", "White-box only (ONNX initialisers / TorchScript state_dict)"),
    ("model", "Activation statistics", "REAL", "White-box ONNX only; TorchScript activation capture not implemented"),
    ("model", "Controlled trigger test", "HEURISTIC", "Data-derived candidates + bounded search (6 patterns × 4 corners) with neutral control"),
    ("model", "General backdoor detection / trigger reverse-engineering (Neural Cleanse etc.)", "NOT SUPPORTED",
     "Only the controlled trigger test above; absence of a hit does not prove absence of a backdoor"),
    ("model", "Invisible / blended / warped trigger detection", "NOT SUPPORTED", "Future enhancement"),
    ("model", "ONNX adapter", "REAL", "onnxruntime CPU"),
    ("model", "TorchScript adapter", "REAL", "Requires optional PyTorch install; reported as unavailable otherwise"),
    ("model", "Detection-model output analysis (e.g. YOLO heads)", "NOT SUPPORTED",
     "Outputs are not decoded, so fingerprint/trigger tests assume class-score outputs; adapter hook exists"),
    ("inference", "Signed inference records (Ed25519)", "REAL", "Binds input, model, preprocessing, config, output, time, nonce, sequence"),
    ("inference", "Tampering / replacement detection", "REAL", "Recomputed digests, record hash, signature, trusted key set"),
    ("inference", "Replay detection", "REAL", "Nonce registry + monotonic sequence at ingest; nonce uniqueness in the log"),
    ("inference", "Hash-chained record stream", "REAL", "Per-stream prev_record_hash chain"),
    ("inference", "Re-execution check", "REAL", "Re-runs the registered model on the bound input"),
    ("inference", "Provenance self-test (expected vs actual)", "REAL", "11 mutations on isolated copies: input, output, model digest, config, reorder, delete, re-sign, replay, audit edit/delete"),
    ("inference", "Hardware-backed keys / trusted timestamping", "NOT SUPPORTED", "Keys are local PEM files in the prototype"),
    ("distribution", "Shift statistics (KS, PSI, MMD)", "REAL", "Reference battery vs latest inference inputs"),
    ("distribution", "Drift vs manipulation attribution", "HEURISTIC", "Global-coherent vs localised pattern; 'insufficient evidence' otherwise"),
    ("governance", "Evidence graph", "REAL", "Nodes/edges from provenance, lineage, bindings and explicit correlation rules"),
    ("governance", "Case management + dispositions", "REAL", "ACCEPT / REVIEW / QUARANTINE, logged to the audit chain"),
    ("governance", "Risk aggregation", "REAL", "Documented formula; inputs include heuristic confidences"),
    ("governance", "Tamper-evident audit log", "REAL", "SHA-256 hash chain + Ed25519-signed head"),
    ("governance", "Assurance report (JSON / HTML, signed)", "REAL", "PDF via the browser's print-to-PDF"),
    ("governance", "Offline / air-gapped operation", "REAL", "In-process socket guard + CSP default-src 'self'; no external assets"),
    ("demo", "Synthetic dataset, models and attack payloads", "DEMO / SIMULATED", "Procedurally generated; labelled in the UI"),
    ("demo", "Model 'retraining' in the poisoning scenario", "DEMO / SIMULATED", "Model pre-trained offline on exactly the injected data"),
    ("platform", "Multi-user authentication / RBAC", "NOT SUPPORTED", "Single local analyst in the prototype"),
]

SUPPORTED_ATTACKS = [
    "Label flipping / systematic mislabelling (concentrated in a source)",
    "Duplicate / near-duplicate flooding",
    "Out-of-distribution sample insertion",
    "Dirty-label poisoning with a stamped, fixed-position trigger",
    "Backdoor behaviour for triggers in the tested pattern library or found in the data",
    "Model substitution / file modification",
    "Inference output / config / input tampering",
    "Inference record replacement (forged or re-signed with an untrusted key)",
    "Record replay (at ingest and in the stored log)",
    "Audit-log modification",
    "Environmental distribution shift (detection + heuristic attribution)",
]

UNSUPPORTED_ATTACKS = [
    "Clean-label poisoning (correct labels, feature-collision)",
    "Blended / invisible / warped / sample-specific triggers",
    "Backdoors with triggers outside the tested library and absent from the audited data",
    "Adversarial examples (per-input perturbations) at inference time",
    "Model extraction / membership inference / privacy attacks",
    "Attacks by a holder of the signing key (key compromise)",
    "Supply-chain attacks on the runtime (onnxruntime, Python) itself",
]

ASSUMPTIONS = [
    "A trusted, correctly-labelled reference battery exists and represents the operational classes.",
    "The signing key and the model registry were not compromised before registration.",
    "Contributor / batch provenance metadata is attached by the ingestion process, not by contributors.",
    "The demo operates on synthetic 48×48 images; thresholds were calibrated on the reference battery only.",
]

LIMITATIONS = [
    "Heuristic confidences are uncalibrated scores, not probabilities.",
    "Absence of findings is not proof of absence of an attack.",
    "Detectors use hand-crafted features; real imagery would need learned embeddings and re-calibration.",
    "Single-process prototype; SQLite storage; no authentication.",
    "Network guard covers this Python process only; host-level isolation is still required.",
]


# Pillar-level status. Mixed pillars say so explicitly instead of rounding up to "implemented".
PILLAR_SUMMARY = [
    ("Dataset integrity", "IMPLEMENTED", "Manifest, exact duplicates and source aggregation are REAL; label / near-duplicate / OOD / trigger detectors are HEURISTIC."),
    ("Model integrity", "IMPLEMENTED", "Digest vs signed registry and behavioural fingerprint are REAL; parameter/activation statistics need white-box access."),
    ("Inference provenance", "IMPLEMENTED", "Ed25519-signed, hash-chained records; tamper / replay / deletion detection; self-test with expected vs actual."),
    ("Audit trail", "IMPLEMENTED", "SHA-256 hash chain with signed head."),
    ("Distribution shift", "PROTOTYPE / HEURISTIC", "Shift statistics are REAL; drift-vs-manipulation attribution is HEURISTIC."),
    ("Controlled trigger testing", "PROTOTYPE / HEURISTIC", "Data-derived candidates + 6 patterns × 4 corners with a neutral control. Not general backdoor detection."),
    ("General backdoor detection", "NOT SUPPORTED", "No trigger reverse-engineering; a clean trigger test does not prove a model is backdoor-free."),
    ("Invisible / blended trigger detection", "NOT SUPPORTED", "Only stamped, fixed-position patches are searched for."),
    ("YOLO support", "LIMITED", "YOLO dataset labels are parsed; YOLO detection-model outputs are not decoded or analysed."),
    ("TorchScript models", "OPTIONAL", "Adapter implemented; UNAVAILABLE unless PyTorch is installed (requirements-optional.txt)."),
    ("Calibration", "SYNTHETIC ONLY", "Thresholds calibrated on the synthetic reference battery; this is not real-world accuracy."),
]


def coverage_doc() -> dict:
    return {
        "pillar_summary": [{"area": a, "status": s, "notes": n} for a, s, n in PILLAR_SUMMARY],
        "capabilities": [{"pillar": p, "capability": c, "status": s, "notes": n} for p, c, s, n in CAPABILITIES],
        "supported_attack_classes": SUPPORTED_ATTACKS,
        "unsupported_attack_classes": UNSUPPORTED_ATTACKS,
        "assumptions": ASSUMPTIONS,
        "limitations": LIMITATIONS,
    }
