# AegisVision — Trustworthy CV Integrity Assurance (SIH26228 prototype)

> *An AI detective for computer-vision systems.*
> It investigates the whole pipeline **DATASET → MODEL → INFERENCE**, connects the evidence, and answers:
> **"Can we actually trust this AI system?"**

AegisVision is an **offline, air-gapped** assurance workbench. It audits contributed training data, the deployed model and the signed inference log. It then correlates what it finds into an evidence graph, opens investigation **cases**, and produces **signed assurance reports**. Every conclusion is labelled **REAL**, **HEURISTIC** or **DEMO / SIMULATED**, and anything the system cannot assess is shown as *unavailable*, never faked.

---

## Quick start (Windows)

```bat
setup.bat      :: one time: creates .venv and installs requirements (Python 3.10+)
run.bat        :: starts http://127.0.0.1:8000 and opens the browser
test.bat       :: runs the automated test suite (33 tests)
```

Linux / macOS: `python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt && ./run.sh`

Or directly: `python -m backend.main` (options: `--port 8000 --open`).

No internet is needed after `pip install`. The demo dataset, models and attack payloads are already in `data/demo/`. If they are ever missing, they are rebuilt automatically, or you can run `python -m backend.demo.generate`, which takes about 10 s.

## The 3-minute judge demo

The dashboard has a **Judge demo** checklist. Full script: [`docs/DEMO.md`](docs/DEMO.md).

1. Click **Run assurance check**. Result: **TRUSTED**, and Dataset, Model, Inference, Distribution and Audit all **PASS**.
2. Go to **Attack Lab** and inject **Controlled Data Poisoning + Inference Tampering**.
3. Run the check again. Result: **UNTRUSTED**, with Dataset **WARNING**, Model **REVIEW**, Inference **FAILED** and Distribution **SUSPICIOUS**.
4. **CASE-0001** has been created automatically. Open it to see the evidence cards, the evidence graph, the connected chain *contrib-B → batch-17 → trigger patch → backdoored model → triggered camera frames*, and the timeline.
5. Under **Inferences**, open **Show proof** on the tampered record. `output_binding`, `record_hash` and `re_execution` fail, while the Ed25519 signature is still valid over the original record.
6. Set the disposition to **QUARANTINE** and click **Generate report**. You get a signed JSON report and an HTML report you can print to PDF.

## What is real, what is demo, what is future

| Status | Examples |
|---|---|
| **REAL** (deterministic / cryptographic) | SHA-256 manifests; Ed25519-signed inference records; tamper, replacement and replay detection; hash-chained audit log with a signed head; model digest vs signed registry; behavioural fingerprint; parameter and activation statistics (white-box); KS, PSI and MMD shift tests; evidence graph; cases; signed reports; offline network guard |
| **HEURISTIC** (real computation, uncalibrated conclusion) | label-flip and mislabelling detection, near-duplicate flooding, OOD samples, stamped-trigger search, controlled trigger test for backdoor-like behaviour, drift-vs-manipulation attribution |
| **DEMO / SIMULATED** | the synthetic 48×48 dataset, the three demo ONNX models, the Attack Lab payloads, and the "retraining" step in the poisoning scenario |
| **NOT YET IMPLEMENTED** | general trigger reverse-engineering (e.g. Neural Cleanse), clean-label and invisible-trigger detection, detection-head decoding for YOLO models, hardware-backed keys, multi-user authentication |

Details: [`docs/COVERAGE.md`](docs/COVERAGE.md). The same information is on the in-app **Coverage / Limitations** page.

## Project layout

```
backend/            Python package (FastAPI server + all logic)
  main.py           HTTP API + static UI, offline guard installed first
  core.py           assurance pipeline orchestrator (AegisApp)
  store.py          SQLite persistence
  netguard.py       in-process egress blocker (air-gap enforcement)
  registry.py       signed trusted-model registry
  coverage.py       single source of truth for REAL / HEURISTIC / DEMO / NOT IMPLEMENTED
  crypto/           keys.py (SHA-256, Ed25519), provenance.py (inference records), audit.py (hash chain)
  adapters/         datasets.py (COCO, YOLO), models.py (ONNX, TorchScript)
  analyzers/        dataset.py, model.py, shift.py, features.py, findings.py
  evidence/graph.py evidence graph + explicit correlation rules
  cases/cases.py    case building, risk aggregation, disposition logic
  reports/report.py signed JSON + printable HTML report
  demo/             synth.py (scenes), train.py (NumPy MLP to ONNX), generate.py, scenarios.py (Attack Lab)
frontend/           no-build SPA (HTML/CSS/ES modules) + vendored Cytoscape.js
data/demo/          pre-built DEMO assets (dataset, reference battery, observation frames, payloads, models)
data/generated/     runtime state: SQLite DB, keys, workspace copy, reports (safe to delete)
tests/              pytest suite (unit + integration)
docs/               architecture, threat model, demo script, coverage, report schema
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md): components, data model, pipeline, crypto design, audit log
- [Threat model](docs/THREAT_MODEL.md): assets, adversaries, attacks covered and not covered
- [Demo instructions](docs/DEMO.md): the judge walkthrough and all Attack Lab scenarios
- [Coverage and limitations](docs/COVERAGE.md): what is real, heuristic, demo or future work
- [Assurance report schema](docs/assurance_report.schema.json)

## Design decisions (simplifications we chose)

- **No React/Vite build.** The UI is plain ES modules served by FastAPI, so there is no Node toolchain on the judge machine and nothing to break offline.
- **PyTorch is optional.** The TorchScript adapter is implemented and reports *unavailable* if torch is not installed. The demo models are real ONNX models run through onnxruntime.
- **No scikit-learn.** kNN, Mahalanobis, KS, PSI and MMD are short NumPy functions the team can read and explain.
- **PDF comes from the browser.** The HTML report has a print stylesheet, so no heavy PDF library is needed.
- **Everything stays local.** SQLite, a local Ed25519 key (a PEM file; production would use an HSM or TPM) and vendored JS.
