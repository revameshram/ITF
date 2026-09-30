# AegisVision architecture

## 1. Big picture

```
                    ┌──────────────── browser (localhost only, CSP default-src 'self') ────────────────┐
                    │  Dashboard · Datasets · Models · Inferences · Distribution · Cases · Evidence    │
                    │  Attack Lab · Audit Log · Reports · Coverage          (frontend/, no build step) │
                    └───────────────────────────────▲──────────────────────────────────────────────────┘
                                                    │ JSON over HTTP (127.0.0.1)
┌───────────────────────────────────────────────────┴──────────────────────────────────────────────────┐
│ backend/main.py  FastAPI  (netguard installed first → outbound sockets refused)                     │
│                                                                                                      │
│  core.AegisApp ─ run_assurance()                                                                     │
│   ├─ adapters/datasets  COCO | YOLO  ──► DatasetView ──► analyzers/dataset   (pillar 1)              │
│   ├─ adapters/models    ONNX | TorchScript ─► ModelAdapter ─► analyzers/model (pillar 2)             │
│   ├─ crypto/provenance  verify every signed inference record + re-execution   (pillar 3)             │
│   ├─ analyzers/shift    reference battery vs current inference inputs         (pillar 4)             │
│   ├─ crypto/audit       hash-chain verification                               (pillar 5)             │
│   ├─ evidence/graph     nodes/edges + correlation rules                                              │
│   ├─ cases/cases        case, chains, risk, disposition                                              │
│   └─ reports/report     signed JSON + HTML                                                           │
│                                                                                                      │
│  store.Store (SQLite: audit, inference_records, nonces, model_registry, findings, evidence,          │
│               graph_nodes/edges, cases, runs)            registry.ModelRegistry (signed manifests)   │
└──────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

A single Python process with a single SQLite file. There are no external services.

## 2. The assurance run (`core.AegisApp.run_assurance`)

1. **Dataset.** Load the workspace dataset through an adapter. Then:
   - Diff its SHA-256 manifest against the accepted snapshot.
   - Run duplicate / near-duplicate, reference-anchored label consistency, OOD and recurring-patch trigger detection.
   - Aggregate per contributor/batch with a binomial significance test.
2. **Model.**
   - Compare the deployed file's SHA-256 with the active entry of the signed registry, and verify the manifest signature.
   - Compute the behavioural fingerprint on the trusted reference battery.
   - Compute parameter and activation statistics (white-box only).
   - Run the controlled trigger tests, using the candidates found in step 1 plus a bounded pattern search.
3. **Inference.** Verify every record: output, config and record-hash bindings, the Ed25519 signature against trusted keys, input re-hash, the model digest against the registry, the per-stream hash-chain link, nonce uniqueness, and re-execution with the registered artefact. Rejected ingest attempts are included.
4. **Distribution.** Compare the latest 60 inference inputs with the reference battery using KS tests (Bonferroni), PSI and MMD (permutation test), plus model confidence. Then apply the attribution heuristic: global vs localised vs insufficient evidence.
5. **Governance.** Verify the audit hash chain and its signed head.
6. **Correlate.** Apply explicit rules R0–R6 (below) to build the evidence graph and evidence chains.
7. **Case.** Open a case if any finding is MEDIUM or higher. Compute severity, risk and the recommended disposition.
8. **Record.** Every step is appended to the audit chain, and the run document is stored.

## 3. Finding model (`analyzers/findings.py`)

Every finding carries: `what`, `why`, `evidence[]`, `severity`, `confidence` plus `confidence_basis`, `affected` assets, `limitations[]`, `method`, `method_status` (REAL / HEURISTIC / DEMO), `recommendation`, and `tags` for the correlation engine. Each evidence item is stored with its own SHA-256.

## 4. Cryptographic design

| Object | Construction |
|---|---|
| Canonical form | JSON with sorted keys and no whitespace, UTF-8 (`crypto/keys.canonical_json`) |
| Inference record | `bindings = {input_sha256, model_sha256, preprocess_sha256, inference_config_sha256, output_sha256}` + stream, seq, timestamp, 128-bit nonce, prev_record_hash, signer key id → `record_hash = SHA-256(canonical(body))` → `signature = Ed25519(record_hash)` |
| Replay protection | nonce registry (`nonces` table) + strictly increasing per-stream sequence at ingest; nonce uniqueness re-checked when the stored log is verified |
| Record chain | `prev_record_hash` per stream: a replaced, inserted or removed record breaks its successor's link |
| Model registry | manifest (digest, fingerprint, parameter statistics, activation baseline, lineage) → SHA-256 → Ed25519 |
| Audit log | `hash_n = SHA-256(canonical({seq, ts, event_id, event_type, actor, asset, details, prev_hash}))`, genesis `0×64`; the current head is Ed25519-signed |
| Report | SHA-256 over the canonical report body + Ed25519 signature embedded in `integrity` |

Keys: `data/generated/keys/signer.pem`, created on first start. The trusted key set is `{local key}`. Anything signed by another key is treated as forged.

## 5. Evidence graph (`evidence/graph.py`)

Node types: Dataset, Contributor, Batch, Sample, Model, ModelVersion, Stream, InferenceRecord, ObservationWindow, Finding, Evidence, Case, AttackScenario, AssuranceCore.

Edges and where each one comes from:

| Edge | Source of truth |
|---|---|
| `contributed_by`, `belongs_to` | dataset provenance metadata (COCO `aegis_source` / `sources.csv`) |
| `derived_from` | registry lineage (model ← previous version, model ← batches it was trained on); evidence ← assets |
| `produced_by` | model digest cryptographically bound inside inference records |
| `affects` | finding → affected assets |
| `verified_by` | finding → evidence; assets → assurance core |
| `violates` | invalid inference record → finding |
| `correlates_with` | correlation rules, with `rule`, `strength` and `reason` stored on the edge |

Correlation rules:

- **R1:** same source flagged by independent dataset detectors.
- **R2:** same trigger location found independently in two pillars.
- **R3:** the model backdoor test used a trigger extracted from a flagged source.
- **R4:** the model lineage includes a flagged batch.
- **R5:** inference records are bound to a substituted model digest.
- **R6:** a replaced record broke its successor's chain link.
- **R0 (context only):** the finding affects the same pipeline but has no causal link. The case says explicitly that such findings are grouped only for that reason.

Attack Lab ground truth appears as dotted `affects` edges from an `AttackScenario` node. Detectors never read it.

## 6. Cases and risk (`cases/cases.py`)

- A **chain** is a connected component over strong links.
- **Severity** is the maximum finding severity, escalated one level when a strong chain spans three or more pillars.
- **Risk** = `1 − Π(1 − w(sev)·confidence)`, with w = {INFO .05, LOW .2, MEDIUM .45, HIGH .75, CRITICAL .95}.
- **Recommended disposition:**
  - QUARANTINE if there is a deterministic integrity failure (HIGH or above), a HIGH model finding, or a corroborated multi-pillar HIGH chain.
  - REVIEW if any finding is MEDIUM or higher.
  - ACCEPT otherwise.
- The analyst's disposition (ACCEPT / REVIEW / QUARANTINE) is appended to the audit chain.

## 7. Extensibility

- **New dataset format:** subclass `DatasetAdapter` (`can_load`, `load` → `DatasetView`) and append it to `ADAPTERS`.
- **New model format:** subclass `ModelAdapter` (`predict`, `parameters`, `activations`, `extensions`). Analyzers only ever see `capabilities()`, so black-box adapters degrade gracefully.
- **New detector:** return `Finding`s and `CheckRecord`s from an analyzer, and add a correlation rule if it produces linkable tags.
- **New scenario:** add a function and a `Scenario(...)` entry in `demo/scenarios.py`, with its expected finding categories.

## 8. Offline enforcement

`netguard.install()` wraps `socket.connect`, `connect_ex` and `create_connection`, and refuses any non-loopback address. Attempts are counted and can be shown with **Test egress block** (logged to the audit chain). The UI is served with `Content-Security-Policy: default-src 'self'`, and every asset (including Cytoscape.js) is vendored. The limitation is scope: the guard covers this process only, so host-level isolation is still expected.
