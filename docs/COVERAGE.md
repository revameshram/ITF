# Coverage and limitations

This is the same information as the in-app **Coverage / Limitations** page, which is generated from `backend/coverage.py`.

## Fully implemented (REAL)
- COCO and YOLO dataset adapters with contributor/batch provenance; SHA-256 dataset manifest diff; exact duplicates.
- Contributor/batch aggregation with a binomial significance test against a baseline calibrated on trusted data.
- ONNX adapter (onnxruntime) with white-box parameter and activation access. TorchScript adapter, active when PyTorch is installed.
- Model digest vs Ed25519-signed registry; manifest signature; behavioural fingerprint; version-to-version behaviour diff; lineage.
- Signed, chained inference records; tamper, forgery, replay, input-swap and model-binding detection; re-execution check; ingest endpoint with nonce registry.
- Distribution statistics: KS with Bonferroni, PSI, MMD with a permutation test, model confidence and class-mix shift.
- Evidence graph from real relationships; explicit correlation rules; cases; documented risk formula; dispositions logged to the audit chain.
- Hash-chained audit log with a signed head. Signed JSON and HTML assurance reports.
- Offline guard (in-process socket blocker + CSP) and an egress self-test.
- Provenance self-test (Attack Lab), run on isolated copies with expected vs actual results: input, output, model-digest and config modification; reorder; delete; re-sign with an untrusted key; replay; audit edit and delete.
- Test suite: 43 tests (`test.bat`).

## Controlled demonstration (real code, heuristic conclusion)
These run real computations, but the conclusion is uncalibrated and is labelled HEURISTIC with stated limitations:
- label-flip / systematic mislabelling
- near-duplicate flooding
- OOD detection
- the recurring stamped-patch trigger search
- the controlled trigger test for backdoor-like behaviour, which uses data-derived candidates plus 6 patterns × 4 corners
- localised-manipulation vs environmental-drift attribution

## Demo / simulated
- The synthetic dataset (48×48 scenes of vehicles, people and signs), the reference battery and the observation frames.
- Three demo models (clean, backdoored, substitute), trained offline in NumPy and exported to ONNX.
- The Attack Lab payloads and the "retraining" step, which deploys a model pre-trained on exactly the injected data.

## Status by area (also shown on the Coverage page)
| Area | Status |
|---|---|
| Dataset integrity | IMPLEMENTED (manifest, duplicates and aggregation are REAL; label, OOD and trigger detection are HEURISTIC) |
| Model integrity | IMPLEMENTED (digest, registry and fingerprint are REAL; statistics need white-box access) |
| Inference provenance | IMPLEMENTED |
| Audit trail | IMPLEMENTED |
| Distribution shift | PROTOTYPE / HEURISTIC (the statistics are real; the attribution is heuristic) |
| Controlled trigger testing | PROTOTYPE / HEURISTIC (not general backdoor detection) |
| General backdoor detection | NOT SUPPORTED |
| Invisible / blended trigger detection | NOT SUPPORTED |
| YOLO support | LIMITED (dataset labels are parsed; detection-model outputs are not decoded) |
| TorchScript models | OPTIONAL (UNAVAILABLE without PyTorch) |
| Calibration | SYNTHETIC ONLY (not real-world accuracy) |

## Future enhancements (not supported yet)
- General trigger reverse-engineering (Neural Cleanse, ABS), plus detection of clean-label, blended and invisible triggers.
- Learned embeddings (for example a frozen CNN) to replace hand-crafted features on real imagery, with re-calibration.
- Detection-model output decoders (YOLO heads) so object-detector outputs can be fingerprinted.
- HSM/TPM keys, key rotation, trusted timestamping, external anchoring of the audit head.
- Multi-user authentication and RBAC; PostgreSQL; streaming ingest.
- Confidence calibration on labelled attack corpora.

## Honest caveats
- Heuristic confidences are **scores, not probabilities**.
- **No finding does not mean no attack.**
- Thresholds were calibrated on the synthetic reference battery only.
