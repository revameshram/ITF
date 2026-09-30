# Threat model

## Assets
| Asset | Why it matters |
|---|---|
| Contributed training data (images, labels, provenance) | poisoned data yields a compromised model |
| Model artefacts + trusted registry | the model that runs must be the model that was approved |
| Inference records (the operational evidence) | decisions are taken on these outputs |
| Audit log | the record of what the system and analysts did |
| Signing key | root of trust for records, registry, audit head and reports |
| Assurance reports | the final decision artefact |

## Adversaries
1. **Malicious or careless data contributor.** Submits mislabelled, duplicated, out-of-domain or trigger-stamped samples.
2. **Supply-chain / deployment attacker.** Swaps or modifies the deployed model file.
3. **Insider with database write access.** Edits inference outputs, replaces records, or edits audit history.
4. **Network-adjacent attacker.** Replays or forges records towards the ingest endpoint.
5. **Physical-world attacker.** Places a trigger sticker in the camera's field of view.
6. **Environment (not an adversary).** Lighting, season or sensor change that looks like an anomaly.

## Attack → control → status
| Attack | Control | Status | Attack Lab scenario |
|---|---|---|---|
| Label flipping / systematic mislabelling | reference-anchored kNN vote + binomial source test | HEURISTIC | `label_flip` |
| Duplicate flooding | dHash + shift-tolerant MAE confirmation | HEURISTIC | `duplicate_flood` |
| OOD insertion | kNN distance + Mahalanobis on image statistics | HEURISTIC | `ood_insertion` |
| Dirty-label stamped-trigger poisoning | recurring patch + label concentration | HEURISTIC | `backdoor_poison`, `combined` |
| Backdoored model (legitimately registered) | controlled trigger test with neutral control; activation response | HEURISTIC | `backdoor_poison`, `combined` |
| Model substitution / modification | SHA-256 vs Ed25519-signed registry; fingerprint | REAL | `model_substitution` |
| Registry manifest tampering | manifest signature | REAL | (unit-tested) |
| Inference output / config tampering | bound digests + record hash | REAL | `inference_tampering` |
| Input image swap after inference | input re-hash | REAL | `input_tampering` |
| Record replacement / forgery | trusted-key signature + chain link | REAL | `record_replacement` |
| Replay at ingest | nonce registry + monotonic sequence + signature | REAL | `replay` |
| Audit-history edit / deletion | hash chain + signed head | REAL | `audit_tampering` |
| Silent edit of accepted training files | dataset manifest diff | REAL | (covered by `manifest_integrity`) |
| Trigger sticker in operational frames | localised-pattern analysis on current inputs | HEURISTIC | `combined` |
| Environmental drift (benign) | KS/PSI/MMD + global-vs-local attribution | REAL stats, HEURISTIC attribution | `distribution_shift` |

## Out of scope / not detected
- Clean-label poisoning (feature collision, correct labels).
- Blended, invisible, warped or sample-specific triggers.
- Backdoors whose trigger is outside the tested library and absent from the audited data.
- Per-input adversarial examples; model extraction; membership inference.
- **Signing-key compromise.** A key holder can produce valid forgeries. Mitigations for production: HSM/TPM, key rotation, a split signer and verifier, external anchoring of the audit head.
- Compromise of the Python runtime / onnxruntime supply chain.

## Trust assumptions
- The reference battery is trusted and correctly labelled.
- The registry and key were not compromised before registration.
- Provenance metadata is attached by the ingestion process, not self-declared by contributors.
- The host is air-gapped. The in-process network guard is defence in depth, not isolation.

## Safety of the Attack Lab
All scenarios act only on the local synthetic workspace copy (`data/generated/workspace`) and the local SQLite database. There is no network code, no scanning, and nothing that touches a real system or real data.
