# Demo instructions

## Before the judges arrive
1. Run `run.bat`. The browser opens at http://127.0.0.1:8000.
2. On the Dashboard, open **Judge demo** and click **Reset demo**. This restores the clean pipeline.
3. Optional: unplug the network or disable Wi-Fi. Nothing changes, because the app is fully offline.

## Guided mode (recommended)
On the Dashboard, open **Judge demo** and click **Start guided demo**. The bar at the bottom shows *Step N / 8*. Each **Run step** click performs that step live:

1. **Clean system:** reset the demo and run assurance. Result: TRUSTED.
2. **Controlled Attack Lab:** inject the DEMO / SIMULATED scenario.
3. **Re-run assurance:** findings appear, and the overall status is UNTRUSTED.
4. **Evidence graph:** the relationships become visible.
5. **Case:** CASE-0001 opens at the *know / suspect / don't know / does not prove* panel.
6. **Investigation:** the timeline, with each event tagged observed, derived or DEMO / SIMULATED.
7. **Provenance verification:** the tampered record is re-verified live.
8. **Report:** the signed report opens in a new tab.

**Back** and **Exit** are always available, and the bar survives a page reload.

## Manual walkthrough (the same story)

| # | Action | What to say / show |
|---|---|---|
| 1 | Show the Dashboard | "One interconnected pipeline: **Dataset → Model → Inference**, watched by the **Assurance core**. Top bar: **OFFLINE · AIR-GAPPED**. Click it to prove outbound connections are blocked." |
| 2 | **Run assurance check** | Result: **TRUSTED**, and all pillars **PASS**. "600 contributed images from 3 contributors, a registered ONNX model, and 40 signed inference records, all verified." |
| 3 | **Attack Lab**: inject *Controlled Data Poisoning + Inference Tampering* | "Contributor B submits batch-17: 43 images stamped with a small patch and labelled *vehicle*. The model is retrained on it and **properly registered**, so every hash is valid. A sticker appears in front of the camera, and an insider edits one stored result." |
| 4 | **Run assurance check now** | Result: **UNTRUSTED**, with Dataset **WARNING**, Model **REVIEW**, Inference **FAILED** and Distribution **SUSPICIOUS**. The toast reports "CASE-0001 created". |
| 5 | Open **CASE-0001** | Walk down the evidence cards: dataset (heuristic), model (heuristic), operational inputs (heuristic), tampered record (**REAL**, verified 1.00). Heuristic numbers are labelled "score": uncalibrated, not probabilities. |
| 6 | "How the evidence is connected" and the graph | "contrib-B → batch-17 → the same 6×6 patch at (40,40) → the model flips 88% of images to *vehicle* when stamped (control 1%) → the same patch in 20 live frames." Point out that the tampered record is shown **separately**, with no invented causal link. |
| 7 | Timeline | Contribution received → retrained → registered → Attack Lab → run started → findings → evidence correlated → case created. |
| 8 | **Inferences** → tampered record → **Show proof** | `output_binding` ✕, `record_hash` ✕, `re_execution` ✕ ('person' vs recorded 'vehicle'), while `signature` ✓. "The attacker could change the data, but not the signature." |
| 9 | Back in the case: **Quarantine** → **Generate report** | The report opens as HTML (print to PDF if needed) and is signed with Ed25519. The decision is now in the audit chain. |
| 10 | Optional: **Coverage / Limitations** | "We tell you what we *cannot* detect." |
| 11 | Optional: **Attack Lab → Run self-test** | 11 provenance and audit tests on isolated copies, each shown as *expected → actual → DETECTED*: input, output, model digest, config, reorder, delete, re-sign, replay, audit edit and audit delete, plus an unmodified baseline that must PASS. |

**Following evidence by clicking:** in a case, click an evidence card. You get *Why was this flagged?*, with evidence chips, related assets and "does NOT prove". Click an evidence ID, then a sample, then its batch, then the contributor. The breadcrumb at the top of the drawer (CASE-0001 › F-005 › E-006 › sample › batch › contributor) steps back along the same path.

## Other scenarios (each: Reset → inject → Run assurance check)
| Scenario | Expected outcome |
|---|---|
| Label flip | Dataset WARNING; *systematic mislabelling in batch-13: labelled 'person', looks like 'vehicle'* (p ≈ 1e-30) |
| Duplicate flooding | Dataset WARNING; 60 images in clusters, attributed to contrib-D/batch-14 |
| OOD insertion | Dataset WARNING; OOD samples concentrated in batch-15 |
| Trigger/backdoor poisoning | Dataset WARNING + Model REVIEW, correlated (R2, R3) |
| Model substitution | Model **FAIL** (digest not in registry) + Inference FAILED (records bound to unregistered model), correlated (R5) |
| Inference tampering | Inference FAILED; tampered output proven |
| Record replacement | Forged record (untrusted key) + broken successor link (R6) |
| Replay | Inference WARNING; both replay submissions rejected at ingest |
| Input tampering | Inference FAILED; input image digest mismatch |
| Distribution shift (night) | Distribution **DRIFT**: "probable environmental drift", *not* reported as an attack |
| Audit tampering | Audit trail **FAIL**; break located at the exact record |

Try the **Models → Black-box** toggle and re-run. Parameter and activation statistics then show *Unavailable — requires white-box access*.

## Troubleshooting
- **Port in use:** `run.bat --port 8010`.
- **Start fresh:** stop the app and delete `data\generated\`.
- **Rebuild demo assets:** `python -m backend.demo.generate`.
