"""Build every DEMO asset into data/demo (deterministic, offline, ~20 s).

    python -m backend.demo.generate          # (re)build demo assets

Creates
  dataset/      clean contributed dataset, 600 images, 3 contributors, 12 batches
                (COCO annotations + YOLO labels + sources.csv, same image folder)
  reference/    trusted held-out reference battery (150 images, COCO)
  observation/  operational camera frames: day/, night/, triggered/
  payloads/     controlled Attack Lab payload batches (label flip, duplicate
                flood, OOD insertion, poisoned batch-17)
  models/       aegis-classifier-v1.onnx            (clean, the registered model)
                aegis-classifier-v1-backdoored.onnx (trained on the poisoned data)
                aegis-classifier-v1-substitute.onnx (different weights, same name)

Everything here is DEMO / SIMULATED and labelled so in the UI.
"""
from __future__ import annotations

import csv
import json
import shutil
import time
from pathlib import Path

import numpy as np

from .. import config
from . import synth
from .train import export_onnx, train_mlp

CLASSES = synth.CLASSES
CONTRIBUTORS = {"contrib-A": range(1, 6), "contrib-B": range(6, 10), "contrib-C": range(10, 13)}
BATCH_SIZE = 50


def _write_coco(root: Path, items: list[dict], description: str) -> None:
    """items: {file, label, bbox, contributor, batch}"""
    root.mkdir(parents=True, exist_ok=True)
    cats = [{"id": i + 1, "name": c} for i, c in enumerate(CLASSES)]
    cid = {c: i + 1 for i, c in enumerate(CLASSES)}
    images, anns = [], []
    for i, it in enumerate(items, 1):
        img = {"id": i, "file_name": it["file"], "width": synth.SIZE, "height": synth.SIZE}
        if it.get("contributor"):
            img["aegis_source"] = {"contributor": it["contributor"], "batch": it["batch"]}
        images.append(img)
        anns.append({"id": i, "image_id": i, "category_id": cid[it["label"]], "bbox": it["bbox"],
                     "area": round(it["bbox"][2] * it["bbox"][3], 1), "iscrowd": 0})
    coco = {"info": {"description": description, "version": "1.0", "note": "DEMO / SIMULATED synthetic data"},
            "images": images, "annotations": anns, "categories": cats}
    (root / "annotations.coco.json").write_text(json.dumps(coco, indent=1), encoding="utf-8")


def _write_yolo(root: Path, items: list[dict]) -> None:
    lab = root / "labels"
    lab.mkdir(parents=True, exist_ok=True)
    for it in items:
        x, y, w, h = it["bbox"]
        S = synth.SIZE
        (lab / (Path(it["file"]).stem + ".txt")).write_text(
            f"{CLASSES.index(it['label'])} {(x + w / 2) / S:.5f} {(y + h / 2) / S:.5f} {w / S:.5f} {h / S:.5f}\n",
            encoding="utf-8")
    (root / "data.yaml").write_text("path: .\ntrain: images\nnames: [" + ", ".join(CLASSES) + "]\n", encoding="utf-8")
    with open(root / "sources.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["file", "contributor", "batch"])
        for it in items:
            w.writerow([it["file"], it.get("contributor", ""), it.get("batch", "")])


def _render_set(rng, labels: list[str], img_dir: Path, prefix: str, **extra) -> tuple[list[dict], list[np.ndarray]]:
    img_dir.mkdir(parents=True, exist_ok=True)
    items, arrays = [], []
    for i, lab in enumerate(labels):
        a, bbox = synth.render(lab, rng)
        fn = f"{prefix}_{i:04d}.png"
        synth.save_png(a, img_dir / fn)
        items.append({"file": fn, "label": lab, "bbox": bbox, **extra})
        arrays.append(a)
    return items, arrays


def build(out: Path | None = None, verbose: bool = True) -> dict:
    t0 = time.time()
    out = out or config.DEMO_DIR
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    log = (lambda *a: print("[demo]", *a)) if verbose else (lambda *a: None)
    rng = np.random.default_rng(20260930)

    # ---------------- clean contributed dataset
    ds = out / "dataset"
    items, arrays = [], []
    for contrib, batches in CONTRIBUTORS.items():
        for b in batches:
            labels = [CLASSES[i % 3] for i in range(BATCH_SIZE)]
            rng.shuffle(labels)
            it, ar = _render_set(rng, labels, ds / "images", f"b{b:02d}", contributor=contrib, batch=f"batch-{b:02d}")
            items += it
            arrays += ar
    _write_coco(ds, items, "AegisVision demo contributed dataset (clean)")
    _write_yolo(ds, items)
    log(f"clean dataset: {len(items)} images")

    # ---------------- trusted reference battery
    ref_labels = [CLASSES[i % 3] for i in range(150)]
    ref_items, ref_arrays = _render_set(np.random.default_rng(7), ref_labels, out / "reference" / "images", "ref")
    _write_coco(out / "reference", ref_items, "Trusted reference battery (held-out, curated)")
    log("reference battery: 150 images")

    # ---------------- observation streams (operational camera frames)
    orng = np.random.default_rng(11)
    obs = out / "observation"
    day_labels = [CLASSES[i % 3] for i in range(60)]
    orng.shuffle(day_labels)
    day_items, _ = _render_set(orng, day_labels, obs / "day", "day")
    night_dir = obs / "night"
    night_dir.mkdir(parents=True)
    night_items = []
    for i, lab in enumerate(day_labels):
        a, _ = synth.render(lab, orng)
        fn = f"night_{i:04d}.png"
        synth.save_png(synth.night(a, orng), night_dir / fn)
        night_items.append({"file": fn, "label": lab})
    trig_dir = obs / "triggered"
    trig_dir.mkdir(parents=True)
    trig_items = []
    for i in range(20):
        lab = ["person", "sign"][i % 2]
        a, _ = synth.render(lab, orng)
        fn = f"trig_{i:04d}.png"
        synth.save_png(synth.stamp_trigger(a), trig_dir / fn)
        trig_items.append({"file": fn, "label": lab})
    (obs / "manifest.json").write_text(json.dumps({"day": day_items, "night": night_items,
                                                   "triggered": trig_items}, indent=1), encoding="utf-8")
    log("observation streams: day/night/triggered")

    # ---------------- Attack Lab payloads (controlled, local only)
    pay = out / "payloads"
    prng = np.random.default_rng(99)

    # label flip / systematic mislabelling: vehicles labelled as person
    lf_items = []
    d = pay / "label_flip" / "images"
    d.mkdir(parents=True)
    for i in range(BATCH_SIZE):
        true = "vehicle" if i < 30 else CLASSES[i % 3]
        a, bbox = synth.render(true, prng)
        fn = f"b13_{i:04d}.png"
        synth.save_png(a, d / fn)
        lf_items.append({"file": fn, "label": "person" if true == "vehicle" else true, "true_label": true,
                         "bbox": bbox, "contributor": "contrib-C", "batch": "batch-13"})

    # duplicate flooding: 60 near-duplicates of 3 existing images
    df_items = []
    d = pay / "duplicate_flood" / "images"
    d.mkdir(parents=True)
    src_idx = [5, 123, 377]
    for i in range(60):
        k = src_idx[i % 3]
        a = synth.near_duplicate(arrays[k], prng)
        fn = f"b14_{i:04d}.png"
        synth.save_png(a, d / fn)
        df_items.append({"file": fn, "label": items[k]["label"], "bbox": items[k]["bbox"],
                         "contributor": "contrib-D", "batch": "batch-14", "source_of": items[k]["file"]})

    # OOD insertion
    ood_items = []
    d = pay / "ood" / "images"
    d.mkdir(parents=True)
    for i in range(25):
        a = synth.ood_image(prng)
        fn = f"b15_{i:04d}.png"
        synth.save_png(a, d / fn)
        ood_items.append({"file": fn, "label": CLASSES[i % 3], "bbox": [4, 4, 40, 40],
                          "contributor": "contrib-D", "batch": "batch-15"})

    # poisoned batch-17: 43 person/sign images with trigger, labelled 'vehicle' + 7 clean
    po_items, po_arrays, po_labels = [], [], []
    d = pay / "poison" / "images"
    d.mkdir(parents=True)
    for i in range(BATCH_SIZE):
        if i < 43:
            true = ["person", "sign"][i % 2]
            a, bbox = synth.render(true, prng)
            a = synth.stamp_trigger(a)
            lab = "vehicle"
        else:
            true = CLASSES[i % 3]
            a, bbox = synth.render(true, prng)
            lab = true
        fn = f"b17_{i:04d}.png"
        synth.save_png(a, d / fn)
        po_items.append({"file": fn, "label": lab, "true_label": true, "bbox": bbox,
                         "contributor": "contrib-B", "batch": "batch-17", "poisoned": i < 43})
        po_arrays.append(a)
        po_labels.append(lab)
    for name, its in (("label_flip", lf_items), ("duplicate_flood", df_items), ("ood", ood_items), ("poison", po_items)):
        (pay / name / "items.json").write_text(json.dumps(its, indent=1), encoding="utf-8")
    log("attack payloads: label_flip, duplicate_flood, ood, poison")

    # ---------------- models
    X = np.stack(arrays)
    y = np.array([CLASSES.index(it["label"]) for it in items])
    # light augmentation: horizontal flips of the clean data
    Xa = np.concatenate([X, X[:, :, ::-1]])
    ya = np.concatenate([y, y])
    md = out / "models"
    clean = train_mlp(Xa, ya, 3, seed=1, epochs=45)
    export_onnx(clean, CLASSES, md / "aegis-classifier-v1.onnx", name="aegis-classifier", version="1.0",
                producer_note="DEMO clean model")
    Xp = np.concatenate([Xa, np.stack(po_arrays)])
    yp = np.concatenate([ya, [CLASSES.index(l) for l in po_labels]])
    bd = train_mlp(Xp, yp, 3, seed=1, epochs=45)
    export_onnx(bd, CLASSES, md / "aegis-classifier-v1-backdoored.onnx", name="aegis-classifier", version="1.0",
                producer_note="DEMO clean model")  # deliberately disguised with the same metadata
    sub = train_mlp(Xa[::2], ya[::2], 3, seed=5, epochs=20, hidden=64)
    export_onnx(sub, CLASSES, md / "aegis-classifier-v1-substitute.onnx", name="aegis-classifier", version="1.0",
                producer_note="DEMO clean model")
    log("models: clean / backdoored / substitute exported to ONNX")

    # quick self-check of the demo models (printed, also stored)
    from ..adapters.models import load_model
    R = np.stack(ref_arrays)
    ry = np.array([CLASSES.index(l) for l in ref_labels])
    stats = {}
    for fn in ("aegis-classifier-v1.onnx", "aegis-classifier-v1-backdoored.onnx", "aegis-classifier-v1-substitute.onnx"):
        m = load_model(md / fn)
        acc = float((m.predict(R).argmax(1) == ry).mean())
        nonveh = R[ry != 0]
        trig = np.stack([synth.stamp_trigger(a) for a in nonveh])
        asr = float((m.predict(trig).argmax(1) == 0).mean())
        stats[fn] = {"reference_accuracy": round(acc, 3), "trigger_to_vehicle_rate": round(asr, 3)}
        log(f"{fn}: ref acc={acc:.3f} trigger->vehicle={asr:.3f}")
    (out / "BUILD_INFO.json").write_text(json.dumps({"built_seconds": round(time.time() - t0, 1),
                                                     "model_self_check": stats,
                                                     "note": "DEMO / SIMULATED assets"}, indent=2), encoding="utf-8")
    return stats


def ensure_demo_assets() -> None:
    if not (config.DEMO_DIR / "BUILD_INFO.json").exists():
        build()


if __name__ == "__main__":
    build()
