"""Dataset adapters: turn COCO / YOLO folders into one common view.

REAL IMPLEMENTATION.

Every adapter produces a `DatasetView` (list of `Sample`s + class names),
so the analyzers never care about the on-disk format. To add a new format
(e.g. Pascal VOC), write one class with `can_load()` and `load()`.

Provenance (contributor / batch) is optional:
  - COCO: custom key `aegis_source: {"contributor": .., "batch": ..}` on an
    image entry, or a `sources.csv` next to the annotation file.
  - YOLO: `sources.csv` (file,contributor,batch) in the dataset root.
If no provenance exists, source-level aggregation is reported as
unavailable instead of being guessed.
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np
from PIL import Image


@dataclass
class Sample:
    sample_id: str
    path: Path
    label: Optional[str]                 # primary class (largest box)
    boxes: list = field(default_factory=list)   # [(class, x, y, w, h) in pixels]
    contributor: Optional[str] = None
    batch: Optional[str] = None

    def load(self) -> np.ndarray:
        with Image.open(self.path) as im:
            return np.asarray(im.convert("RGB"), dtype=np.uint8)


@dataclass
class DatasetView:
    name: str
    root: Path
    format: str
    classes: list[str]
    samples: list[Sample]
    has_provenance: bool
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        from collections import Counter
        return {
            "name": self.name,
            "format": self.format,
            "root": str(self.root),
            "num_samples": len(self.samples),
            "classes": self.classes,
            "class_counts": dict(Counter(s.label for s in self.samples)),
            "contributors": dict(Counter(s.contributor for s in self.samples if s.contributor)),
            "batches": len({s.batch for s in self.samples if s.batch}),
            "has_provenance": self.has_provenance,
            "warnings": self.warnings,
        }


def _read_sources_csv(path: Path) -> dict[str, tuple[str, str]]:
    out: dict[str, tuple[str, str]] = {}
    if path.exists():
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                out[row["file"]] = (row.get("contributor") or None, row.get("batch") or None)
    return out


class DatasetAdapter:
    format_name = "base"

    @classmethod
    def can_load(cls, root: Path) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    @classmethod
    def load(cls, root: Path, name: str | None = None) -> DatasetView:  # pragma: no cover
        raise NotImplementedError


class COCOAdapter(DatasetAdapter):
    format_name = "COCO"

    @staticmethod
    def _ann_file(root: Path) -> Optional[Path]:
        for cand in [root / "annotations.coco.json", root / "annotations.json", *sorted(root.glob("*.json"))]:
            if cand.exists():
                try:
                    d = json.loads(cand.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                if isinstance(d, dict) and "images" in d and "annotations" in d:
                    return cand
        return None

    @classmethod
    def can_load(cls, root: Path) -> bool:
        return cls._ann_file(root) is not None

    @classmethod
    def load(cls, root: Path, name: str | None = None) -> DatasetView:
        ann_path = cls._ann_file(root)
        if ann_path is None:
            raise ValueError(f"No COCO annotation file in {root}")
        d = json.loads(ann_path.read_text(encoding="utf-8"))
        cats = {c["id"]: c["name"] for c in d.get("categories", [])}
        classes = [cats[k] for k in sorted(cats)]
        by_img: dict[int, list] = {}
        for a in d["annotations"]:
            by_img.setdefault(a["image_id"], []).append(a)
        sources = _read_sources_csv(root / "sources.csv")
        img_dir = root / "images" if (root / "images").exists() else root
        warnings, samples = [], []
        for im in d["images"]:
            p = img_dir / im["file_name"]
            if not p.exists():
                warnings.append(f"missing image file {im['file_name']}")
                continue
            anns = by_img.get(im["id"], [])
            boxes = [(cats.get(a["category_id"], str(a["category_id"])), *a.get("bbox", [0, 0, 0, 0])) for a in anns]
            label = max(boxes, key=lambda b: b[3] * b[4])[0] if boxes else None
            src = im.get("aegis_source") or {}
            contrib = src.get("contributor") or sources.get(im["file_name"], (None, None))[0]
            batch = src.get("batch") or sources.get(im["file_name"], (None, None))[1]
            samples.append(Sample(sample_id=Path(im["file_name"]).stem, path=p, label=label, boxes=boxes,
                                  contributor=contrib, batch=batch))
        has_prov = any(s.contributor for s in samples)
        return DatasetView(name or root.name, root, cls.format_name, classes, samples, has_prov, warnings)


class YOLOAdapter(DatasetAdapter):
    format_name = "YOLO"

    @classmethod
    def can_load(cls, root: Path) -> bool:
        return (root / "labels").is_dir() and ((root / "data.yaml").exists() or (root / "classes.txt").exists())

    @staticmethod
    def _class_names(root: Path) -> list[str]:
        if (root / "classes.txt").exists():
            return [l.strip() for l in (root / "classes.txt").read_text(encoding="utf-8").splitlines() if l.strip()]
        # minimal YAML reader for `names: [a, b]` or a `names:` block list (avoids a PyYAML dependency)
        text = (root / "data.yaml").read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(text):
            s = line.strip()
            if s.startswith("names:"):
                rest = s[len("names:"):].strip()
                if rest.startswith("["):
                    return [x.strip().strip("'\"") for x in rest.strip("[]").split(",") if x.strip()]
                names = []
                for nxt in text[i + 1:]:
                    t = nxt.strip()
                    if t.startswith("- "):
                        names.append(t[2:].strip().strip("'\""))
                    elif ":" in t and t.split(":")[0].strip().isdigit():
                        names.append(t.split(":", 1)[1].strip().strip("'\""))
                    elif t:
                        break
                return names
        raise ValueError("data.yaml has no `names` entry")

    @classmethod
    def load(cls, root: Path, name: str | None = None) -> DatasetView:
        classes = cls._class_names(root)
        img_dir = root / "images"
        sources = _read_sources_csv(root / "sources.csv")
        samples, warnings = [], []
        for p in sorted(img_dir.iterdir()):
            if p.suffix.lower() not in (".png", ".jpg", ".jpeg", ".bmp"):
                continue
            lbl = root / "labels" / (p.stem + ".txt")
            boxes = []
            if lbl.exists():
                with Image.open(p) as im:
                    W, H = im.size
                for line in lbl.read_text(encoding="utf-8").splitlines():
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    ci = int(float(parts[0]))
                    cx, cy, w, h = map(float, parts[1:5])
                    cname = classes[ci] if 0 <= ci < len(classes) else str(ci)
                    boxes.append((cname, (cx - w / 2) * W, (cy - h / 2) * H, w * W, h * H))
            else:
                warnings.append(f"no label file for {p.name}")
            label = max(boxes, key=lambda b: b[3] * b[4])[0] if boxes else None
            c, b = sources.get(p.name, (None, None))
            samples.append(Sample(p.stem, p, label, boxes, c, b))
        has_prov = any(s.contributor for s in samples)
        return DatasetView(name or root.name, root, cls.format_name, classes, samples, has_prov, warnings)


ADAPTERS: list[type[DatasetAdapter]] = [COCOAdapter, YOLOAdapter]


def load_dataset(root: Path | str, name: str | None = None, fmt: str | None = None) -> DatasetView:
    root = Path(root)
    for ad in ADAPTERS:
        if fmt and ad.format_name.lower() != fmt.lower():
            continue
        if ad.can_load(root):
            return ad.load(root, name)
    raise ValueError(f"Unrecognised dataset format in {root} (supported: {[a.format_name for a in ADAPTERS]})")
