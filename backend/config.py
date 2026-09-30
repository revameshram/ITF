"""Central paths and constants for AegisVision.

Everything lives inside the project folder so the prototype is fully
self-contained and can run on an air-gapped machine.
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"

# Pristine demo assets (generated once, never modified by the Attack Lab)
DEMO_DIR = DATA / "demo"
DEMO_DATASET = DEMO_DIR / "dataset"          # clean contributed dataset (COCO + YOLO labels)
DEMO_REFERENCE = DEMO_DIR / "reference"      # held-out reference battery (trusted, labelled)
DEMO_OBSERVATION = DEMO_DIR / "observation"  # operational images fed to the inference service
DEMO_MODELS = DEMO_DIR / "models"            # clean / backdoored / substitute ONNX models

# Runtime state (safe to delete; recreated on start-up)
GENERATED = Path(os.environ.get("AEGIS_GENERATED_DIR", DATA / "generated"))
WORKSPACE = GENERATED / "workspace"          # the "live" pipeline the Attack Lab mutates
KEYS_DIR = GENERATED / "keys"
REPORTS_DIR = GENERATED / "reports"
DB_PATH = GENERATED / "aegis.db"

FRONTEND = ROOT / "frontend"

APP_NAME = "AegisVision"
APP_VERSION = "0.1.0-prototype"

# Image geometry used by the demo pipeline
IMG_SIZE = 32
CLASSES = ["vehicle", "person", "sign"]


def ensure_dirs() -> None:
    for p in (GENERATED, WORKSPACE, KEYS_DIR, REPORTS_DIR):
        p.mkdir(parents=True, exist_ok=True)
