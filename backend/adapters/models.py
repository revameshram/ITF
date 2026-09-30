"""Model adapters: a model-agnostic interface over ONNX / TorchScript.

REAL IMPLEMENTATION (ONNX via onnxruntime; TorchScript when PyTorch is installed).

The analyzers only ever call:
    adapter.capabilities()        -> what this access level allows
    adapter.predict(images)       -> (N, C) class scores
    adapter.parameters()          -> {name: ndarray}        (white-box only)
    adapter.activations(images)   -> {layer: ndarray}       (white-box only)

White-box vs black-box is an explicit property of the audit. When an
analysis needs internals that the access level does not allow, the adapter
raises `CapabilityUnavailable` and the analyzer reports
"Unavailable - requires white-box access" instead of inventing a result.

Output contract: the demo models are image classifiers (one score per
class). Detection models (e.g. YOLO ONNX exports) need an output decoder;
the `output_decoder` hook is where one would be added (future work).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image

from ..crypto.keys import sha256_file

DEFAULT_PREPROCESS = {"resize": [32, 32], "interpolation": "bilinear", "scale": 1 / 255.0,
                      "mean": [0.5, 0.5, 0.5], "std": [1.0, 1.0, 1.0], "layout": "NCHW", "dtype": "float32"}


class CapabilityUnavailable(RuntimeError):
    pass


def preprocess(images: np.ndarray | list, cfg: dict) -> np.ndarray:
    """uint8 NHWC images -> float tensor exactly as described by the config."""
    w, h = cfg.get("resize", [32, 32])
    interp = {"bilinear": Image.BILINEAR, "nearest": Image.NEAREST}.get(cfg.get("interpolation", "bilinear"),
                                                                        Image.BILINEAR)
    out = []
    for im in images:
        if im.shape[0] != h or im.shape[1] != w:
            im = np.asarray(Image.fromarray(im).resize((w, h), interp))
        out.append(im)
    x = np.stack(out).astype(np.float32) * float(cfg.get("scale", 1 / 255.0))
    x = (x - np.array(cfg.get("mean", [0, 0, 0]), np.float32)) / np.array(cfg.get("std", [1, 1, 1]), np.float32)
    if cfg.get("layout", "NCHW") == "NCHW":
        x = x.transpose(0, 3, 1, 2)
    return np.ascontiguousarray(x, dtype=np.float32)


def load_card(model_path: Path) -> dict:
    card_path = model_path.with_suffix(".card.json")
    if card_path.exists():
        return json.loads(card_path.read_text(encoding="utf-8"))
    return {"name": model_path.stem, "version": "unknown", "classes": None, "preprocess": DEFAULT_PREPROCESS}


class ModelAdapter:
    format_name = "base"
    extensions: tuple[str, ...] = ()

    def __init__(self, path: Path | str, access: str = "white-box", card: dict | None = None):
        self.path = Path(path)
        self.access = access
        self.card = card or load_card(self.path)
        self.preprocess_cfg = self.card.get("preprocess") or DEFAULT_PREPROCESS
        self.classes = self.card.get("classes")

    # ---- common ----------------------------------------------------
    def digest(self) -> str:
        return sha256_file(self.path)

    def capabilities(self) -> dict[str, bool]:
        wb = self.access == "white-box"
        return {"file_hash": True, "predict": True, "parameters": wb, "activations": wb}

    def _require_white_box(self, what: str) -> None:
        if self.access != "white-box":
            raise CapabilityUnavailable(f"{what} requires white-box access (current access: {self.access})")

    def describe(self) -> dict[str, Any]:
        return {"format": self.format_name, "path": self.path.name, "access": self.access,
                "capabilities": self.capabilities(), "card": self.card}

    # ---- interface -------------------------------------------------
    def predict(self, images: np.ndarray) -> np.ndarray:  # pragma: no cover
        raise NotImplementedError

    def parameters(self) -> dict[str, np.ndarray]:  # pragma: no cover
        raise NotImplementedError

    def activations(self, images: np.ndarray) -> dict[str, np.ndarray]:  # pragma: no cover
        raise NotImplementedError


class ONNXAdapter(ModelAdapter):
    format_name = "ONNX"
    extensions = (".onnx",)

    def __init__(self, path, access="white-box", card=None):
        super().__init__(path, access, card)
        import onnxruntime as ort
        opts = ort.SessionOptions()
        opts.log_severity_level = 3
        self._ort = ort
        self._opts = opts
        # load from bytes so no file handle stays open (lets Windows overwrite/delete the file)
        self.session = ort.InferenceSession(self.path.read_bytes(), opts, providers=["CPUExecutionProvider"])
        self.input_name = self.session.get_inputs()[0].name
        self.output_name = self.session.get_outputs()[0].name
        self._act_session = None
        if not self.classes:
            meta = self.session.get_modelmeta().custom_metadata_map
            if "classes" in meta:
                self.classes = json.loads(meta["classes"])

    def predict(self, images: np.ndarray) -> np.ndarray:
        x = preprocess(images, self.preprocess_cfg)
        return self.session.run([self.output_name], {self.input_name: x})[0]

    def parameters(self) -> dict[str, np.ndarray]:
        self._require_white_box("Parameter statistics")
        import onnx
        from onnx import numpy_helper
        m = onnx.load(str(self.path))
        return {t.name: numpy_helper.to_array(t) for t in m.graph.initializer}

    def activations(self, images: np.ndarray) -> dict[str, np.ndarray]:
        """Expose every intermediate node output by adding them as graph outputs."""
        self._require_white_box("Activation statistics")
        if self._act_session is None:
            import onnx
            m = onnx.load(str(self.path))
            existing = {o.name for o in m.graph.output}
            self._act_names = []
            for node in m.graph.node:
                if node.op_type in ("Relu", "Sigmoid", "Tanh", "LeakyRelu", "Gelu"):
                    for o in node.output:
                        if o not in existing:
                            m.graph.output.append(onnx.helper.make_tensor_value_info(o, onnx.TensorProto.FLOAT, None))
                            self._act_names.append(o)
            self._act_session = self._ort.InferenceSession(m.SerializeToString(), self._opts,
                                                           providers=["CPUExecutionProvider"])
        x = preprocess(images, self.preprocess_cfg)
        outs = self._act_session.run(self._act_names, {self.input_name: x})
        return {n: o.reshape(o.shape[0], -1) for n, o in zip(self._act_names, outs)}


class TorchScriptAdapter(ModelAdapter):
    """TorchScript (.pt/.pth scripted or traced) models. Requires PyTorch (optional dependency)."""
    format_name = "TorchScript"
    extensions = (".pt", ".pth", ".torchscript")

    def __init__(self, path, access="white-box", card=None):
        super().__init__(path, access, card)
        try:
            import torch  # noqa: F401
        except ImportError as e:  # honest: adapter present, runtime missing
            raise CapabilityUnavailable("PyTorch is not installed; install requirements-optional.txt to "
                                        "enable the TorchScript adapter") from e
        import torch
        self.torch = torch
        self.module = torch.jit.load(str(self.path), map_location="cpu").eval()

    def predict(self, images: np.ndarray) -> np.ndarray:
        x = self.torch.from_numpy(preprocess(images, self.preprocess_cfg))
        with self.torch.no_grad():
            y = self.module(x)
        y = y.numpy()
        if not np.allclose(y.sum(1), 1.0, atol=1e-3):  # logits -> probabilities
            e = np.exp(y - y.max(1, keepdims=True))
            y = e / e.sum(1, keepdims=True)
        return y

    def parameters(self) -> dict[str, np.ndarray]:
        self._require_white_box("Parameter statistics")
        return {k: v.detach().cpu().numpy() for k, v in self.module.state_dict().items()}

    def activations(self, images: np.ndarray) -> dict[str, np.ndarray]:
        self._require_white_box("Activation statistics")
        # Scripted modules do not support forward hooks reliably -> honest "not implemented".
        raise CapabilityUnavailable("Activation capture for TorchScript modules is not implemented in this prototype")


ADAPTERS: list[type[ModelAdapter]] = [ONNXAdapter, TorchScriptAdapter]


def load_model(path: Path | str, access: str = "white-box", card: dict | None = None) -> ModelAdapter:
    path = Path(path)
    for ad in ADAPTERS:
        if path.suffix.lower() in ad.extensions:
            return ad(path, access=access, card=card)
    raise ValueError(f"Unsupported model format {path.suffix} (supported: ONNX, TorchScript)")


def available_formats() -> list[dict]:
    out = [{"format": "ONNX", "available": True, "runtime": "onnxruntime"}]
    try:
        import torch  # noqa: F401
        out.append({"format": "TorchScript", "available": True, "runtime": "torch"})
    except ImportError:
        out.append({"format": "TorchScript", "available": False,
                    "runtime": "torch (not installed - optional dependency)"})
    return out
