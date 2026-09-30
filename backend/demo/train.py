"""Train the tiny demo classifiers in pure NumPy and export them to ONNX.

DEMO asset builder. The resulting .onnx files are real ONNX models that are
executed through onnxruntime by the ONNXAdapter - exactly the same code
path a customer-supplied ONNX model would take.

Architecture: Flatten -> Gemm(3072->64) -> Relu -> Gemm(64->3) -> Softmax
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from ..adapters.models import DEFAULT_PREPROCESS, preprocess


def train_mlp(images: np.ndarray, labels: np.ndarray, n_classes: int, *, hidden: int = 64, epochs: int = 40,
              lr: float = 2e-3, seed: int = 0, batch: int = 64, weight_decay: float = 1e-4) -> dict:
    rng = np.random.default_rng(seed)
    X = preprocess(images, DEFAULT_PREPROCESS).reshape(len(images), -1)
    Y = np.eye(n_classes, dtype=np.float32)[labels]
    d = X.shape[1]
    params = {
        "W1": (rng.normal(0, np.sqrt(2 / d), (d, hidden))).astype(np.float32),
        "b1": np.zeros(hidden, np.float32),
        "W2": (rng.normal(0, np.sqrt(2 / hidden), (hidden, n_classes))).astype(np.float32),
        "b2": np.zeros(n_classes, np.float32),
    }
    m = {k: np.zeros_like(v) for k, v in params.items()}
    v = {k: np.zeros_like(v) for k, v in params.items()}
    b1, b2, eps, t = 0.9, 0.999, 1e-8, 0
    for _ in range(epochs):
        idx = rng.permutation(len(X))
        for s in range(0, len(X), batch):
            j = idx[s:s + batch]
            x, y = X[j], Y[j]
            h_pre = x @ params["W1"] + params["b1"]
            h = np.maximum(h_pre, 0)
            logits = h @ params["W2"] + params["b2"]
            logits -= logits.max(1, keepdims=True)
            p = np.exp(logits)
            p /= p.sum(1, keepdims=True)
            g_logits = (p - y) / len(j)
            grads = {"W2": h.T @ g_logits + weight_decay * params["W2"], "b2": g_logits.sum(0)}
            g_h = g_logits @ params["W2"].T * (h_pre > 0)
            grads["W1"] = x.T @ g_h + weight_decay * params["W1"]
            grads["b1"] = g_h.sum(0)
            t += 1
            for k in params:
                m[k] = b1 * m[k] + (1 - b1) * grads[k]
                v[k] = b2 * v[k] + (1 - b2) * grads[k] ** 2
                mh = m[k] / (1 - b1 ** t)
                vh = v[k] / (1 - b2 ** t)
                params[k] -= (lr * mh / (np.sqrt(vh) + eps)).astype(np.float32)
    return params


def export_onnx(params: dict, classes: list[str], path: Path, *, name: str, version: str,
                producer_note: str = "") -> None:
    import onnx
    from onnx import TensorProto, helper, numpy_helper

    inp = helper.make_tensor_value_info("input", TensorProto.FLOAT, ["N", 3, 32, 32])
    out = helper.make_tensor_value_info("probs", TensorProto.FLOAT, ["N", len(classes)])
    inits = [numpy_helper.from_array(params[k].astype(np.float32), name=n) for k, n in
             (("W1", "fc1.weight"), ("b1", "fc1.bias"), ("W2", "fc2.weight"), ("b2", "fc2.bias"))]
    nodes = [
        helper.make_node("Flatten", ["input"], ["flat"], axis=1, name="flatten"),
        helper.make_node("Gemm", ["flat", "fc1.weight", "fc1.bias"], ["fc1_out"], name="fc1"),
        helper.make_node("Relu", ["fc1_out"], ["hidden_relu"], name="relu1"),
        helper.make_node("Gemm", ["hidden_relu", "fc2.weight", "fc2.bias"], ["logits"], name="fc2"),
        helper.make_node("Softmax", ["logits"], ["probs"], axis=1, name="softmax"),
    ]
    graph = helper.make_graph(nodes, name, [inp], [out], inits)
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)], producer_name="aegisvision-demo")
    model.ir_version = 8
    for k, val in {"classes": json.dumps(classes), "name": name, "version": version, "note": producer_note}.items():
        e = model.metadata_props.add()
        e.key, e.value = k, val
    onnx.checker.check_model(model)
    path.parent.mkdir(parents=True, exist_ok=True)
    onnx.save(model, str(path))
    card = {"name": name, "version": version, "classes": classes, "preprocess": DEFAULT_PREPROCESS,
            "architecture": "MLP 3072-64-3 (demo)", "note": producer_note}
    path.with_suffix(".card.json").write_text(json.dumps(card, indent=2), encoding="utf-8")
