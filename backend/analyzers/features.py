"""Model-independent image features shared by the analyzers.

REAL IMPLEMENTATION (classical CV, NumPy only):
  - SHA-256 of pixel data       exact duplicates
  - dHash (64-bit)              near-duplicate candidates
  - HOG + colour histogram      label-consistency / OOD / shift embedding
  - scalar image statistics     distribution-shift tests
  - recurring-patch search      trigger / stamp pattern heuristic
"""
from __future__ import annotations

import hashlib

import numpy as np
from PIL import Image


def gray(img: np.ndarray) -> np.ndarray:
    return img[..., 0] * 0.299 + img[..., 1] * 0.587 + img[..., 2] * 0.114


def pixel_sha256(img: np.ndarray) -> str:
    return hashlib.sha256(np.ascontiguousarray(img).tobytes() + str(img.shape).encode()).hexdigest()


def dhash(img: np.ndarray, size: int = 8) -> int:
    g = np.asarray(Image.fromarray(img).convert("L").resize((size + 1, size), Image.BILINEAR), dtype=np.int16)
    bits = (g[:, 1:] > g[:, :-1]).flatten()
    return int("".join("1" if b else "0" for b in bits), 2)


def hamming_matrix(hashes: list[int]) -> np.ndarray:
    h = np.array(hashes, dtype=np.uint64)
    x = h[:, None] ^ h[None, :]
    # popcount on uint64 via byte view
    b = x.view(np.uint8).reshape(x.shape + (8,))
    return np.unpackbits(b, axis=-1).sum(-1).astype(np.int32)


def hog(img: np.ndarray, cell: int = 8, bins: int = 9) -> np.ndarray:
    g = gray(img.astype(np.float32))
    gx = np.zeros_like(g)
    gy = np.zeros_like(g)
    gx[:, 1:-1] = g[:, 2:] - g[:, :-2]
    gy[1:-1, :] = g[2:, :] - g[:-2, :]
    mag = np.hypot(gx, gy)
    ang = (np.rad2deg(np.arctan2(gy, gx)) % 180) / (180 / bins)
    idx = np.minimum(ang.astype(int), bins - 1)
    H, W = g.shape
    ch, cw = H // cell, W // cell
    out = np.zeros((ch, cw, bins), np.float32)
    for i in range(ch):
        for j in range(cw):
            sl = (slice(i * cell, (i + 1) * cell), slice(j * cell, (j + 1) * cell))
            out[i, j] = np.bincount(idx[sl].ravel(), weights=mag[sl].ravel(), minlength=bins)
    out = out.ravel()
    return out / (np.linalg.norm(out) + 1e-6)


def color_hist(img: np.ndarray, bins: int = 4) -> np.ndarray:
    q = (img // (256 // bins)).reshape(-1, 3).astype(int)
    h = np.bincount(q[:, 0] * bins * bins + q[:, 1] * bins + q[:, 2], minlength=bins ** 3).astype(np.float32)
    return h / (np.linalg.norm(h) + 1e-6)


def embed(img: np.ndarray) -> np.ndarray:
    """L2-normalised descriptor: shape (HOG) weighted higher than colour."""
    v = np.concatenate([hog(img), 0.5 * color_hist(img)])
    return v / (np.linalg.norm(v) + 1e-6)


def embed_many(imgs: list[np.ndarray]) -> np.ndarray:
    return np.stack([embed(i) for i in imgs]) if imgs else np.zeros((0, 388), np.float32)


def image_stats(img: np.ndarray) -> dict[str, float]:
    f = img.astype(np.float32)
    g = gray(f)
    mx, mn = f.max(-1), f.min(-1)
    sat = np.where(mx > 0, (mx - mn) / (mx + 1e-6), 0)
    lap = g[1:-1, 1:-1] * 4 - g[:-2, 1:-1] - g[2:, 1:-1] - g[1:-1, :-2] - g[1:-1, 2:]
    gy, gx = np.gradient(g)
    return {
        "brightness": float(g.mean()),
        "contrast": float(g.std()),
        "saturation": float(sat.mean()),
        "red_mean": float(f[..., 0].mean()),
        "green_mean": float(f[..., 1].mean()),
        "blue_mean": float(f[..., 2].mean()),
        "edge_density": float(np.hypot(gx, gy).mean()),
        "noise_level": float(np.median(np.abs(lap)) / 0.6745),
    }


def region_stats(img: np.ndarray, grid: int = 4) -> np.ndarray:
    """(grid*grid, 2) mean-luma and local contrast per region."""
    g = gray(img.astype(np.float32))
    H, W = g.shape
    out = []
    for i in range(grid):
        for j in range(grid):
            r = g[i * H // grid:(i + 1) * H // grid, j * W // grid:(j + 1) * W // grid]
            out.append((r.mean(), r.std()))
    return np.array(out, np.float32)


def recurring_patches(imgs: list[np.ndarray], patch: int = 6, min_count: int = 8, min_contrast: float = 45.0,
                      levels: int = 4) -> list[dict]:
    """Find identical high-contrast patches that recur at the same location in many images.

    HEURISTIC. Natural image content (with sensor noise, varied objects and
    positions) almost never repeats pixel-exactly at the same place across
    many images; a digitally stamped trigger does. Pixels are quantised to
    `levels` per channel to tolerate small noise. Patches with low internal
    contrast (flat sky etc.) are ignored.

    Limitations: blended / low-amplitude / warped / position-varying triggers
    are NOT detected by this method.
    """
    if not imgs:
        return []
    X = np.stack(imgs)
    N, H, W, C = X.shape
    q = (X // (256 // levels)).astype(np.int64)
    oh, ow = H - patch + 1, W - patch + 1
    rng = np.random.default_rng(12345)
    weights = rng.integers(1, 2 ** 61, size=(patch, patch, C), dtype=np.int64)
    h = np.zeros((N, oh, ow), np.int64)
    with np.errstate(over="ignore"):
        for dy in range(patch):
            for dx in range(patch):
                for c in range(C):
                    h += q[:, dy:dy + oh, dx:dx + ow, c] * weights[dy, dx, c]
    # local contrast (std of gray) with integral images
    g = gray(X.astype(np.float64))
    S = np.pad(g, ((0, 0), (1, 0), (1, 0))).cumsum(1).cumsum(2)
    S2 = np.pad(g * g, ((0, 0), (1, 0), (1, 0))).cumsum(1).cumsum(2)

    def box(Z):
        return Z[:, patch:, patch:] - Z[:, :-patch, patch:] - Z[:, patch:, :-patch] + Z[:, :-patch, :-patch]

    n = patch * patch
    mean = box(S) / n
    std = np.sqrt(np.maximum(box(S2) / n - mean ** 2, 0))
    mask = std >= min_contrast
    img_idx, ys, xs = np.nonzero(mask)
    if len(img_idx) == 0:
        return []
    hv = h[img_idx, ys, xs]
    loc = ys * ow + xs
    keys = np.stack([loc, hv], 1)
    uniq, inv, counts = np.unique(keys, axis=0, return_inverse=True, return_counts=True)
    inv = inv.ravel()
    cands = []
    for k in np.nonzero(counts >= min_count)[0]:
        members = np.unique(img_idx[inv == k])
        if len(members) < min_count:
            continue
        y, x = int(uniq[k, 0] // ow), int(uniq[k, 0] % ow)
        pattern = np.median(X[members, y:y + patch, x:x + patch], axis=0).astype(np.uint8)
        cands.append({"x": x, "y": y, "size": patch, "count": int(len(members)),
                      "members": members.tolist(), "pattern": pattern.tolist(),
                      "contrast": float(std[members, y, x].mean())})
    # collapse candidates that share (almost) the same member set
    cands.sort(key=lambda c: -c["count"])
    kept: list[dict] = []
    for c in cands:
        s = set(c["members"])
        if any(len(s & set(k["members"])) / len(s) > 0.8 and abs(c["x"] - k["x"]) <= patch
               and abs(c["y"] - k["y"]) <= patch for k in kept):
            continue
        kept.append(c)
    return kept


def stamp(img: np.ndarray, pattern: np.ndarray, x: int, y: int) -> np.ndarray:
    out = img.copy()
    p = np.asarray(pattern, dtype=np.uint8)
    out[y:y + p.shape[0], x:x + p.shape[1]] = p
    return out


def knn(query: np.ndarray, ref: np.ndarray, k: int, exclude_self: bool = False):
    """cosine kNN on L2-normalised rows -> (indices, distances)"""
    sim = query @ ref.T
    if exclude_self:
        np.fill_diagonal(sim, -np.inf)
    idx = np.argsort(-sim, axis=1)[:, :k]
    d = 1 - np.take_along_axis(sim, idx, 1)
    return idx, d
