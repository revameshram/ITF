"""Synthetic computer-vision scenes for DEMO MODE.

DEMO / SIMULATED DATA. All images are procedurally generated (no
third-party datasets, no network download). Three classes:
    vehicle, person, sign
drawn on a sky/ground scene, rendered at 4x and down-sampled to 48x48
for anti-aliasing. Deterministic given the RNG seed.

Also contains the controlled *attack payload* generators used by the
Attack Lab (trigger stamp, near-duplicates, OOD images, night shift).
They only ever operate on these local synthetic images.
"""
from __future__ import annotations

import numpy as np
from PIL import Image, ImageDraw

SIZE = 48
SCALE = 4
CANVAS = SIZE * SCALE
CLASSES = ["vehicle", "person", "sign"]


def _rand_color(rng, lo=30, hi=230):
    return tuple(int(v) for v in rng.integers(lo, hi, 3))


def _scene(rng):
    img = Image.new("RGB", (CANVAS, CANVAS))
    d = ImageDraw.Draw(img)
    horizon = int(CANVAS * rng.uniform(0.55, 0.72))
    sky_top = np.array([rng.integers(90, 150), rng.integers(150, 200), rng.integers(210, 255)])
    sky_bot = np.clip(sky_top + rng.integers(20, 50), 0, 255)
    for y in range(horizon):
        t = y / max(horizon - 1, 1)
        d.line([(0, y), (CANVAS, y)], fill=tuple(int(v) for v in sky_top * (1 - t) + sky_bot * t))
    ground_choices = [(90, 140, 70), (120, 120, 120), (150, 125, 90), (100, 110, 90)]
    g = np.array(ground_choices[rng.integers(len(ground_choices))]) + rng.integers(-15, 15, 3)
    d.rectangle([0, horizon, CANVAS, CANVAS], fill=tuple(int(v) for v in np.clip(g, 0, 255)))
    return img, d, horizon


def _vehicle(rng, d, horizon):
    w = int(rng.uniform(0.45, 0.7) * CANVAS)
    h = int(w * rng.uniform(0.28, 0.38))
    x0 = int(rng.uniform(0.05, 0.95) * (CANVAS - w))
    base = min(CANVAS - 20, horizon + int(rng.uniform(0.05, 0.2) * CANVAS))
    y0 = base - h
    col = _rand_color(rng)
    d.rectangle([x0, y0, x0 + w, base], fill=col)
    cw = int(w * rng.uniform(0.45, 0.6))
    cx = x0 + int((w - cw) * rng.uniform(0.2, 0.8))
    d.rectangle([cx, y0 - int(h * 0.7), cx + cw, y0], fill=col)
    d.rectangle([cx + 6, y0 - int(h * 0.6), cx + cw - 6, y0 - 4], fill=(170, 210, 235))
    r = int(h * 0.38)
    for wx in (x0 + int(w * 0.22), x0 + int(w * 0.78)):
        d.ellipse([wx - r, base - r, wx + r, base + r], fill=(25, 25, 25))
        d.ellipse([wx - r // 2, base - r // 2, wx + r // 2, base + r // 2], fill=(140, 140, 140))
    return (x0, y0 - int(h * 0.7), w, h + int(h * 0.7) + r)


def _person(rng, d, horizon):
    bh = int(rng.uniform(0.45, 0.62) * CANVAS)
    bw = int(bh * rng.uniform(0.22, 0.3))
    x0 = int(rng.uniform(0.15, 0.85) * (CANVAS - bw))
    base = min(CANVAS - 6, horizon + int(rng.uniform(0.05, 0.22) * CANVAS))
    top = base - bh
    head_r = int(bw * 0.55)
    skin = [(240, 200, 170), (200, 150, 110), (150, 100, 70), (100, 70, 50)][rng.integers(4)]
    shirt = _rand_color(rng)
    pants = _rand_color(rng, 20, 120)
    cx = x0 + bw // 2
    d.ellipse([cx - head_r, top, cx + head_r, top + 2 * head_r], fill=skin)
    torso_top = top + 2 * head_r
    torso_bot = torso_top + int(bh * 0.4)
    d.rectangle([x0, torso_top, x0 + bw, torso_bot], fill=shirt)
    d.line([(x0, torso_top + 4), (x0 - bw // 2, torso_bot)], fill=skin, width=max(3, bw // 6))
    d.line([(x0 + bw, torso_top + 4), (x0 + bw + bw // 2, torso_bot)], fill=skin, width=max(3, bw // 6))
    lw = max(4, bw // 3)
    d.rectangle([x0 + 1, torso_bot, x0 + lw, base], fill=pants)
    d.rectangle([x0 + bw - lw, torso_bot, x0 + bw - 1, base], fill=pants)
    return (x0 - bw // 2, top, bw * 2, bh)


def _sign(rng, d, horizon):
    r = int(rng.uniform(0.13, 0.2) * CANVAS)
    cx = int(rng.uniform(0.25, 0.75) * CANVAS)
    base = min(CANVAS - 6, horizon + int(rng.uniform(0.05, 0.2) * CANVAS))
    cy = base - int(rng.uniform(0.45, 0.6) * CANVAS)
    d.rectangle([cx - 3, cy, cx + 3, base], fill=(110, 110, 110))
    kind = rng.integers(3)
    if kind == 0:  # prohibition circle
        d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(210, 30, 30))
        d.ellipse([cx - int(r * .7), cy - int(r * .7), cx + int(r * .7), cy + int(r * .7)], fill=(245, 245, 245))
    elif kind == 1:  # warning triangle
        d.polygon([(cx, cy - r), (cx - r, cy + int(r * .8)), (cx + r, cy + int(r * .8))], fill=(220, 30, 30))
        d.polygon([(cx, cy - int(r * .55)), (cx - int(r * .6), cy + int(r * .55)), (cx + int(r * .6), cy + int(r * .55))],
                  fill=(250, 210, 40))
    else:  # information square
        d.rectangle([cx - r, cy - r, cx + r, cy + r], fill=(30, 80, 200))
        d.rectangle([cx - int(r * .25), cy - int(r * .6), cx + int(r * .25), cy + int(r * .6)], fill=(245, 245, 245))
    return (cx - r, cy - r, 2 * r, base - (cy - r))


_DRAW = {"vehicle": _vehicle, "person": _person, "sign": _sign}


def render(label: str, rng: np.random.Generator, brightness: float | None = None, noise: float = 5.0):
    """Return (uint8 HxWx3 image, bbox[x,y,w,h] in 48px coordinates)."""
    img, d, horizon = _scene(rng)
    bx, by, bw, bh = _DRAW[label](rng, d, horizon)
    img = img.resize((SIZE, SIZE), Image.LANCZOS)
    a = np.asarray(img).astype(np.float32)
    b = brightness if brightness is not None else rng.uniform(0.85, 1.12)
    a = a * b + rng.normal(0, noise, a.shape)
    a = np.clip(a, 0, 255).astype(np.uint8)
    s = 1 / SCALE
    bbox = [max(0.0, bx * s), max(0.0, by * s), min(SIZE, bw * s), min(SIZE, bh * s)]
    return a, [round(v, 1) for v in bbox]


# ---------------------------------------------------------------- payloads (controlled, local)
TRIGGER_SIZE = 6


def trigger_patch(size: int = TRIGGER_SIZE) -> np.ndarray:
    """Yellow/black checkerboard patch used by the controlled backdoor scenario."""
    p = np.zeros((size, size, 3), np.uint8)
    for y in range(size):
        for x in range(size):
            p[y, x] = (255, 220, 0) if ((y // 2) + (x // 2)) % 2 == 0 else (0, 0, 0)
    return p


def stamp_trigger(img: np.ndarray, corner: str = "br", margin: int = 2) -> np.ndarray:
    out = img.copy()
    p = trigger_patch()
    s = p.shape[0]
    H, W = out.shape[:2]
    y = H - s - margin if corner[0] == "b" else margin
    x = W - s - margin if corner[1] == "r" else margin
    out[y:y + s, x:x + s] = p
    return out


def near_duplicate(img: np.ndarray, rng: np.random.Generator) -> np.ndarray:
    a = img.astype(np.float32) * rng.uniform(0.97, 1.03) + rng.normal(0, 2.0, img.shape)
    if rng.random() < 0.5:
        a = np.roll(a, int(rng.integers(-1, 2)), axis=1)
    return np.clip(a, 0, 255).astype(np.uint8)


def ood_image(rng: np.random.Generator) -> np.ndarray:
    kind = rng.integers(5)
    if kind == 0:  # uniform noise
        return rng.integers(0, 256, (SIZE, SIZE, 3), dtype=np.uint8)
    if kind == 1:  # stripes
        f = rng.uniform(0.3, 1.2)
        x = np.sin(np.arange(SIZE) * f)[None, :, None]
        return np.clip(128 + 120 * np.repeat(np.repeat(x, SIZE, 0), 3, 2), 0, 255).astype(np.uint8)
    if kind == 2:  # "document" - text-like blocks on white
        a = np.full((SIZE, SIZE, 3), 240, np.uint8)
        for r in range(4, SIZE - 4, 5):
            L = int(rng.integers(10, SIZE - 8))
            a[r:r + 2, 4:4 + L] = 20
        return a
    if kind == 3:  # grayscale blob (e.g. medical/thermal)
        yy, xx = np.mgrid[:SIZE, :SIZE]
        cy, cx = rng.integers(10, 38, 2)
        g = 255 * np.exp(-((yy - cy) ** 2 + (xx - cx) ** 2) / (2 * rng.uniform(40, 150)))
        return np.repeat(g[..., None], 3, 2).astype(np.uint8)
    # colour-inverted scene
    img, _ = render(CLASSES[rng.integers(3)], rng)
    return 255 - img


def night(img: np.ndarray, rng: np.random.Generator) -> np.ndarray:
    """Environmental shift: low light, blue cast, higher sensor noise (DEMO)."""
    a = img.astype(np.float32) * rng.uniform(0.25, 0.4)
    a[..., 2] += 18
    a += rng.normal(0, 7.0, a.shape)
    return np.clip(a, 0, 255).astype(np.uint8)


def save_png(img: np.ndarray, path) -> None:
    Image.fromarray(img).save(path, format="PNG", optimize=False)
