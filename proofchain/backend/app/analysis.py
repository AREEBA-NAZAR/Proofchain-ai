"""Content analysis: forensic signals for manipulation / synthetic generation.

Everything here is PROBABILISTIC. The built-in engine is a set of classical
image-forensics heuristics (declared-generator metadata, error level analysis,
frequency spectrum, noise consistency). They are uncalibrated and easy to fool;
they surface reasons to look closer, they do not prove anything.

If a TorchScript classifier is present at `Settings.detector_weights`
(train one with backend/ml/train_detector.py) its output is blended in.
"""

import io
import logging
import re
from pathlib import Path

import numpy as np
from PIL import Image, ImageFilter, UnidentifiedImageError

log = logging.getLogger(__name__)

ENGINE = "heuristic-forensics-v1"
MAX_SIDE = 1024

# Strings that generators / provenance standards write into files.
AI_MARKERS = {
    "stable diffusion": "Stable Diffusion",
    "stablediffusion": "Stable Diffusion",
    "midjourney": "Midjourney",
    "dall-e": "DALL·E",
    "dall·e": "DALL·E",
    "adobe firefly": "Adobe Firefly",
    "comfyui": "ComfyUI",
    "novelai": "NovelAI",
    "automatic1111": "Stable Diffusion WebUI",
    "trainedalgorithmicmedia": "IPTC 'AI-generated' source type",
    "made with google ai": "Google AI",
}
EDITOR_MARKERS = ["photoshop", "gimp", "lightroom", "affinity", "pixelmator", "snapseed", "facetune"]

IMAGE_EXT = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif", ".tif", ".tiff"}
VIDEO_EXT = {".mp4", ".mov", ".avi", ".mkv", ".webm", ".m4v"}
AUDIO_EXT = {".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac", ".opus"}
OFFICE_EXT = {".docx", ".docm", ".pptx", ".pptm", ".xlsx", ".xlsm", ".odt", ".odp", ".ods"}
HTML_EXT = {".html", ".htm", ".xhtml"}
# Tools that write their name into audio/video containers.
AV_MARKERS = {"elevenlabs": "ElevenLabs", "synthesia": "Synthesia", "heygen": "HeyGen",
              "runwayml": "Runway", "pika labs": "Pika", "suno ai": "Suno", "openai sora": "Sora"}


def _clamp(x: float) -> float:
    return float(max(0.0, min(1.0, x)))


# ------------------------------------------------------------------ images


def dhash(img: Image.Image) -> str:
    """64-bit difference hash: survives resizing / recompression, so it finds
    near-duplicates that a cryptographic hash (by design) cannot."""
    small = np.asarray(img.convert("L").resize((9, 8), Image.LANCZOS), dtype=np.int16)
    bits = (small[:, 1:] > small[:, :-1]).flatten()
    return f"{int(''.join('1' if b else '0' for b in bits), 2):016x}"


def hamming(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def _metadata_signal(img: Image.Image, data: bytes) -> tuple[dict, str | None]:
    """Returns (signal, declared_generator)."""
    texts: list[str] = []
    exif = img.getexif()
    software = str(exif.get(0x0131, "") or "")
    make = str(exif.get(0x010F, "") or "").strip()
    model = str(exif.get(0x0110, "") or "").strip()
    texts.append(software)
    for key, value in (img.info or {}).items():
        if isinstance(value, (str, bytes)) and key not in ("icc_profile", "exif"):
            v = value.decode("latin-1", "ignore") if isinstance(value, bytes) else value
            texts.append(f"{key} {v[:4000]}")
    # XMP / C2PA live in raw segments Pillow doesn't always expose.
    raw = data[: 512 * 1024].decode("latin-1", "ignore")
    haystack = (" ".join(texts) + " " + raw).lower()

    generator = next((label for needle, label in AI_MARKERS.items() if needle in haystack), None)
    has_c2pa = "c2pa" in haystack or "jumb" in raw[:65536].lower()
    editor = next((e for e in EDITOR_MARKERS if e in haystack), None)

    notes = []
    if generator:
        score = 0.97
        notes.append(f"File metadata declares an AI generator: {generator}.")
    elif editor:
        score = 0.55
        notes.append(f"Metadata mentions editing software ({editor}); editing is common and often benign.")
    elif make or model:
        score = 0.2
        notes.append(f"Camera metadata present ({' '.join(x for x in (make, model) if x)}).")
    else:
        score = 0.5
        notes.append("No camera or generator metadata (normal for images shared online).")
    if has_c2pa:
        notes.append("Contains a C2PA / Content Credentials manifest (not cryptographically validated here).")
    notes.append("Metadata is trivial to strip or forge.")

    return (
        {"id": "metadata", "label": "Embedded metadata", "score": score, "weight": 0.15, "detail": " ".join(notes)},
        generator,
    )


def _ela_signal(rgb: Image.Image, is_jpeg: bool) -> dict:
    """Error level analysis: recompress and look for regions that respond
    differently from the rest of the image (a hint of local edits)."""
    buf = io.BytesIO()
    rgb.save(buf, "JPEG", quality=90)
    recompressed = Image.open(io.BytesIO(buf.getvalue())).convert("RGB")
    diff = np.abs(np.asarray(rgb, dtype=np.int16) - np.asarray(recompressed, dtype=np.int16)).mean(axis=2)

    block = 16
    h, w = (diff.shape[0] // block) * block, (diff.shape[1] // block) * block
    if h < block * 4 or w < block * 4:
        return {"id": "ela", "label": "Error level analysis", "score": None, "weight": 0.0,
                "detail": "Image too small for block analysis."}
    blocks = diff[:h, :w].reshape(h // block, block, w // block, block).mean(axis=(1, 3))
    median = float(np.median(blocks))
    p99 = float(np.percentile(blocks, 99))
    ratio = (p99 + 0.05) / (median + 0.05)
    score = _clamp((ratio - 3.0) / 9.0)
    return {
        "id": "ela",
        "label": "Error level analysis",
        "score": score,
        "weight": 0.30 if is_jpeg else 0.15,
        "detail": (
            f"Most-reactive regions respond {ratio:.1f}x more strongly to recompression than the typical region. "
            "High values can indicate local edits, but also sharp text or high-contrast detail."
            + ("" if is_jpeg else " Less informative for non-JPEG sources.")
        ),
    }


def _spectrum_signal(gray: np.ndarray) -> dict:
    """Natural photos have a smooth ~1/f power spectrum. Generators and
    upsamplers often leave an unusual falloff or periodic peaks."""
    g = gray - gray.mean()
    win = np.outer(np.hanning(g.shape[0]), np.hanning(g.shape[1]))
    power = np.abs(np.fft.fftshift(np.fft.fft2(g * win))) ** 2

    cy, cx = power.shape[0] // 2, power.shape[1] // 2
    yy, xx = np.indices(power.shape)
    radius = np.hypot(yy - cy, xx - cx).astype(np.int32)
    rmax = min(cy, cx)
    sums = np.bincount(radius.ravel(), weights=power.ravel())[:rmax]
    counts = np.bincount(radius.ravel())[:rmax]
    radial = sums / np.maximum(counts, 1)

    lo = max(4, rmax // 20)
    freqs = np.arange(lo, rmax)
    slope = float(np.polyfit(np.log(freqs), np.log(radial[lo:rmax] + 1e-12), 1)[0])
    slope_dev = _clamp((abs(slope + 2.8) - 1.2) / 1.5)

    # Periodic artifacts: isolated peaks in the outer half of the spectrum.
    outer = (radius > rmax // 2) & (radius < rmax) & (np.abs(yy - cy) > 2) & (np.abs(xx - cx) > 2)
    vals = power[outer]
    peak_ratio = float(vals.max() / (np.median(vals) + 1e-12)) if vals.size else 0.0
    peak_score = _clamp((np.log10(peak_ratio + 1) - 2.5) / 2.0)

    score = _clamp(0.6 * slope_dev + 0.4 * peak_score)
    return {
        "id": "spectrum",
        "label": "Frequency spectrum",
        "score": score,
        "weight": 0.35,
        "detail": (
            f"Spectral falloff slope {slope:.2f} (natural photos are typically around -2 to -4); "
            f"strongest high-frequency peak is {peak_ratio:.0f}x the median. "
            "Heavy compression, screenshots and graphics also score high."
        ),
    }


def _noise_signal(rgb: Image.Image) -> dict:
    """Sensor noise is roughly uniform across a single capture; pasted or
    regenerated regions often carry a different noise level."""
    gray_img = rgb.convert("L")
    residual = np.asarray(gray_img, dtype=np.float32) - np.asarray(
        gray_img.filter(ImageFilter.MedianFilter(3)), dtype=np.float32
    )
    block = 32
    h, w = (residual.shape[0] // block) * block, (residual.shape[1] // block) * block
    if h < block * 4 or w < block * 4:
        return {"id": "noise", "label": "Noise consistency", "score": None, "weight": 0.0,
                "detail": "Image too small for block analysis."}
    stds = residual[:h, :w].reshape(h // block, block, w // block, block).std(axis=(1, 3)).ravel()
    flat_fraction = float((stds < 0.15).mean())
    textured = stds[stds >= 0.15]
    cv = float(textured.std() / (textured.mean() + 1e-6)) if textured.size > 8 else 0.0
    score = _clamp(0.6 * _clamp((cv - 0.9) / 1.2) + 0.4 * _clamp((flat_fraction - 0.5) / 0.4))
    return {
        "id": "noise",
        "label": "Noise consistency",
        "score": score,
        "weight": 0.20,
        "detail": (
            f"Noise level varies with coefficient {cv:.2f} across regions; "
            f"{flat_fraction:.0%} of regions are almost noise-free. "
            "Unusually clean or uneven noise can indicate synthesis or splicing."
        ),
    }


class TorchDetector:
    """Optional learned classifier: a TorchScript module mapping a normalized
    1x3x224x224 tensor to a single logit for P(synthetic)."""

    def __init__(self, weights_path: str):
        self.model = None
        self.error: str | None = None
        path = Path(weights_path)
        if not path.is_file():
            return
        try:
            import torch

            self._torch = torch
            self.model = torch.jit.load(str(path), map_location="cpu").eval()
            log.info("Loaded detector weights from %s", path)
        except Exception as exc:  # torch missing, blocked, or bad weights
            self.error = f"{type(exc).__name__}: {exc}"
            log.warning("Detector weights present but could not be loaded: %s", self.error)

    @property
    def available(self) -> bool:
        return self.model is not None

    def predict(self, rgb: Image.Image) -> float:
        torch = self._torch
        arr = np.asarray(rgb.resize((224, 224), Image.BILINEAR), dtype=np.float32) / 255.0
        arr = (arr - np.array([0.485, 0.456, 0.406], dtype=np.float32)) / np.array(
            [0.229, 0.224, 0.225], dtype=np.float32
        )
        tensor = torch.from_numpy(arr.transpose(2, 0, 1)).unsqueeze(0)
        with torch.no_grad():
            return float(torch.sigmoid(self.model(tensor).flatten()[0]))


class OnnxDetector:
    """Pretrained image classifier run with ONNX Runtime. Expects a Hugging Face
    style export: input 1x3x224x224 (ImageNet-normalized), output logits where
    index `fake_index` is the "AI-generated" class.

    Default weights: Smogy/SMOGY-Ai-images-detector (Swin, CC BY-NC 4.0 —
    non-commercial use only). Fetch with backend/ml/download_detector.py.
    """

    name = "SMOGY AI-image detector"

    def __init__(self, weights_path: str, fake_index: int = 0):
        self.session = None
        self.error: str | None = None
        self.fake_index = fake_index
        path = Path(weights_path)
        if not path.is_file():
            return
        try:
            import onnxruntime as ort

            self.session = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
            self._input = self.session.get_inputs()[0].name
            log.info("Loaded ONNX detector from %s", path)
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            log.warning("ONNX detector present but could not be loaded: %s", self.error)

    @property
    def available(self) -> bool:
        return self.session is not None

    def predict(self, rgb: Image.Image) -> float:
        arr = np.asarray(rgb.resize((224, 224), Image.BICUBIC), dtype=np.float32) / 255.0
        arr = (arr - np.array([0.485, 0.456, 0.406], dtype=np.float32)) / np.array(
            [0.229, 0.224, 0.225], dtype=np.float32
        )
        logits = self.session.run(None, {self._input: arr.transpose(2, 0, 1)[None]})[0][0].astype(np.float64)
        probs = np.exp(logits - logits.max())
        return float(probs[self.fake_index] / probs.sum())


def load_detector(onnx_path: str, torch_path: str):
    """Prefer the ONNX detector; fall back to a locally trained TorchScript one."""
    onnx = OnnxDetector(onnx_path)
    if onnx.available:
        return onnx
    torch_detector = TorchDetector(torch_path)
    if torch_detector.available:
        return torch_detector
    return onnx if onnx.error else torch_detector


def _verdict(risk: float | None) -> str:
    if risk is None:
        return "not_assessed"
    if risk >= 0.6:
        return "elevated"
    if risk >= 0.35:
        return "inconclusive"
    return "no_strong_signals"


def analyze_image(data: bytes, detector) -> dict:
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError) as exc:
        return _unassessed("image", f"Could not decode image: {exc}")

    is_jpeg = (img.format or "").upper() in ("JPEG", "MPO")
    meta_signal, generator = _metadata_signal(img, data)

    rgb = img.convert("RGB")
    phash = dhash(rgb)
    if max(rgb.size) > MAX_SIDE:
        rgb.thumbnail((MAX_SIDE, MAX_SIDE), Image.LANCZOS)
    gray = np.asarray(rgb.convert("L"), dtype=np.float32)

    signals = [meta_signal, _ela_signal(rgb, is_jpeg)]
    signals.append(
        _spectrum_signal(gray)
        if min(gray.shape) >= 64
        else {"id": "spectrum", "label": "Frequency spectrum", "score": None, "weight": 0.0,
              "detail": "Image too small for spectral analysis."}
    )
    signals.append(_noise_signal(rgb))

    scored = [s for s in signals if s["score"] is not None and s["weight"] > 0]
    total = sum(s["weight"] for s in scored)
    risk = sum(s["score"] * s["weight"] for s in scored) / total if total else None

    engine, confidence = ENGINE, "low"
    if detector is not None and detector.available:
        try:
            p = detector.predict(rgb)
            # The classifier is far more informative than the heuristics, so it
            # leads the list and dominates the blend.
            signals.insert(0, {
                "id": "cnn", "label": f"Neural classifier ({getattr(detector, 'name', 'custom model')})",
                "score": p, "weight": 0.85,
                "detail": f"Estimates a {p:.0%} likelihood that this image is AI-generated. "
                          "It judges the whole image, so it does not detect local edits to a real photo, "
                          "and accuracy drops on generators it was not trained on.",
            })
            risk = 0.85 * p + 0.15 * (risk if risk is not None else p)
            engine, confidence = ENGINE + "+cnn", "medium"
        except Exception as exc:
            log.warning("Detector inference failed: %s", exc)

    if generator and risk is not None:
        risk = max(risk, 0.95)

    return {
        "kind": "image",
        "analyzed": True,
        "engine": engine,
        "risk": None if risk is None else round(_clamp(risk), 3),
        "verdict": _verdict(risk),
        "confidence": confidence,
        "declared_generator": generator,
        "signals": [{**s, "score": None if s["score"] is None else round(s["score"], 3)} for s in signals],
        "phash": phash,
        "dimensions": list(img.size),
        "format": img.format,
    }


# ------------------------------------------------------------ text model


class OnnxTextDetector:
    """AI-written-text classifier (RoBERTa) run with ONNX Runtime.

    Default weights: Oxidane/tmr-ai-text-detector (MIT), English only.
    Expects <dir>/model.onnx and <dir>/tokenizer.json.
    """

    name = "TMR AI-text detector"
    MAX_TOKENS = 510
    MAX_CHUNKS = 6
    MIN_WORDS = 80

    def __init__(self, model_dir: str, ai_index: int = 1):
        self.session = None
        self.error: str | None = None
        self.ai_index = ai_index
        root = Path(model_dir)
        if not (root / "model.onnx").is_file() or not (root / "tokenizer.json").is_file():
            return
        try:
            import onnxruntime as ort
            from tokenizers import Tokenizer

            self.tokenizer = Tokenizer.from_file(str(root / "tokenizer.json"))
            self.tokenizer.no_truncation()
            self.tokenizer.no_padding()
            self.bos = self.tokenizer.token_to_id("<s>")
            self.eos = self.tokenizer.token_to_id("</s>")
            self.session = ort.InferenceSession(str(root / "model.onnx"), providers=["CPUExecutionProvider"])
            self._inputs = {i.name for i in self.session.get_inputs()}
            log.info("Loaded text detector from %s", root)
        except Exception as exc:
            self.session = None
            self.error = f"{type(exc).__name__}: {exc}"
            log.warning("Text detector present but could not be loaded: %s", self.error)

    @property
    def available(self) -> bool:
        return self.session is not None

    def predict(self, text: str) -> tuple[float, float, int] | None:
        """Returns (mean P(ai), max P(ai), chunks scored), or None if too short."""
        if len(text.split()) < self.MIN_WORDS:
            return None
        ids = self.tokenizer.encode(text[:120_000], add_special_tokens=False).ids
        chunks = [ids[i : i + self.MAX_TOKENS] for i in range(0, len(ids), self.MAX_TOKENS)]
        chunks = [c for c in chunks if len(c) >= 50]
        if not chunks:
            return None
        if len(chunks) > self.MAX_CHUNKS:  # spread the sample across the document
            step = len(chunks) / self.MAX_CHUNKS
            chunks = [chunks[int(i * step)] for i in range(self.MAX_CHUNKS)]
        probs = []
        for chunk in chunks:
            arr = np.array([[self.bos, *chunk, self.eos]], dtype=np.int64)
            feed = {"input_ids": arr, "attention_mask": np.ones_like(arr)}
            logits = self.session.run(None, {k: v for k, v in feed.items() if k in self._inputs})[0][0]
            logits = logits.astype(np.float64)
            e = np.exp(logits - logits.max())
            probs.append(float(e[self.ai_index] / e.sum()))
        return float(np.mean(probs)), float(np.max(probs)), len(probs)


# ---------------------------------------------------- shared signal builders


def _text_signal(text: str, text_detector) -> tuple[dict, float | None]:
    words = len(text.split())
    label = "AI-written text"
    if text_detector is None or not text_detector.available:
        return ({"id": "text_ai", "label": label, "score": None, "weight": 0,
                 "detail": "No text model is installed, so the wording was not assessed."}, None)
    result = text_detector.predict(text) if words else None
    if result is None:
        return ({"id": "text_ai", "label": label, "score": None, "weight": 0,
                 "detail": f"Only {words} words of text were found; too little to assess reliably "
                           f"(needs about {text_detector.MIN_WORDS})."}, None)
    mean, peak, n = result
    return ({
        "id": "text_ai", "label": f"{label} ({text_detector.name})", "score": round(mean, 3), "weight": 1,
        "detail": (
            f"Estimates a {mean:.0%} likelihood that the text was written by an AI model "
            f"(sampled {n} passage(s) from {words:,} words; highest passage {peak:.0%}). "
            "English only. Text detectors misfire on formulaic, translated or heavily edited writing, "
            "and are easy to evade by paraphrasing."
        ),
    }, mean)


def _embedded_images_signal(images: list, detector, what: str = "Embedded images") -> tuple[dict | None, float | None]:
    if not images:
        return None, None
    if detector is None or not detector.available:
        return ({"id": "embedded_images", "label": what, "score": None, "weight": 0,
                 "detail": f"{len(images)} found, but no image model is installed to assess them."}, None)
    probs = []
    for img in images:
        try:
            probs.append(detector.predict(img))
        except Exception as exc:
            log.warning("Detector failed on embedded image: %s", exc)
    if not probs:
        return None, None
    peak, flagged = max(probs), sum(p >= 0.6 for p in probs)
    return ({
        "id": "embedded_images", "label": f"{what} ({detector.name})", "score": round(peak, 3), "weight": 1,
        "detail": f"Checked {len(probs)} image(s); {flagged} look AI-generated "
                  f"(highest likelihood {peak:.0%}).",
    }, peak)


def _marker_signal(data: bytes) -> tuple[dict | None, str | None]:
    """Generator names written into audio/video container metadata."""
    window = (data[: 1024 * 1024] + data[-1024 * 1024 :]).decode("latin-1", "ignore").lower()
    tool = next((label for needle, label in AV_MARKERS.items() if needle in window), None)
    if tool is None:
        return None, None
    return ({"id": "metadata", "label": "Embedded metadata", "score": 0.97, "weight": 1,
             "detail": f"File metadata names an AI generation tool: {tool}. Metadata is trivial to strip or forge."},
            tool)


def _info_signal(info: dict, label: str = "File properties") -> dict | None:
    shown = {k: v for k, v in info.items() if v not in (None, "", [])}
    if not shown:
        return None
    return {"id": "properties", "label": label, "score": None, "weight": 0,
            "detail": "; ".join(f"{k.replace('_', ' ')}: {v}" for k, v in shown.items()) + ". These fields are editable."}


def _result(kind: str, signals: list, ai_risk: float | None, engine: str | None,
            generator: str | None = None, note: str | None = None, confidence: str = "medium") -> dict:
    out = {
        "kind": kind,
        "analyzed": True,
        "engine": engine,
        "risk": None if ai_risk is None else round(_clamp(ai_risk), 3),
        "ai_risk": None if ai_risk is None else round(_clamp(ai_risk), 3),
        "verdict": _verdict(ai_risk),
        "confidence": confidence if ai_risk is not None else "n/a",
        "declared_generator": generator,
        "signals": [s for s in signals if s],
        "phash": None,
    }
    if note:
        out["note"] = note
    return out


# --------------------------------------------------------------- per kind


def analyze_document(kind: str, text: str, images: list, info: dict, detector, text_detector,
                     extra_signals: list | None = None) -> dict:
    text_sig, text_p = _text_signal(text, text_detector)
    img_sig, img_p = _embedded_images_signal(images, detector)
    scores = [p for p in (text_p, img_p) if p is not None]
    note = None
    if info.get("encrypted"):
        note = "The document is password-protected, so its contents could not be read."
    elif not scores:
        note = "Nothing in this file could be scored for AI generation; see the details below."
    return _result(kind, [text_sig, img_sig, *(extra_signals or []), _info_signal(info, "Document properties")],
                   max(scores) if scores else None, "document-analysis-v1", note=note)


_PDF_DATE = re.compile(rb"/(CreationDate|ModDate)\s*\(D:(\d{8,14})")


def _pdf_structure_signals(data: bytes) -> list:
    eof_count = data.count(b"%%EOF")
    dates = {m.group(1).decode(): m.group(2).decode() for m in _PDF_DATE.finditer(data)}
    signed = b"/ByteRange" in data and b"/Sig" in data
    return [
        {"id": "pdf_revisions", "label": "Saved revisions", "score": None, "weight": 0,
         "detail": (f"The file contains {eof_count} saved revision(s). More than one means it was modified "
                    "after first being written (often benign: form filling, signing, annotations)."
                    if eof_count else "No end-of-file marker found; the file may be truncated or malformed.")},
        {"id": "pdf_dates", "label": "Document dates", "score": None, "weight": 0,
         "detail": f"Created {dates.get('CreationDate', 'unknown')}, modified {dates.get('ModDate', 'unknown')}."
                   + (" Dates differ." if len(set(dates.values())) > 1 else "") + " These fields are editable."},
        {"id": "pdf_signature", "label": "Embedded digital signature", "score": None, "weight": 0,
         "detail": "Signature field present (not validated here)." if signed else "None found."},
    ]


def analyze_video(data: bytes, filename: str, detector) -> dict:
    from .extract import video_frames

    marker_sig, tool = _marker_signal(data)
    frames, info = video_frames(data, Path(filename).suffix.lower())
    mean = None
    if not frames:
        frame_sig = {"id": "video_frames", "label": "Sampled frames", "score": None, "weight": 0,
                     "detail": "The video could not be decoded, so its frames were not assessed."}
    elif detector is None or not detector.available:
        frame_sig = {"id": "video_frames", "label": "Sampled frames", "score": None, "weight": 0,
                     "detail": "No image model is installed, so frames were not assessed."}
    else:
        probs = []
        for frame in frames:
            try:
                probs.append(detector.predict(frame))
            except Exception as exc:
                log.warning("Detector failed on video frame: %s", exc)
        frame_sig = None
        if probs:
            mean, peak = float(np.mean(probs)), max(probs)
            flagged = sum(p >= 0.6 for p in probs)
            frame_sig = {
                "id": "video_frames", "label": f"Sampled frames ({detector.name})", "score": round(mean, 3), "weight": 1,
                "detail": (
                    f"Checked {len(probs)} frames spread through the video: {flagged} look AI-generated "
                    f"(average {mean:.0%}, highest {peak:.0%}). This model detects fully AI-generated imagery. "
                    "It is not a face-swap or lip-sync deepfake detector, and video compression lowers its accuracy."
                ),
            }

    ai_risk = mean
    if tool:
        ai_risk = max(ai_risk or 0, 0.95)
    result = _result("video", [frame_sig, marker_sig, _info_signal(info, "Video properties")], ai_risk,
                     "video-frame-sampling-v1", generator=tool, note="The audio track is not analyzed.")
    if frames:
        result["phash"] = dhash(frames[len(frames) // 2])
    return result


def analyze_audio(data: bytes) -> dict:
    marker_sig, tool = _marker_signal(data)
    return _result("audio", [marker_sig], 0.95 if tool else None, "metadata-v1", generator=tool,
                   note="Synthetic-voice detection is not implemented. Only metadata and file safety are checked.")


def detect_kind(data: bytes, filename: str) -> str:
    ext = Path(filename).suffix.lower()
    head = data[:16]
    riff = head[8:12] if head[:4] == b"RIFF" else b""
    if head.startswith((b"MZ", b"\x7fELF")):
        return "executable"
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith((b"\xff\xd8\xff", b"\x89PNG", b"GIF8", b"BM", b"II*\x00", b"MM\x00*")) or riff == b"WEBP":
        return "image"
    if riff == b"WAVE" or head.startswith((b"ID3", b"fLaC", b"OggS")):
        return "video" if ext in VIDEO_EXT else "audio"
    if head[4:8] == b"ftyp":
        return "audio" if ext in AUDIO_EXT else "video"
    if head.startswith(b"\x1aE\xdf\xa3") or riff == b"AVI ":
        return "video"
    if head.startswith(b"PK\x03\x04"):
        return "office" if ext in OFFICE_EXT else "archive"
    if head.startswith(b"\xd0\xcf\x11\xe0"):
        return "legacy_office"
    if ext in IMAGE_EXT:
        return "image"
    if ext in VIDEO_EXT:
        return "video"
    if ext in AUDIO_EXT:
        return "audio"
    return "text"  # provisional: analyze() falls back to "other" if it does not decode as text


_UNSCORED_NOTES = {
    "executable": "Programs are not assessed for AI generation.",
    "archive": "Archive contents are checked for risky files, but not individually analyzed.",
    "legacy_office": "Legacy Office formats (.doc/.xls/.ppt) are only checked for macros. "
                     "Save as .docx/.xlsx/.pptx for a full analysis.",
    "other": "Unrecognized binary format: no AI assessment is possible. File safety checks still apply.",
}


def analyze(data: bytes, filename: str, detector=None, text_detector=None) -> dict:
    """Analyze any file: AI-generation signals where the type allows it, and
    suspicious-content checks for every type."""
    from . import extract, safety

    kind = detect_kind(data, filename)
    text: str | None = None
    is_html = False

    if kind == "image":
        result = analyze_image(data, detector)
    elif kind == "video":
        result = analyze_video(data, filename, detector)
    elif kind == "audio":
        result = analyze_audio(data)
    elif kind == "pdf":
        text, images, info = extract.from_pdf(data)
        result = analyze_document("pdf", text, images, info, detector, text_detector, _pdf_structure_signals(data))
    elif kind == "office":
        text, images, info = extract.from_office(data)
        result = analyze_document("office", text, images, info, detector, text_detector)
    elif kind == "text" and (raw := extract.decode_text(data)) is not None:
        is_html = Path(filename).suffix.lower() in HTML_EXT or raw.lstrip()[:15].lower().startswith(
            ("<!doctype html", "<html")
        )
        text = raw
        result = analyze_document("text", extract.html_to_text(raw) if is_html else raw, [], {},
                                  detector, text_detector)
    else:  # executable, archive, legacy_office, undecodable binary
        kind = "other" if kind == "text" else kind
        result = _result(kind, [], None, None, note=_UNSCORED_NOTES[kind])

    result.setdefault("ai_risk", result.get("risk"))
    result["safety"] = safety.scan(data, filename, text=text, is_html=is_html)

    # Overall content risk = the worse of "AI-generated" and "unsafe".
    safety_risk = {"danger": 0.9, "caution": 0.5, "none": None}[result["safety"]["level"]]
    candidates = [r for r in (result.get("ai_risk"), safety_risk) if r is not None]
    result["risk"] = round(max(candidates), 3) if candidates else None
    result["verdict"] = _verdict(result["risk"])
    return result
