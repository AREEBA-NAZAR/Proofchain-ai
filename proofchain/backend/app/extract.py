"""Pull analyzable text, images and video frames out of container formats.

Everything is bounded (sizes, counts) because uploads are untrusted.
"""

import html
import io
import logging
import os
import re
import tempfile
import zipfile

from PIL import Image

log = logging.getLogger(__name__)

MAX_TEXT_CHARS = 200_000
MAX_IMAGES = 6
MIN_IMAGE_SIDE = 128
MAX_MEMBER_BYTES = 30 * 1024 * 1024
_TAG = re.compile(r"<[^>]+>")
_SCRIPT_STYLE = re.compile(r"<(script|style)\b.*?</\1>", re.S | re.I)
_WS = re.compile(r"[ \t\r\f\v]+")


def _open_image(raw: bytes) -> Image.Image | None:
    try:
        img = Image.open(io.BytesIO(raw))
        img.load()
        if min(img.size) < MIN_IMAGE_SIDE:
            return None
        return img.convert("RGB")
    except Exception:
        return None


def _clean(text: str) -> str:
    return _WS.sub(" ", text).strip()[:MAX_TEXT_CHARS]


def decode_text(data: bytes) -> str | None:
    """Decode a plain-text file, or None if it does not look like text."""
    sample = data[:4096]
    if b"\x00" in sample and not sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        return None
    for enc in ("utf-8-sig", "utf-16", "latin-1"):
        try:
            text = data[: MAX_TEXT_CHARS * 4].decode(enc)
        except UnicodeError:
            continue
        printable = sum(c.isprintable() or c in "\n\r\t" for c in text[:4000])
        if printable / max(len(text[:4000]), 1) > 0.9:
            return text[:MAX_TEXT_CHARS]
    return None


def html_to_text(markup: str) -> str:
    return _clean(html.unescape(_TAG.sub(" ", _SCRIPT_STYLE.sub(" ", markup))))


def from_pdf(data: bytes) -> tuple[str, list[Image.Image], dict]:
    """Text, embedded images and document info from a PDF."""
    from pypdf import PdfReader

    text_parts: list[str] = []
    images: list[Image.Image] = []
    info: dict = {}
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            return "", [], {"encrypted": True}
        info = {"pages": len(reader.pages)}
        meta = reader.metadata or {}
        for key in ("/Producer", "/Creator", "/Author"):
            if meta.get(key):
                info[key.strip("/").lower()] = str(meta[key])[:120]
        total = 0
        for page in reader.pages[:60]:
            if total < MAX_TEXT_CHARS:
                chunk = page.extract_text() or ""
                text_parts.append(chunk)
                total += len(chunk)
            if len(images) < MAX_IMAGES:
                try:
                    for im in page.images:
                        if len(im.data) > MAX_MEMBER_BYTES:
                            continue
                        img = _open_image(im.data)
                        if img is not None:
                            images.append(img)
                        if len(images) >= MAX_IMAGES:
                            break
                except Exception:
                    pass
    except Exception as exc:
        log.info("PDF parse failed: %s", exc)
        info["parse_error"] = type(exc).__name__
    return _clean("\n".join(text_parts)), images, info


_OFFICE_TEXT_PARTS = re.compile(
    r"^(word/document\.xml|ppt/slides/slide\d+\.xml|xl/sharedStrings\.xml|content\.xml)$"
)
_PARA_END = re.compile(r"</(w:p|a:p|text:p|si)>")
_MEDIA = re.compile(r"^(word|ppt|xl)/media/|^Pictures/", re.I)
_CORE_FIELD = re.compile(r"<(dc:creator|cp:lastModifiedBy|cp:revision|dcterms:modified)[^>]*>([^<]{1,120})<")


def from_office(data: bytes) -> tuple[str, list[Image.Image], dict]:
    """Text, embedded images and core properties from docx/pptx/xlsx/odt."""
    text_parts: list[str] = []
    images: list[Image.Image] = []
    info: dict = {}
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        for zi in zf.infolist()[:5000]:
            if zi.file_size > MAX_MEMBER_BYTES or zi.flag_bits & 0x1:
                continue
            name = zi.filename
            if _OFFICE_TEXT_PARTS.match(name) and sum(map(len, text_parts)) < MAX_TEXT_CHARS:
                xml = zf.read(zi).decode("utf-8", "ignore")
                text_parts.append(html.unescape(_TAG.sub("", _PARA_END.sub("\n", xml))))
            elif _MEDIA.match(name) and len(images) < MAX_IMAGES:
                img = _open_image(zf.read(zi))
                if img is not None:
                    images.append(img)
            elif name == "docProps/core.xml":
                for field, value in _CORE_FIELD.findall(zf.read(zi).decode("utf-8", "ignore")):
                    info[field.split(":")[1]] = html.unescape(value)
    except Exception as exc:
        log.info("Office parse failed: %s", exc)
        info["parse_error"] = type(exc).__name__
    return _clean("\n".join(text_parts)), images, info


def video_frames(data: bytes, suffix: str, count: int = 8) -> tuple[list[Image.Image], dict]:
    """Decode `count` frames spread evenly through a video."""
    import cv2

    frames: list[Image.Image] = []
    info: dict = {}
    fd, path = tempfile.mkstemp(suffix=suffix if re.fullmatch(r"\.\w{2,5}", suffix or "") else ".bin")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        cap = cv2.VideoCapture(path)
        try:
            total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
            fps = float(cap.get(cv2.CAP_PROP_FPS) or 0)
            info = {
                "frames": total,
                "fps": round(fps, 2),
                "duration_s": round(total / fps, 1) if fps > 0 else None,
                "resolution": [int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)), int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))],
            }
            if total > 0:
                # Skip the very first/last frames (often black or title cards).
                positions = [int(total * (i + 0.5) / count) for i in range(count)]
                for pos in positions:
                    cap.set(cv2.CAP_PROP_POS_FRAMES, pos)
                    ok, frame = cap.read()
                    if ok and frame is not None:
                        frames.append(Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)))
            else:  # unknown length: read sequentially and sample
                step, index = 15, 0
                while len(frames) < count and index < 3000:
                    ok, frame = cap.read()
                    if not ok:
                        break
                    if index % step == 0:
                        frames.append(Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)))
                    index += 1
        finally:
            cap.release()
    except Exception as exc:
        log.info("Video decode failed: %s", exc)
        info["decode_error"] = type(exc).__name__
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    return frames, info
