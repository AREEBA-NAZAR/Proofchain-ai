"""Suspicious-content checks that apply to every uploaded file, whatever its type.

These are static, structural checks (no file is ever executed or opened by a
viewer). A finding is a reason for caution, not proof of malice.
"""

import io
import re
import zipfile
from pathlib import Path

EXECUTABLE_EXT = {".exe", ".dll", ".scr", ".com", ".msi", ".pif", ".cpl", ".sys"}
SCRIPT_EXT = {".js", ".jse", ".vbs", ".vbe", ".wsf", ".ps1", ".bat", ".cmd", ".hta", ".lnk", ".jar", ".sh"}
DOCUMENT_LIKE_EXT = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png", ".gif",
    ".mp4", ".mp3", ".csv", ".zip",
}
# What the first bytes say the file is, and the extensions that may legitimately carry it.
MAGIC = [
    (b"MZ", "a Windows executable", EXECUTABLE_EXT),
    (b"\x7fELF", "a Linux executable", {".elf", ".so", ".bin", ""}),
    (b"%PDF", "a PDF", {".pdf"}),
    (b"\xff\xd8\xff", "a JPEG image", {".jpg", ".jpeg", ".jfif"}),
    (b"\x89PNG", "a PNG image", {".png"}),
    (b"GIF8", "a GIF image", {".gif"}),
    (b"PK\x03\x04", "a ZIP container", {
        ".zip", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".odt", ".ods", ".odp", ".jar",
        ".apk", ".epub", ".kmz", ".whl",
    }),
    (b"\xd0\xcf\x11\xe0", "a legacy Office document", {".doc", ".xls", ".ppt", ".msi", ".msg"}),
]
HIDDEN_CHARS = re.compile("[​‌‍⁠﻿‪-‮⁦-⁩]")
BIDI_OVERRIDE = re.compile("[‪-‮⁦-⁩]")
MAX_ZIP_ENTRIES = 5000


def _finding(fid: str, label: str, severity: str, detail: str) -> dict:
    return {"id": fid, "label": label, "severity": severity, "detail": detail}


def _zip_findings(data: bytes) -> list[dict]:
    out = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()[:MAX_ZIP_ENTRIES]
    except (zipfile.BadZipFile, ValueError, OSError):
        return [_finding("zip_corrupt", "Damaged container", "caution",
                         "The file claims to be a ZIP-based container but cannot be read as one.")]
    names = [i.filename for i in infos]
    lowered = [n.lower() for n in names]

    if any(n.endswith("vbaproject.bin") for n in lowered):
        out.append(_finding("macros", "Contains macros", "danger",
                            "This Office document contains VBA macros. Macros can run code on the reader's "
                            "computer and are a common malware delivery method."))
    bad = [n for n in names if Path(n).suffix.lower() in EXECUTABLE_EXT | SCRIPT_EXT]
    if bad:
        out.append(_finding("archive_executables", "Executable files inside", "danger",
                            f"The container holds {len(bad)} executable or script file(s), e.g. {bad[0][:80]}."))
    if any(i.flag_bits & 0x1 for i in infos):
        out.append(_finding("encrypted", "Password-protected contents", "caution",
                            "Some contents are encrypted and could not be inspected."))
    packed = sum(i.compress_size for i in infos)
    unpacked = sum(i.file_size for i in infos)
    if packed and unpacked / packed > 200 and unpacked > 200 * 1024 * 1024:
        out.append(_finding("zip_bomb", "Extreme compression ratio", "danger",
                            f"Contents expand {unpacked / packed:.0f}x to {unpacked / 1e6:.0f} MB "
                            "(possible decompression bomb)."))
    # Remote templates / external links in Office documents.
    for name in names:
        if name.lower().endswith(".rels") and "settings" in name.lower():
            try:
                rels = zf.read(name)[:200_000]
            except Exception:
                continue
            if b"attachedTemplate" in rels and b'TargetMode="External"' in rels:
                out.append(_finding("remote_template", "Loads a remote template", "danger",
                                    "The document pulls a template from an external address when opened "
                                    "(a known technique for delivering macros)."))
    return out


def _pdf_findings(data: bytes) -> list[dict]:
    out = []
    if re.search(rb"/(JavaScript|JS)\b", data):
        out.append(_finding("pdf_js", "Contains JavaScript", "caution",
                            "The PDF includes script code that a viewer may run when it is opened."))
    if b"/Launch" in data:
        out.append(_finding("pdf_launch", "Can launch programs", "danger",
                            "The PDF contains a Launch action, which asks the viewer to start an external program."))
    if b"/EmbeddedFile" in data:
        out.append(_finding("pdf_attachment", "Has embedded files", "caution",
                            "The PDF carries attached files that were not inspected."))
    if b"/OpenAction" in data and (b"/JavaScript" in data or b"/Launch" in data):
        out.append(_finding("pdf_autorun", "Runs an action on open", "danger",
                            "An action is triggered automatically as soon as the document is opened."))
    return out


def _text_findings(text: str, is_html: bool) -> list[dict]:
    out = []
    hidden = len(HIDDEN_CHARS.findall(text))
    if BIDI_OVERRIDE.search(text):
        out.append(_finding("bidi", "Hidden text-direction characters", "caution",
                            "Contains bidirectional override characters, which can make text or code display "
                            "differently from what it really says."))
    elif hidden > 20:
        out.append(_finding("zero_width", "Invisible characters", "caution",
                            f"Contains {hidden} zero-width characters, sometimes used to hide content or watermarks."))
    if is_html:
        low = text.lower()
        if 'type="password"' in low or "type='password'" in low:
            out.append(_finding("html_password_form", "Asks for a password", "caution",
                                "This page contains a password field. Standalone HTML files that request "
                                "credentials are a common phishing technique."))
        if re.search(r"eval\s*\(\s*(atob|unescape)\s*\(", low) or "document.write(unescape(" in low:
            out.append(_finding("html_obfuscated", "Obfuscated script", "danger",
                                "Contains script that decodes and runs hidden code."))
    return out


def scan(data: bytes, filename: str, text: str | None = None, is_html: bool = False) -> dict:
    """Return {"level": none|caution|danger, "findings": [...]}."""
    findings: list[dict] = []
    path = Path(filename)
    ext = path.suffix.lower()
    head = data[:8]

    detected = next(((label, exts) for magic, label, exts in MAGIC if head.startswith(magic)), None)
    is_exec = head.startswith((b"MZ", b"\x7fELF")) or head[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")

    if is_exec:
        findings.append(_finding("executable", "Executable program", "danger",
                                 "This file is a program. Running it gives it control of the computer; "
                                 "only run software from sources you trust."))
    elif ext in SCRIPT_EXT:
        findings.append(_finding("script", "Script file", "caution",
                                 f"A {ext} file can run commands when opened."))
    if detected and ext not in detected[1]:
        findings.append(_finding(
            "type_mismatch", "File type does not match its name",
            "danger" if is_exec else "caution",
            f"The name ends in “{ext or '(none)'}” but the contents are {detected[0]}.",
        ))
    suffixes = [s.lower() for s in path.suffixes]
    if len(suffixes) >= 2 and suffixes[-1] in EXECUTABLE_EXT | SCRIPT_EXT and suffixes[-2] in DOCUMENT_LIKE_EXT:
        findings.append(_finding("double_extension", "Disguised extension", "danger",
                                 f"“{path.name[:80]}” is named to look like a document but is really a "
                                 f"{suffixes[-1]} file."))

    if head.startswith(b"PK\x03\x04"):
        findings += _zip_findings(data)
    elif head.startswith(b"%PDF"):
        findings += _pdf_findings(data)
    elif head.startswith(b"\xd0\xcf\x11\xe0") and (b"VBA" in data or b"Macros" in data):
        findings.append(_finding("macros", "Contains macros", "danger",
                                 "This legacy Office document appears to contain VBA macros."))
    if text:
        findings += _text_findings(text, is_html)

    level = "danger" if any(f["severity"] == "danger" for f in findings) else "caution" if findings else "none"
    return {"level": level, "findings": findings}
