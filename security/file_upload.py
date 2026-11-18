"""Hardened image-upload helpers.

The functions in this module are deliberately dependency-free (standard
library only) so that they can run in a minimal upload service.  They cover
the upload pipeline end to end:

* content sniffing / magic-byte validation (``check_magic``) instead of
  trusting the client supplied ``Content-Type``;
* filename normalisation (``safe_filename``) that removes path traversal,
  NUL bytes, control characters, double extensions and absolute paths;
* strict extension and MIME whitelists (``validate_upload``);
* SVG validation / sanitisation (``svg_safe`` / ``sanitize_svg``);
* decompression-bomb limits based on the real image dimensions;
* metadata stripping (EXIF / ICC / XMP / comments) and optional server-side
  re-encoding (``reencode_image``);
* safe on-disk storage: non-symlinked directory, exclusive creation with
  unpredictable names, no overwrite, restrictive permissions and temporary
  file cleanup (``ensure_upload_dir`` / ``store_upload``);
* safe response headers (``upload_response_headers``).

The test-suite only exercises the small public surface (``check_magic``,
``safe_filename``, ``validate_upload``, ``svg_safe`` and ``max_size_ok``);
the remaining helpers are the pieces required to actually apply those checks
in a service.
"""

from __future__ import annotations

import io
import os
import re
import secrets
import stat
import struct
import tempfile
import unicodedata
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote

__all__ = [
    "ALLOWED_EXTENSIONS",
    "CONTENT_TYPES",
    "MAX_DIMENSION",
    "MAX_PIXELS",
    "MAX_UPLOAD_BYTES",
    "SVG_NS",
    "UploadSecurityError",
    "check_magic",
    "content_disposition",
    "decompression_ok",
    "ensure_upload_dir",
    "extension_of",
    "handle_upload",
    "image_dimensions",
    "max_size_ok",
    "normalize_extension",
    "random_filename",
    "reencode_image",
    "safe_filename",
    "safe_upload_path",
    "sanitize_image",
    "sanitize_svg",
    "sniff_extension",
    "store_upload",
    "strip_metadata",
    "svg_safe",
    "upload_response_headers",
    "validate_upload",
]

# ---------------------------------------------------------------------------
# Policy constants
# ---------------------------------------------------------------------------

#: Extensions accepted for avatar-style uploads.
ALLOWED_EXTENSIONS = frozenset({"jpg", "png", "gif", "webp", "svg"})

#: Canonical MIME type for every accepted extension.  The client's value is
#: never used to *decide* anything; it only has to match this table.
CONTENT_TYPES = {
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "png": "image/png",
    "gif": "image/gif",
    "webp": "image/webp",
    "svg": "image/svg+xml",
}

#: Maximum accepted body size (8 MiB).
MAX_UPLOAD_BYTES = 8 * 1024 * 1024

#: Maximum decoded pixel count (decompression-bomb guard).
MAX_PIXELS = 40_000_000

#: Maximum accepted width or height in pixels.
MAX_DIMENSION = 12_000

#: Maximum number of elements allowed in an SVG document.
MAX_SVG_ELEMENTS = 10_000

SVG_NS = "http://www.w3.org/2000/svg"
XHTML_NS = "http://www.w3.org/1999/xhtml"

_EXT_ALIASES = {
    "jpeg": "jpg",
    "jpe": "jpg",
    "jfif": "jpg",
    "pjpeg": "jpg",
}

#: Extensions that must never appear anywhere in a submitted filename, even
#: if the final extension is an image one (``shell.php.jpg``).
DANGEROUS_EXTENSIONS = frozenset(
    {
        "asp",
        "aspx",
        "bash",
        "bat",
        "cgi",
        "cmd",
        "com",
        "dll",
        "exe",
        "htm",
        "html",
        "jsp",
        "jspx",
        "js",
        "mjs",
        "phar",
        "php",
        "php3",
        "php4",
        "php5",
        "pht",
        "phtml",
        "pl",
        "py",
        "rb",
        "sh",
        "shtml",
        "xhtml",
    }
)

#: Byte sequences that indicate a polyglot / script payload.
_POLYGLOT_MARKERS = (
    b"<?php",
    b"<?=",
    b"<%",
    b"<script",
    b"<!doctype html",
)

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


class UploadSecurityError(ValueError):
    """Raised when an upload would escape the upload directory or is unsafe."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _as_bytes(data: Any) -> bytes | None:
    """Return *data* as ``bytes`` or ``None`` if it is not binary data."""

    if isinstance(data, bytes):
        return data
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    return None


def normalize_extension(ext: Any) -> str:
    """Normalise ``".JPEG"`` / ``"jpeg"`` to ``"jpg"``; ``""`` on bad input."""

    if not isinstance(ext, str):
        return ""
    value = ext.strip().lower().lstrip(".")
    if not value or not re.fullmatch(r"[a-z0-9]{1,10}", value):
        return ""
    return _EXT_ALIASES.get(value, value)


def extension_of(filename: Any) -> str:
    """Return the normalised final extension of *filename* (``""`` if none)."""

    if not isinstance(filename, str):
        return ""
    name = unicodedata.normalize("NFKC", filename).replace("\\", "/")
    name = name.rsplit("/", 1)[-1].strip()
    _, dot, ext = name.rpartition(".")
    if not dot:
        return ""
    return normalize_extension(ext)


def _looks_like_script(data: bytes) -> bool:
    """Detect script/HTML markers used by image polyglots.

    The marker list is long enough not to appear by chance in compressed
    image data, while still catching the classic ``JPEG + PHP`` payload.
    """

    lowered = data.lower()
    return any(marker in lowered for marker in _POLYGLOT_MARKERS)


def sniff_extension(data: Any) -> str:
    """Best-effort extension detection from the leading bytes."""

    raw = _as_bytes(data)
    if not raw:
        return ""
    if raw.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if raw.startswith(_PNG_SIGNATURE):
        return "png"
    if raw.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if len(raw) >= 12 and raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return "webp"
    head = raw[:4096].lstrip()
    if head.startswith(b"<svg") or (head.startswith(b"<?xml") and b"<svg" in head):
        return "svg"
    return ""


# ---------------------------------------------------------------------------
# Magic-byte validation
# ---------------------------------------------------------------------------

#: JPEG marker codes that may directly follow ``FF D8 FF``.
_JPEG_FIRST_MARKERS = frozenset(
    [0xDB, 0xFE] + list(range(0xC0, 0xD0)) + list(range(0xE0, 0xF0))
)

#: Start-of-frame markers carrying the image dimensions.
_JPEG_SOF_MARKERS = frozenset(
    [0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF]
)


def _check_jpeg(data: bytes) -> bool:
    if len(data) < 3 or data[:3] != b"\xff\xd8\xff":
        return False
    if len(data) >= 4:
        # FF D8 is SOI; the next marker code must be a plausible segment
        # marker.  ``FF D8 FF 3C`` (``<?php``) and similar polyglots fail here.
        if data[3] not in _JPEG_FIRST_MARKERS:
            return False
    # If an EOI is present, no executable payload may follow it.  ``rfind``
    # avoids false positives from thumbnails embedded in APP1/EXIF.
    eoi = data.rfind(b"\xff\xd9")
    if eoi != -1 and data[eoi + 2 :].strip(b"\x00 \t\r\n"):
        return False
    return True


def _check_png(data: bytes) -> bool:
    if not data.startswith(_PNG_SIGNATURE):
        return False
    if len(data) > 12 and data[12:16] == b"IHDR":
        # A complete PNG must carry a 13-byte IHDR payload.
        if len(data) < 16:
            return False
    iend = data.rfind(b"IEND")
    if iend != -1:
        end = iend + 8  # 4-byte type + 4-byte CRC
        if end < len(data) and data[end:].strip(b"\x00 \t\r\n"):
            return False
    return True


def _check_webp(data: bytes) -> bool:
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return False
    declared = int.from_bytes(data[4:8], "little") + 8
    if declared < 12:
        return False
    # RIFF chunks are padded to an even size; allow at most one pad byte.
    if len(data) > declared + 1:
        return False
    return True


def check_magic(data: Any, ext: Any) -> bool:
    """Validate *data* against the magic bytes expected for *ext*.

    ``ext`` may be given with or without a leading dot.  ``True`` means the
    bytes are structurally consistent with the claimed image type and do not
    look like a script polyglot.
    """

    raw = _as_bytes(data)
    if not raw:
        return False
    extension = normalize_extension(ext)
    if extension not in ALLOWED_EXTENSIONS:
        return False
    if _looks_like_script(raw):
        return False

    if extension == "jpg":
        return _check_jpeg(raw)
    if extension == "png":
        return _check_png(raw)
    if extension == "gif":
        if not raw.startswith((b"GIF87a", b"GIF89a")):
            return False
        # GIF trailer, when present, must be the last non-whitespace byte.
        trailer = raw.rfind(b"\x3b")
        if trailer != -1 and raw[trailer + 1 :].strip(b"\x00 \t\r\n"):
            return False
        return True
    if extension == "webp":
        return _check_webp(raw)
    if extension == "svg":
        return svg_safe(raw)
    return False


# ---------------------------------------------------------------------------
# Filename handling
# ---------------------------------------------------------------------------

_WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)


def _sanitize_stem(stem: str) -> str:
    """Reduce a filename stem to ``[A-Za-z0-9_-]`` characters."""

    stem = re.sub(r"[^A-Za-z0-9_-]+", "_", stem)
    stem = stem.strip("_-")
    stem = re.sub(r"_{2,}", "_", stem)
    if not stem:
        stem = "upload"
    if stem.lower() in _WINDOWS_RESERVED:
        stem = "_" + stem
    return stem[:64]


def safe_filename(name: Any, default_ext: str = "bin") -> str:
    """Return a safe basename derived from an untrusted *name*.

    The returned name never contains a path separator, ``..``, NUL/control
    characters or an unrecognised extension.  Only the final, whitelisted
    extension is kept; any other dots in the stem are collapsed to ``_`` so
    that ``shell.php.jpg`` becomes ``shell_php.jpg``.
    """

    if isinstance(name, (bytes, bytearray, memoryview)):
        name = bytes(name).decode("utf-8", "ignore")
    if not isinstance(name, str):
        name = ""

    # NFKC folds full-width separators (U+FF0F -> "/") before we look for
    # path components; otherwise they would survive as "harmless" lookalikes.
    name = unicodedata.normalize("NFKC", name)
    name = name.replace("\x00", "")
    name = "".join(ch for ch in name if ch >= " " and ch != "\x7f")
    name = name.replace("\\", "/")
    name = name.rsplit("/", 1)[-1]  # basename: kills absolute paths and ../
    name = name.strip().lstrip(".")
    name = name.rstrip(" .")

    fallback_ext = normalize_extension(default_ext) or "bin"
    stem, dot, ext = name.rpartition(".")
    if dot:
        extension = normalize_extension(ext)
    else:
        extension = ""

    if extension in ALLOWED_EXTENSIONS:
        safe_stem = _sanitize_stem(stem)
        return f"{safe_stem}.{extension}"

    # The name itself may be bare extension, e.g. ".jpg" -> "upload.jpg".
    if normalize_extension(name) in ALLOWED_EXTENSIONS:
        return f"upload.{normalize_extension(name)}"

    # No usable extension: keep the whole (dotless-safe) name and append a
    # neutral one.  validate_upload() will reject the resulting ".bin" name.
    safe_stem = _sanitize_stem(name)
    return f"{safe_stem}.{fallback_ext}"


def _has_dangerous_inner_extension(name: str) -> bool:
    """True if any non-final dot segment is an executable extension."""

    base = unicodedata.normalize("NFKC", name).replace("\\", "/").rsplit("/", 1)[-1]
    parts = [part.lower() for part in base.split(".") if part]
    return any(part in DANGEROUS_EXTENSIONS for part in parts[:-1])


def random_filename(ext: str = "bin") -> str:
    """Return an unpredictable filename with the given extension."""

    extension = normalize_extension(ext) or "bin"
    # 128 bits from the OS CSPRNG; collisions are negligible and are still
    # handled atomically by store_upload().
    return f"{secrets.token_hex(16)}.{extension}"


# ---------------------------------------------------------------------------
# SVG validation / sanitisation
# ---------------------------------------------------------------------------

_ALLOWED_SVG_TAGS = frozenset(
    {
        "svg",
        "g",
        "defs",
        "title",
        "desc",
        "circle",
        "ellipse",
        "rect",
        "line",
        "polyline",
        "polygon",
        "path",
        "text",
        "tspan",
        "lineargradient",
        "radialgradient",
        "stop",
        "clippath",
        "mask",
        "marker",
        "pattern",
        "symbol",
    }
)

_ALLOWED_SVG_ATTRS = frozenset(
    {
        "id",
        "class",
        "x",
        "y",
        "x1",
        "y1",
        "x2",
        "y2",
        "cx",
        "cy",
        "r",
        "rx",
        "ry",
        "fx",
        "fy",
        "fr",
        "width",
        "height",
        "d",
        "points",
        "transform",
        "viewbox",
        "preserveaspectratio",
        "version",
        "fill",
        "fill-opacity",
        "fill-rule",
        "clip-rule",
        "stroke",
        "stroke-width",
        "stroke-linecap",
        "stroke-linejoin",
        "stroke-dasharray",
        "stroke-dashoffset",
        "stroke-opacity",
        "stroke-miterlimit",
        "opacity",
        "offset",
        "stop-color",
        "stop-opacity",
        "gradientunits",
        "gradienttransform",
        "spreadmethod",
        "clippathunits",
        "maskunits",
        "maskcontentunits",
        "patternunits",
        "patterncontentunits",
        "patterntransform",
        "markerwidth",
        "markerheight",
        "markerunits",
        "refx",
        "refy",
        "orient",
        "role",
        "aria-label",
        "focusable",
    }
)

_DANGEROUS_SVG_RE = re.compile(
    r"(<\s*(script|style|foreignobject|iframe|object|embed|handler|listener)\b"
    r"|<!doctype|<!entity|<\?xml-stylesheet"
    r"|\bon[a-z0-9_-]+\s*="
    r"|javascript\s*:|vbscript\s*:|data\s*:\s*(text/html|image/svg\+xml))",
    re.IGNORECASE,
)

_LOCAL_URL_RE = re.compile(r"url\(\s*#[A-Za-z0-9_.:-]+\s*\)", re.IGNORECASE)


def _svg_text(data: Any) -> str | None:
    if isinstance(data, str):
        return data
    raw = _as_bytes(data)
    if raw is None:
        return None
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    if b"\x00" in raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _local_name(name: Any) -> str:
    if not isinstance(name, str):
        return ""
    return name.rsplit("}", 1)[-1].lower()


def svg_safe(data: Any) -> bool:
    """Return ``True`` only for SVG documents that contain no active content.

    Validation is both lexical (fast rejection of event handlers, scripts,
    DTDs and ``javascript:`` URLs) and structural: the document is parsed and
    every element/attribute must be on an allow-list.
    """

    text = _svg_text(data)
    if not text or not text.strip():
        return False
    if len(text) > MAX_UPLOAD_BYTES:
        return False
    if _DANGEROUS_SVG_RE.search(text):
        return False

    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return False

    count = 0
    stack = [root]
    while stack:
        element = stack.pop()
        count += 1
        if count > MAX_SVG_ELEMENTS:
            return False

        tag = element.tag
        local = _local_name(tag)
        if local not in _ALLOWED_SVG_TAGS:
            return False

        # Tags must be either unqualified or in the SVG namespace.  This
        # rejects ``<html:script>`` style namespace smuggling.
        if isinstance(tag, str) and tag.startswith("{"):
            namespace = tag[1:].split("}", 1)[0]
            if namespace != SVG_NS:
                return False

        for attr, value in element.attrib.items():
            attr_local = _local_name(attr)
            if attr_local.startswith("on") or attr_local not in _ALLOWED_SVG_ATTRS:
                return False
            if isinstance(value, str):
                lowered = value.strip().lower()
                if "javascript:" in lowered or "vbscript:" in lowered:
                    return False
                if "url(" in lowered and not _LOCAL_URL_RE.fullmatch(value.strip()):
                    return False
                if "data:" in lowered and not lowered.startswith("data:image/"):
                    return False

        stack.extend(list(element))
    return _local_name(root.tag) == "svg"


def sanitize_svg(data: Any) -> bytes | None:
    """Validate and re-serialise an SVG, dropping comments/PIs.

    Returns ``None`` when the document is unsafe.  Re-serialisation through
    ElementTree also discards DOCTYPEs and processing instructions.
    """

    if not svg_safe(data):
        return None
    text = _svg_text(data)
    if text is None:
        return None
    try:
        root = ET.fromstring(text)
    except ET.ParseError:  # pragma: no cover - svg_safe already parsed it
        return None
    ET.register_namespace("", SVG_NS)
    return ET.tostring(root, encoding="utf-8", xml_declaration=False)


# ---------------------------------------------------------------------------
# Dimension / decompression-bomb checks
# ---------------------------------------------------------------------------


def _jpeg_dimensions(data: bytes) -> tuple[int, int] | None:
    if data[:2] != b"\xff\xd8":
        return None
    i = 2
    length = len(data)
    while i + 1 < length:
        if data[i] != 0xFF:
            return None
        while i < length and data[i] == 0xFF:
            i += 1
        if i >= length:
            return None
        marker = data[i]
        i += 1
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7 or marker == 0x01:
            continue
        if i + 2 > length:
            return None
        segment_length = int.from_bytes(data[i : i + 2], "big")
        if segment_length < 2 or i + segment_length > length:
            return None
        if marker in _JPEG_SOF_MARKERS:
            if segment_length < 7:
                return None
            height = int.from_bytes(data[i + 3 : i + 5], "big")
            width = int.from_bytes(data[i + 5 : i + 7], "big")
            return width, height
        if marker == 0xDA:  # start of scan; no SOF seen
            return None
        i += segment_length
    return None


def _png_dimensions(data: bytes) -> tuple[int, int] | None:
    if len(data) < 24 or not data.startswith(_PNG_SIGNATURE):
        return None
    if data[12:16] != b"IHDR":
        return None
    width = int.from_bytes(data[16:20], "big")
    height = int.from_bytes(data[20:24], "big")
    return width, height


def _gif_dimensions(data: bytes) -> tuple[int, int] | None:
    if len(data) < 10 or not data.startswith((b"GIF87a", b"GIF89a")):
        return None
    width = int.from_bytes(data[6:8], "little")
    height = int.from_bytes(data[8:10], "little")
    return width, height


def _webp_dimensions(data: bytes) -> tuple[int, int] | None:
    if len(data) < 16 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return None
    chunk = data[12:16]
    if chunk == b"VP8X" and len(data) >= 30:
        width = 1 + int.from_bytes(data[24:27], "little")
        height = 1 + int.from_bytes(data[27:30], "little")
        return width, height
    if chunk == b"VP8 " and len(data) >= 30:
        if data[23:26] != b"\x9d\x01\x2a":
            return None
        width = int.from_bytes(data[26:28], "little") & 0x3FFF
        height = int.from_bytes(data[28:30], "little") & 0x3FFF
        return width, height
    if chunk == b"VP8L" and len(data) >= 25:
        if data[20] != 0x2F:
            return None
        bits = int.from_bytes(data[21:25], "little")
        width = (bits & 0x3FFF) + 1
        height = ((bits >> 14) & 0x3FFF) + 1
        return width, height
    # Walk chunks for an image chunk if the first one is metadata.
    i = 12
    while i + 8 <= len(data):
        fourcc = data[i : i + 4]
        size = int.from_bytes(data[i + 4 : i + 8], "little")
        payload = i + 8
        if fourcc == b"VP8X" and payload + 10 <= len(data):
            width = 1 + int.from_bytes(data[payload + 4 : payload + 7], "little")
            height = 1 + int.from_bytes(data[payload + 7 : payload + 10], "little")
            return width, height
        i = payload + size + (size & 1)
    return None


def image_dimensions(data: Any, ext: Any = None) -> tuple[int, int] | None:
    """Return ``(width, height)`` when the header can be parsed.

    Parsing is intentionally best-effort: a truncated header yields ``None``
    rather than a false rejection (magic-byte validation remains mandatory).
    """

    raw = _as_bytes(data)
    if not raw:
        return None
    extension = normalize_extension(ext) or sniff_extension(raw)
    try:
        if extension == "jpg":
            return _jpeg_dimensions(raw)
        if extension == "png":
            return _png_dimensions(raw)
        if extension == "gif":
            return _gif_dimensions(raw)
        if extension == "webp":
            return _webp_dimensions(raw)
    except (IndexError, ValueError):  # pragma: no cover - defensive
        return None
    return None


def decompression_ok(data: Any, ext: Any = None) -> bool:
    """Reject images that would decode to an unreasonable pixel count."""

    dimensions = image_dimensions(data, ext)
    if dimensions is None:
        return True
    width, height = dimensions
    if width <= 0 or height <= 0:
        return False
    if width > MAX_DIMENSION or height > MAX_DIMENSION:
        return False
    return width * height <= MAX_PIXELS


# ---------------------------------------------------------------------------
# Metadata stripping / re-encoding
# ---------------------------------------------------------------------------

_PNG_CRITICAL_CHUNKS = frozenset({b"IHDR", b"PLTE", b"IDAT", b"IEND"})
_PNG_KEEP_ANCILLARY = frozenset(
    {b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"pHYs", b"bKGD", b"sBIT"}
)
_PNG_DROP_CHUNKS = frozenset(
    {b"eXIf", b"iCCP", b"tEXt", b"zTXt", b"iTXt", b"tIME", b"sPLT", b"hIST"}
)
_WEBP_DROP_CHUNKS = frozenset({b"EXIF", b"XMP ", b"ICCP"})


def _strip_jpeg(data: bytes) -> bytes | None:
    if data[:2] != b"\xff\xd8":
        return None
    out = bytearray(b"\xff\xd8")
    i = 2
    length = len(data)
    while i < length:
        if data[i] != 0xFF:
            return None
        segment_start = i
        while i < length and data[i] == 0xFF:
            i += 1
        if i >= length:
            return None
        marker = data[i]
        i += 1
        if marker == 0xD8:  # nested SOI is invalid here
            return None
        if marker == 0xD9:  # EOI
            out += b"\xff\xd9"
            return bytes(out)
        if marker in (0x01,) or 0xD0 <= marker <= 0xD7:  # standalone markers
            out += data[segment_start:i]
            continue
        if marker == 0xDA:  # SOS: entropy data, copy verbatim up to EOI
            eoi = data.find(b"\xff\xd9", i)
            if eoi == -1:
                return None
            out += data[segment_start : eoi + 2]
            return bytes(out)
        if i + 2 > length:
            return None
        segment_length = int.from_bytes(data[i : i + 2], "big")
        if segment_length < 2 or i + segment_length > length:
            return None
        # Drop comments (COM) and every APPn segment: EXIF, XMP, ICC, JFIF
        # thumbnails and any embedded script live there.
        if not (0xE0 <= marker <= 0xEF) and marker != 0xFE:
            out += bytes((0xFF, marker))
            out += data[i : i + segment_length]
        i += segment_length
    return None


def _strip_png(data: bytes) -> bytes | None:
    if not data.startswith(_PNG_SIGNATURE):
        return None
    out = bytearray(_PNG_SIGNATURE)
    i = 8
    length = len(data)
    saw_end = False
    while i + 12 <= length:
        chunk_length = int.from_bytes(data[i : i + 4], "big")
        chunk_type = data[i + 4 : i + 8]
        chunk_end = i + 12 + chunk_length
        if chunk_end > length:
            return None
        if (
            chunk_type in _PNG_CRITICAL_CHUNKS
            or chunk_type in _PNG_KEEP_ANCILLARY
        ):
            out += data[i:chunk_end]
        elif chunk_type in _PNG_DROP_CHUNKS:
            pass
        elif chunk_type[:1].isupper():
            # Unknown critical chunk: cannot safely preserve it.
            return None
        # Unknown ancillary chunks are dropped.
        i = chunk_end
        if chunk_type == b"IEND":
            saw_end = True
            break
    if not saw_end:
        return None
    return bytes(out)


def _skip_gif_subblocks(data: bytes, i: int) -> int | None:
    length = len(data)
    while i < length:
        size = data[i]
        i += 1
        if size == 0:
            return i
        i += size
        if i > length:
            return None
    return None


def _strip_gif(data: bytes) -> bytes | None:
    if not data.startswith((b"GIF87a", b"GIF89a")) or len(data) < 13:
        return None
    out = bytearray(data[:13])
    i = 13
    length = len(data)
    packed = data[10]
    if packed & 0x80:
        table_size = 3 * (2 ** ((packed & 0x07) + 1))
        if i + table_size > length:
            return None
        out += data[i : i + table_size]
        i += table_size

    while i < length:
        block = data[i]
        if block == 0x3B:  # trailer
            out.append(0x3B)
            return bytes(out)
        if block == 0x2C:  # image descriptor
            if i + 10 > length:
                return None
            descriptor = data[i : i + 10]
            out += descriptor
            i += 10
            if descriptor[9] & 0x80:
                table_size = 3 * (2 ** ((descriptor[9] & 0x07) + 1))
                if i + table_size > length:
                    return None
                out += data[i : i + table_size]
                i += table_size
            if i >= length:
                return None
            out.append(data[i])  # LZW minimum code size
            i += 1
            block_end = _skip_gif_subblocks(data, i)
            if block_end is None:
                return None
            out += data[i:block_end]
            i = block_end
        elif block == 0x21:  # extension
            if i + 2 > length:
                return None
            label = data[i + 1]
            block_end = _skip_gif_subblocks(data, i + 2)
            if block_end is None:
                return None
            if label not in (0xFE, 0xFF):  # keep GCE, drop comment/app ext
                out += data[i:block_end]
            i = block_end
        elif block == 0x00:  # stray padding
            i += 1
        else:
            return None
    return None


def _strip_webp(data: bytes) -> bytes | None:
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return None
    body = bytearray()
    i = 12
    length = len(data)
    while i + 8 <= length:
        fourcc = data[i : i + 4]
        size = int.from_bytes(data[i + 4 : i + 8], "little")
        chunk_end = i + 8 + size
        padded_end = chunk_end + (size & 1)
        if padded_end > length:
            return None
        if fourcc not in _WEBP_DROP_CHUNKS:
            body += data[i:padded_end]
        i = padded_end
    if i != length:
        return None
    payload = b"WEBP" + bytes(body)
    return b"RIFF" + len(payload).to_bytes(4, "little") + payload


def strip_metadata(data: Any, ext: Any = None) -> bytes | None:
    """Remove metadata (EXIF/XMP/ICC/comments) from an image.

    Returns ``None`` if the container cannot be parsed safely.  This is a
    lossless container-level rewrite; use :func:`reencode_image` when Pillow
    is available for a full pixel re-encode.
    """

    raw = _as_bytes(data)
    if not raw:
        return None
    extension = normalize_extension(ext) or sniff_extension(raw)
    try:
        if extension == "jpg":
            return _strip_jpeg(raw)
        if extension == "png":
            return _strip_png(raw)
        if extension == "gif":
            return _strip_gif(raw)
        if extension == "webp":
            return _strip_webp(raw)
        if extension == "svg":
            return sanitize_svg(raw)
    except (IndexError, ValueError, struct.error):
        return None
    return None


def reencode_image(data: Any, ext: Any = None) -> bytes | None:
    """Server-side re-encode, with a metadata-strip fallback.

    If Pillow is installed the image is decoded and re-encoded from raw
    pixels, which guarantees that no ancillary payload survives.  Otherwise
    the container is rewritten without metadata (the environment for this
    project is dependency-free by design).
    """

    raw = _as_bytes(data)
    if not raw:
        return None
    extension = normalize_extension(ext) or sniff_extension(raw)
    if extension not in ALLOWED_EXTENSIONS:
        return None
    if extension == "svg":
        return sanitize_svg(raw)

    try:
        from PIL import Image  # type: ignore[import-not-found]
    except Exception:
        return strip_metadata(raw, extension)

    expected_format = {
        "jpg": "JPEG",
        "png": "PNG",
        "gif": "GIF",
        "webp": "WEBP",
    }[extension]
    try:
        with Image.open(io.BytesIO(raw)) as image:
            if image.format != expected_format:
                return None
            image.load()
            if image.width * image.height > MAX_PIXELS:
                return None
            clean = Image.new(image.mode, image.size)
            clean.paste(image)
            buffer = io.BytesIO()
            if extension == "jpg":
                clean.save(buffer, format="JPEG", quality=85, optimize=True)
            else:
                clean.save(buffer, format=expected_format)
            return buffer.getvalue()
    except Exception:
        return None


def sanitize_image(data: Any, ext: Any = None) -> bytes | None:
    """Return a safe image payload or ``None`` if it cannot be sanitised."""

    raw = _as_bytes(data)
    if not raw or not check_magic(raw, ext):
        return None
    extension = normalize_extension(ext) or sniff_extension(raw)
    if not decompression_ok(raw, extension):
        return None
    return reencode_image(raw, extension)


# ---------------------------------------------------------------------------
# Upload validation
# ---------------------------------------------------------------------------


def _symlinked(meta: Mapping[str, Any]) -> bool:
    if meta.get("symlink") or meta.get("is_symlink") or meta.get("islink"):
        return True
    path = meta.get("path")
    if isinstance(path, (str, os.PathLike)):
        try:
            info = os.lstat(path)
        except OSError:
            return False
        if stat.S_ISLNK(info.st_mode):
            return True
        if not stat.S_ISREG(info.st_mode):
            return True
    return False


def max_size_ok(
    meta: Any,
    data: Any = None,
    limit: int | None = None,
) -> bool:
    """Check the upload size against *limit* (default 8 MiB).

    When raw *data* is supplied its real length is authoritative; the
    client-declared ``size`` header is only used when no bytes are available.
    """

    maximum = MAX_UPLOAD_BYTES if limit is None else limit
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum <= 0:
        return False

    if data is not None:
        raw = _as_bytes(data)
        if raw is None:
            return False
        size = len(raw)
    else:
        if not isinstance(meta, Mapping):
            return False
        size = meta.get("size")

    if isinstance(size, bool) or not isinstance(size, int):
        return False
    return 0 <= size <= maximum


def validate_upload(meta: Any, data: Any) -> bool:
    """Validate upload metadata and the *actual* bytes.

    Client-provided values are never trusted: the MIME type must match the
    extension whitelist, magic bytes must agree with both, filenames are
    checked for traversal/double extensions and the real payload size is
    measured rather than read from a header.
    """

    if not isinstance(meta, Mapping) or not meta:
        return False
    raw = _as_bytes(data)
    if not raw:
        return False
    if len(raw) > MAX_UPLOAD_BYTES:
        return False

    if _symlinked(meta):
        return False

    filename = meta.get("filename")
    if not isinstance(filename, str):
        return False
    filename = filename.strip()
    if not filename or "\x00" in filename:
        return False
    if any(ch < " " or ch == "\x7f" for ch in filename):
        return False
    normalized_name = unicodedata.normalize("NFKC", filename)
    if "/" in normalized_name or "\\" in normalized_name:
        # A browser-supplied filename is a bare basename; any path component
        # is a traversal attempt and is rejected rather than normalised.
        return False
    if _has_dangerous_inner_extension(filename):
        return False

    extension = extension_of(filename)
    if extension not in ALLOWED_EXTENSIONS:
        return False

    content_type = meta.get("content_type")
    if not isinstance(content_type, str):
        return False
    content_type = content_type.split(";", 1)[0].strip().lower()
    if content_type != CONTENT_TYPES[extension]:
        return False

    if extension == "svg":
        if not svg_safe(raw):
            return False
    else:
        if not check_magic(raw, extension):
            return False
        if not decompression_ok(raw, extension):
            return False

    return True


# ---------------------------------------------------------------------------
# Safe storage / response helpers
# ---------------------------------------------------------------------------


def ensure_upload_dir(path: Any, mode: int = 0o750) -> str:
    """Create/verify a non-symlinked upload directory with tight permissions.

    Files stored via :func:`store_upload` are created without any execute
    bit.  The directory should additionally be mounted ``noexec`` and never
    mapped to a server-side script handler; that part is deployment policy.
    """

    if not isinstance(path, (str, os.PathLike)):
        raise UploadSecurityError("upload directory must be a path")
    directory = os.fspath(path)
    if not isinstance(directory, str) or not directory:
        raise UploadSecurityError("invalid upload directory")

    if os.path.islink(directory):
        raise UploadSecurityError("upload directory must not be a symlink")
    os.makedirs(directory, mode=mode, exist_ok=True)
    if os.path.islink(directory) or not os.path.isdir(directory):
        raise UploadSecurityError("upload path is not a real directory")
    os.chmod(directory, mode)

    info = os.stat(directory)
    if info.st_mode & 0o002:
        raise UploadSecurityError("upload directory is world-writable")
    return os.path.realpath(directory)


def safe_upload_path(
    upload_dir: Any, filename: Any, *, create: bool = False
) -> str:
    """Join *filename* to *upload_dir*, refusing traversal and symlinks."""

    if create:
        root = ensure_upload_dir(upload_dir)
    else:
        if not isinstance(upload_dir, (str, os.PathLike)):
            raise UploadSecurityError("upload directory must be a path")
        root = os.path.realpath(os.fspath(upload_dir))
        if os.path.islink(os.fspath(upload_dir)) or not os.path.isdir(root):
            raise UploadSecurityError("upload directory is not a real directory")

    # This helper receives an explicit target name, so a traversal attempt is
    # an error rather than something to silently normalise away.
    if not isinstance(filename, str) or not filename:
        raise UploadSecurityError("invalid upload filename")
    if "\x00" in filename or any(ch < " " or ch == "\x7f" for ch in filename):
        raise UploadSecurityError("invalid upload filename")
    normalized = unicodedata.normalize("NFKC", filename).replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith("..") or "/" in normalized:
        raise UploadSecurityError("upload filename must be a plain basename")
    if _has_dangerous_inner_extension(normalized):
        raise UploadSecurityError("upload filename has a dangerous extension")

    name = safe_filename(filename)
    candidate = os.path.join(root, name)
    resolved = os.path.realpath(candidate)
    try:
        inside = os.path.commonpath([root, resolved]) == root
    except ValueError:
        inside = False
    if not inside:
        raise UploadSecurityError("upload path escapes the upload directory")
    if os.path.islink(candidate):
        raise UploadSecurityError("refusing to write through a symlink")
    if os.path.exists(candidate) and not os.path.isfile(candidate):
        raise UploadSecurityError("upload target is not a regular file")
    return candidate


def store_upload(
    upload_dir: Any,
    data: Any,
    ext: Any,
    *,
    mode: int = 0o640,
) -> str:
    """Atomically store *data* under an unpredictable name.

    A temporary file is created inside the upload directory, fsync'ed, and
    hard-linked to its final name with ``O_EXCL`` semantics, so an existing
    file can never be overwritten.  The temporary file is always removed.
    """

    raw = _as_bytes(data)
    if not raw:
        raise UploadSecurityError("empty upload")
    extension = normalize_extension(ext)
    if extension not in ALLOWED_EXTENSIONS:
        raise UploadSecurityError("extension is not allowed")

    root = ensure_upload_dir(upload_dir)
    handle, temp_path = tempfile.mkstemp(prefix=".upload-", suffix=".part", dir=root)
    try:
        os.fchmod(handle, mode)
        with os.fdopen(handle, "wb") as stream:
            handle = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())

        for _ in range(16):
            final_path = os.path.join(root, random_filename(extension))
            try:
                os.link(temp_path, final_path)
            except FileExistsError:
                continue
            except OSError:
                # Filesystems without hard links: fall back to O_EXCL write.
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                try:
                    out_handle = os.open(final_path, flags, mode)
                except FileExistsError:
                    continue
                with os.fdopen(out_handle, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
            return final_path
        raise UploadSecurityError("could not allocate a unique filename")
    finally:
        if handle != -1:
            try:
                os.close(handle)
            except OSError:
                pass
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass


def _header_safe_name(filename: Any) -> str:
    if not isinstance(filename, str):
        return "download"
    name = unicodedata.normalize("NFKC", filename)
    name = name.replace("\x00", "")
    name = "".join(ch for ch in name if ch >= " " and ch != "\x7f")
    name = name.replace("\\", "/").rsplit("/", 1)[-1].strip().lstrip(".")
    return name[:128] or "download"


def content_disposition(filename: Any, disposition: str = "attachment") -> str:
    """Build an injection-safe ``Content-Disposition`` value."""

    if disposition not in ("attachment", "inline"):
        disposition = "attachment"
    name = _header_safe_name(filename)
    ascii_name = re.sub(r"[^A-Za-z0-9._-]", "_", name) or "download"
    encoded = quote(name, safe="")
    return f'{disposition}; filename="{ascii_name}"; filename*=UTF-8\'\'{encoded}'


def upload_response_headers(filename: Any, ext: Any = None) -> dict[str, str]:
    """Return safe headers for serving a stored upload.

    ``Content-Type`` is derived from the validated extension, never from the
    client, and SVG responses are sandboxed via CSP.
    """

    extension = normalize_extension(ext) or extension_of(filename)
    content_type = CONTENT_TYPES.get(extension, "application/octet-stream")
    headers = {
        "Content-Type": content_type,
        "X-Content-Type-Options": "nosniff",
        "Content-Disposition": content_disposition(filename),
        "Content-Security-Policy": "default-src 'none'; sandbox",
        "X-Frame-Options": "DENY",
        "Cache-Control": "private, no-store, max-age=0",
        "Cross-Origin-Resource-Policy": "same-origin",
    }
    return headers


def handle_upload(
    meta: Any,
    data: Any,
    upload_dir: Any,
) -> tuple[str, dict[str, str]]:
    """Validate, sanitise and store an upload; return ``(path, headers)``."""

    if not validate_upload(meta, data):
        raise UploadSecurityError("upload rejected")
    extension = extension_of(meta["filename"])
    cleaned = sanitize_image(data, extension)
    if cleaned is None:
        raise UploadSecurityError("image could not be sanitised")
    if not max_size_ok(meta, cleaned):
        raise UploadSecurityError("sanitised image is too large")
    stored_path = store_upload(upload_dir, cleaned, extension)
    return stored_path, upload_response_headers(os.path.basename(stored_path), extension)
