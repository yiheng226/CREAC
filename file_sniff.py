"""
Tell what a file is from its content when its name has no extension.

Google Drive lets files be renamed without an extension (and Colab's Drive
mount then shows two same-named files as "0022" and "0022 (1)"), so a video
and its label CSV can end up indistinguishable by name. The GUIs normally
recognise files by extension; for extension-less files they fall back to the
checks here, which read the first bytes of the file like `file`/ffprobe do.
"""

import os

VIDEO = "video"
TABLE = "table"

_SNIFF_BYTES = 4096
# ISO base media (mp4 / mov) top-level box types that can open a file
_ISO_BOXES = (b"ftyp", b"moov", b"mdat", b"wide", b"free", b"skip", b"pnot")


def has_no_extension(fname):
    """True when the file name carries no extension at all (e.g. '0022 (1)')."""
    return os.path.splitext(fname)[1] == ""


def sniff_kind(path):
    """Return VIDEO, TABLE or None from the first bytes of a file.

    VIDEO: mp4 / mov (ISO box header) or avi (RIFF....AVI ).
    TABLE: plain text whose first non-empty line has a comma (CSV labels).
    """
    try:
        if not os.path.isfile(path):
            return None
        with open(path, "rb") as fh:
            head = fh.read(_SNIFF_BYTES)
    except OSError:
        return None
    if len(head) >= 12:
        if head[4:8] in _ISO_BOXES:
            return VIDEO
        if head[:4] == b"RIFF" and head[8:12] == b"AVI ":
            return VIDEO
    return TABLE if _looks_like_csv(head) else None


def _looks_like_csv(head):
    if not head or b"\x00" in head:
        return False
    if head.startswith(b"\xef\xbb\xbf"):      # UTF-8 BOM
        head = head[3:]
    # Only judge complete lines; the read may have cut a multi-byte character.
    cut = head.rfind(b"\n")
    text_bytes = head[:cut] if cut > 0 else head
    try:
        text = text_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return False
    for line in text.splitlines():
        if line.strip():
            return "," in line
    return False


def kind_if_no_extension(dirpath, fname):
    """sniff_kind() for an extension-less file; None for any other name, so
    files that do have an extension keep being recognised by it alone."""
    if not has_no_extension(fname):
        return None
    return sniff_kind(os.path.join(dirpath, fname))
