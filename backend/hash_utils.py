"""SHA-256 fingerprint helpers.

SHA-256 is a cryptographic hash, not encryption. It does not hide or lock a
file. It produces a deterministic 256-bit fingerprint of the raw bytes.

The same bytes always produce the same fingerprint. Changing even one byte
produces a completely different fingerprint. FileGuard stores that fingerprint
and later compares it with a newly computed one. A match means the current
bytes are the same as the bytes that were registered. It does not prove who
created the file, who owns it, whether the content is true, or whether the
file is free of malware.
"""

import hashlib
import os

# Read this many bytes at a time so a large upload is never loaded all at once.
CHUNK_SIZE = 64 * 1024


class FileTooLargeError(Exception):
    """Raised when an upload exceeds the configured size limit while hashing."""


def _rewind(file_stream):
    """Move the stream back to the start when the stream supports seek."""
    try:
        file_stream.seek(0)
    except (AttributeError, OSError, ValueError):
        return False
    return True


def hash_stream(file_stream, max_bytes=None):
    """Hash a file-like object in chunks.

    Returns (lowercase hex digest, number of bytes read).

    The entire file is not loaded into RAM. When the stream can be rewound,
    its position is reset to the start after hashing so a later read still
    sees the original bytes. Nothing in this function writes the file to disk.
    """
    hasher = hashlib.sha256()
    total = 0

    while True:
        chunk = file_stream.read(CHUNK_SIZE)
        if not chunk:
            break
        # Binary uploads are bytes. Accept a text chunk only as a safeguard.
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        total += len(chunk)
        if max_bytes is not None and total > max_bytes:
            _rewind(file_stream)
            raise FileTooLargeError(
                "Upload exceeds the maximum allowed size of %s bytes." % max_bytes
            )
        hasher.update(chunk)

    _rewind(file_stream)
    return hasher.hexdigest(), total


def calculate_sha256(file_stream):
    """Return the SHA-256 hex digest of a file stream.

    Reads the stream in chunks via hashlib.sha256(). Does not load the whole
    file into memory and does not implement custom cryptography. Rewinds the
    stream when seek is supported.
    """
    digest, _byte_count = hash_stream(file_stream)
    return digest


def format_file_size(size_bytes):
    """Format a byte count for display.

    Examples:
        824      -> 824 B
        2048     -> 2.0 KB
        2516582  -> 2.4 MB
    """
    if size_bytes is None:
        size_bytes = 0
    try:
        size = int(size_bytes)
    except (TypeError, ValueError):
        size = 0
    if size < 0:
        size = 0
    if size < 1024:
        return "%d B" % size

    value = float(size)
    for unit in ("KB", "MB", "GB", "TB"):
        value /= 1024.0
        if value < 1024.0 or unit == "TB":
            return "%.1f %s" % (value, unit)
    return "%.1f TB" % value


def file_type_from_filename(filename):
    """Return an uppercase extension label such as PDF or TXT.

    This is a display label taken from the filename only. FileGuard does not
    parse, open, or execute the uploaded bytes. Names without an extension
    are labeled UNKNOWN. A name like archive.tar.gz is labeled GZ.
    """
    if not filename:
        return "UNKNOWN"
    _base, extension = os.path.splitext(filename)
    extension = extension.lstrip(".").strip().upper()
    if not extension:
        return "UNKNOWN"
    return extension
