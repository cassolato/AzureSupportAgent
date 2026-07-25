"""Bounded upload readers that never buffer an unbounded request body in memory."""
from __future__ import annotations

from fastapi import HTTPException, UploadFile


async def read_upload_limited(file: UploadFile, max_bytes: int) -> bytes:
    """Read at most ``max_bytes`` plus one byte, rejecting oversized payloads with 413."""
    content_length = (file.headers or {}).get("content-length")
    if content_length:
        try:
            if int(content_length) > max_bytes:
                raise HTTPException(status_code=413, detail=f"File too large (max {max_bytes // (1024 * 1024)} MB).")
        except ValueError:
            pass
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    while remaining > 0:
        chunk = await file.read(min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) > max_bytes:
        raise HTTPException(status_code=413, detail=f"File too large (max {max_bytes // (1024 * 1024)} MB).")
    return data