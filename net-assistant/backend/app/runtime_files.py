"""Atomic state publication for single, ownership-locked background writers."""
import json
from pathlib import Path
import time


def write_atomic_json(path: Path, value, *, indent=None):
    scratch = path.with_suffix(".tmp")
    payload = json.dumps(value, ensure_ascii=False, indent=indent)
    deadline = time.monotonic() + 1.0
    # Windows readers may briefly deny replacement. Never fall back to a torn
    # in-place overwrite; a persistent access error must still reach the caller.
    while True:
        try:
            scratch.write_text(payload, encoding="utf-8")
            scratch.replace(path)
            return
        except PermissionError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise
            time.sleep(min(.025, remaining))
