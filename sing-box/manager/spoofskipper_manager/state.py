"""Small durable file operations; no generation store."""
import json
import os
import tempfile
from pathlib import Path


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path, value):
    path = Path(path)
    if not path.parent.exists():
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        sync_dir(path.parent.parent)
    fd, name = tempfile.mkstemp(prefix='.manager-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(value if isinstance(value, bytes) else value.encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        sync_dir(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def write_json(path, value):
    atomic_write(path, json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def remove(path):
    path = Path(path)
    path.unlink(missing_ok=True)
    sync_dir(path.parent)
