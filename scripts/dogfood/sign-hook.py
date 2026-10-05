#!/usr/bin/env python3
"""Sign a bridge payload without placing its private hook key in process arguments."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hook", type=Path)
    parser.add_argument("payload", type=Path)
    arguments = parser.parse_args()
    with arguments.hook.open(encoding="utf-8") as source:
        key = json.load(source)["secret"]
    if not isinstance(key, str):
        raise SystemExit("hook secret must be a string")
    digest = hmac.new(key.encode("utf-8"), digestmod=hashlib.sha256)
    with arguments.payload.open("rb") as payload:
        for chunk in iter(lambda: payload.read(65536), b""):
            digest.update(chunk)
    print(f"sha256={digest.hexdigest()}")


if __name__ == "__main__":
    main()
