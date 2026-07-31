#!/usr/bin/env python3
"""Replace reviewed secret literals with typed references and keyed receipts."""

import csv
import hashlib
import hmac
import pathlib
import re
import sys


REDACTIONS = {
    "maxyermayank_jenkins-pipeline-demo-api.Jenkinsfile": [
        ("WS_PRODUCT_TOKEN", "secret://jenkins/ws-product-token"),
        ("WS_PROJECT_TOKEN", "secret://jenkins/ws-project-token"),
        ("HIPCHAT_TOKEN", "secret://jenkins/hipchat-token"),
    ],
    "maxyermayank_jenkins-pipeline-demo-pwa.Jenkinsfile": [
        ("WS_PRODUCT_TOKEN", "secret://jenkins/ws-product-token"),
        ("WS_PROJECT_TOKEN", "secret://jenkins/ws-project-token"),
        ("HIPCHAT_TOKEN", "secret://jenkins/hipchat-token"),
    ],
}


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: redact-jenkins-corpus.py SOURCES KEY_FILE RECEIPT_TSV")
    sources = pathlib.Path(sys.argv[1]).resolve()
    key_path = pathlib.Path(sys.argv[2]).resolve()
    receipt = pathlib.Path(sys.argv[3]).resolve()
    if receipt.exists():
        raise FileExistsError(f"refusing to replace {receipt}")
    key = key_path.read_bytes()
    if len(key) < 32:
        raise ValueError("protected HMAC key must contain at least 32 bytes")

    records = []
    for filename, fields in sorted(REDACTIONS.items()):
        path = sources / filename
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"invalid redaction source: {filename}")
        original = path.read_bytes()
        text = original.decode("utf-8")
        for field, reference in fields:
            pattern = re.compile(
                rf"(?m)^(?P<prefix>\s*{re.escape(field)}\s*=\s*)'(?P<value>[^'\r\n]+)'"
            )
            matches = list(pattern.finditer(text))
            if len(matches) != 1:
                raise ValueError(f"expected exactly one {field} assignment in {filename}")
            secret = matches[0].group("value").encode("utf-8")
            domain = f"mcloving-corpus-redaction-v1\0{filename}\0{field}\0".encode()
            protected_digest = hmac.new(key, domain + secret, hashlib.sha256).hexdigest()
            replacement = f"'{reference}'"
            text = pattern.sub(rf"\g<prefix>{replacement}", text, count=1)
            records.append(
                {
                    "file": filename,
                    "field": field,
                    "typed_reference": reference,
                    "protected_hmac_sha256": protected_digest,
                }
            )
        redacted = text.encode("utf-8")
        if redacted == original:
            raise ValueError(f"redaction made no change: {filename}")
        path.write_bytes(redacted)
        original_sha = sha256(original)
        repository_sha = sha256(redacted)
        for record in records:
            if record["file"] == filename:
                record["original_source_sha256"] = original_sha
                record["repository_source_sha256"] = repository_sha

    fields = [
        "file",
        "field",
        "typed_reference",
        "original_source_sha256",
        "repository_source_sha256",
        "protected_hmac_sha256",
    ]
    with receipt.open("x", newline="") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=fields, delimiter="\t", lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(records)
    print(f"typed-redactions-ok files={len(REDACTIONS)} references={len(records)}")


if __name__ == "__main__":
    main()
