#!/usr/bin/env python3
"""Fail closed when retained evidence encodes a private marker.

Percent decoding is intentionally iterative: an attacker-controlled value such as
``%2559...`` must not become a marker only after a second decoding pass.
"""

from __future__ import annotations

import argparse
import base64
import os
import stat
import sys
import urllib.parse


MAX_PERCENT_DECODE_ROUNDS = 8


class ScanError(Exception):
    """A generic evidence-scan failure that never contains marker material."""


def percent_decode_fixed_point(value: bytes) -> bytes:
    current = value
    for _ in range(MAX_PERCENT_DECODE_ROUNDS):
        decoded = urllib.parse.unquote_to_bytes(current)
        if decoded == current:
            return current
        current = decoded

    if urllib.parse.unquote_to_bytes(current) != current:
        raise ScanError("percent decoding exceeded the permitted nesting depth")
    return current


def representations(marker: bytes) -> tuple[tuple[bytes, ...], tuple[bytes, ...]]:
    first_level = {
        base64.b64encode(marker),
        base64.b64encode(marker).rstrip(b"="),
        base64.urlsafe_b64encode(marker),
        base64.urlsafe_b64encode(marker).rstrip(b"="),
    }
    second_level: set[bytes] = set()
    for encoded in first_level:
        for nested in (base64.b64encode(encoded), base64.urlsafe_b64encode(encoded)):
            second_level.add(nested)
            second_level.add(nested.rstrip(b"="))
    exact = tuple({marker, *first_level, *second_level})
    case_insensitive = (marker.hex().encode("ascii"),)
    return exact, case_insensitive


def contains_marker(value: bytes, markers: list[bytes]) -> bool:
    decoded = percent_decode_fixed_point(value)
    folded = decoded.lower()
    for marker in markers:
        exact, case_insensitive = representations(marker)
        if any(candidate in decoded for candidate in exact):
            return True
        if any(candidate.lower() in folded for candidate in case_insensitive):
            return True
    return False


def self_test(markers: list[bytes]) -> None:
    probes = markers or [b"fixed-point-scanner-self-test-marker"]
    for marker in probes:
        exact, case_insensitive = representations(marker)
        for representation in (*exact, *case_insensitive):
            if not representation:
                raise ScanError("empty marker representation")
            first = f"{representation[0]:02X}".encode("ascii")
            for depth in range(1, MAX_PERCENT_DECODE_ROUNDS + 1):
                probe = b"%" + (b"25" * (depth - 1)) + first + representation[1:]
                if not contains_marker(probe, [marker]):
                    raise ScanError("fixed-point scanner self-test failed")
            over_depth = (
                b"%"
                + (b"25" * MAX_PERCENT_DECODE_ROUNDS)
                + first
                + representation[1:]
            )
            try:
                contains_marker(over_depth, [marker])
            except ScanError:
                pass
            else:
                raise ScanError("over-depth scanner self-test failed")


def scan_evidence(root: bytes, markers: list[bytes]) -> None:
    try:
        root_stat = os.stat(root, follow_symlinks=False)
    except OSError as error:
        raise ScanError("evidence root is unavailable") from error
    if not stat.S_ISDIR(root_stat.st_mode) or os.path.islink(root):
        raise ScanError("evidence root is not a safe directory")

    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        for name in (*directory_names, *file_names):
            path = os.path.join(directory, name)
            relative = os.path.relpath(path, root)
            if contains_marker(relative, markers):
                raise ScanError("retained evidence pathname disclosed an encoded marker")
            try:
                entry_stat = os.stat(path, follow_symlinks=False)
            except OSError as error:
                raise ScanError("retained evidence entry is unavailable") from error
            if stat.S_ISLNK(entry_stat.st_mode):
                raise ScanError("retained evidence contains an unsafe symbolic link")

        for name in file_names:
            path = os.path.join(directory, name)
            entry_stat = os.stat(path, follow_symlinks=False)
            if not stat.S_ISREG(entry_stat.st_mode):
                raise ScanError("retained evidence contains a non-regular file")
            try:
                with open(path, "rb") as retained_file:
                    contents = retained_file.read()
            except OSError as error:
                raise ScanError("retained evidence file is unreadable") from error
            if contains_marker(contents, markers):
                raise ScanError("retained evidence disclosed an encoded marker")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("evidence_root", nargs="?")
    parser.add_argument("markers", nargs="*")
    arguments = parser.parse_args()

    markers = [os.fsencode(marker) for marker in arguments.markers]
    try:
        self_test(markers)
        if arguments.self_test and arguments.evidence_root is None:
            return 0
        if arguments.evidence_root is None or not markers:
            raise ScanError("evidence root and marker set are required")
        scan_evidence(os.fsencode(arguments.evidence_root), markers)
    except ScanError as error:
        print(f"DIFF-003 encoded marker scan failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
