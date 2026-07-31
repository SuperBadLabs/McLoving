#!/usr/bin/env python3
"""Seal and independently verify the immutable Jenkins corpus bundle."""

import collections
import csv
import hashlib
import json
import pathlib
import re
import sys


EXPECTED_PROFILE = "feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271"
EXPECTED_INVENTORY = "b1c2f81c74ec0ffc36971f358f920b2d0775c6009f474bea924448cd2a1915c1"
EXPECTED_PLUGIN_MANIFEST = "e33fa87646e6e360e7614373cc0057ba2e92ff18b9a9ea9419dea796dcb950b0"
EXPECTED_ORACLE = {
    "declarative_invalid": 14,
    "declarative_valid": 80,
    "not_declarative_pipeline": 134,
}
EXPECTED_JOB = {
    "compile_or_model_failure": 29,
    "compiled_waiting_for_agent": 119,
    "declarative_agent_value_failure": 1,
    "missing_binding_or_library": 4,
    "missing_cloud_configuration": 4,
    "missing_shared_library": 1,
    "missing_step_or_plugin": 67,
    "offline_scm_dependency": 1,
    "other_runtime_failure": 2,
}


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            value.update(chunk)
    return value.hexdigest()


def digest_bytes(value):
    return hashlib.sha256(value).hexdigest()


def tsv(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def jsonl(path):
    with path.open() as stream:
        return [json.loads(line) for line in stream if line.strip()]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def source_manifest(root):
    entries = {}
    pattern = re.compile(r"^([0-9a-f]{64})  (sources/[A-Za-z0-9_.+-]+\.Jenkinsfile)$")
    for line in (root / "SOURCE_SHA256SUMS").read_text().splitlines():
        match = pattern.fullmatch(line)
        require(match is not None, f"invalid source manifest line: {line}")
        entries[match.group(2).rsplit("/", 1)[-1]] = match.group(1)
    return entries


def bundle_files(root):
    result = []
    for path in root.rglob("*"):
        require(not path.is_symlink(), f"symbolic link forbidden: {path}")
        if path.is_file() and path.name != "SHA256SUMS":
            result.append(path)
    return sorted(result, key=lambda path: path.relative_to(root).as_posix())


def seal(root):
    target = root / "SHA256SUMS"
    require(not target.exists(), "refusing to replace corpus SHA256SUMS")
    lines = [
        f"{digest(path)}  {path.relative_to(root).as_posix()}\n"
        for path in bundle_files(root)
    ]
    target.write_text("".join(lines))
    print(f"corpus-sealed files={len(lines)} manifest-sha256={digest(target)}")


def verify_manifest(root):
    target = root / "SHA256SUMS"
    require(target.is_file() and not target.is_symlink(), "missing corpus SHA256SUMS")
    expected = {}
    pattern = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9_./+-]+)$")
    for line in target.read_text().splitlines():
        match = pattern.fullmatch(line)
        require(match is not None, f"invalid bundle manifest line: {line}")
        expected[match.group(2)] = match.group(1)
    actual_files = bundle_files(root)
    actual_names = {path.relative_to(root).as_posix() for path in actual_files}
    require(set(expected) == actual_names, "bundle manifest file set mismatch")
    for path in actual_files:
        relative = path.relative_to(root).as_posix()
        require(digest(path) == expected[relative], f"bundle digest mismatch: {relative}")


def verify(root):
    verify_manifest(root)
    source_hashes = source_manifest(root)
    source_files = sorted((root / "sources").glob("*.Jenkinsfile"))
    require(len(source_files) == 228, "expected 228 source files")
    require(set(source_hashes) == {path.name for path in source_files}, "source set mismatch")
    for source in source_files:
        require(digest(source) == source_hashes[source.name], f"source digest mismatch: {source.name}")

    provenance = tsv(root / "source-provenance.tsv")
    require(len(provenance) == 228, "expected 228 provenance rows")
    require(len({row["file"] for row in provenance}) == 228, "duplicate provenance file")
    require(len({row["repo"] for row in provenance}) == 228, "duplicate provenance repository")
    for row in provenance:
        require(row["file"] in source_hashes, "unknown provenance source")
        require(row["provenance_status"] == "exact-commit", "unresolved source revision")
        require(re.fullmatch(r"[0-9a-f]{40}", row["commit_sha1"]) is not None, "invalid commit")
        require(re.fullmatch(r"[0-9a-f]{40}", row["blob_sha1"]) is not None, "invalid blob")
        require(bool(row["license_spdx"]), "missing license disposition")

    redactions = tsv(root / "typed-redactions.tsv")
    require(len(redactions) == 6, "expected six typed redaction receipts")
    require(len({(row["file"], row["field"]) for row in redactions}) == 6, "duplicate redaction")
    redacted_by_file = {}
    for row in redactions:
        require(row["file"] in source_hashes, "unknown redacted source")
        require(row["typed_reference"].startswith("secret://jenkins/"), "untyped redaction")
        require(re.fullmatch(r"[0-9a-f]{64}", row["protected_hmac_sha256"]) is not None, "invalid protected digest")
        require(row["repository_source_sha256"] == source_hashes[row["file"]], "redacted source substitution")
        redacted_by_file.setdefault(row["file"], []).append(row)
    require(set(redacted_by_file) == {
        "maxyermayank_jenkins-pipeline-demo-api.Jenkinsfile",
        "maxyermayank_jenkins-pipeline-demo-pwa.Jenkinsfile",
    }, "unexpected redacted source set")
    provenance_by_file = {row["file"]: row for row in provenance}
    for filename in source_hashes:
        original = provenance_by_file[filename]["source_sha256"]
        if filename in redacted_by_file:
            require(all(row["original_source_sha256"] == original for row in redacted_by_file[filename]), "redaction origin mismatch")
            require(original != source_hashes[filename], "redaction did not change source")
        else:
            require(original == source_hashes[filename], "unrecorded source redaction")

    index = tsv(root / "corpus-index.tsv")
    job_map = tsv(root / "source-job-map.tsv")
    normalizations = tsv(root / "jenkins-source-normalization.tsv")
    require(len(index) == 228, "expected 228 corpus index rows")
    require(len(job_map) == 230, "expected 230 source/job mappings")
    require(len(normalizations) == 4, "expected four XML line-ending normalizations")
    require(
        len({row["file"] for row in normalizations}) == 4,
        "duplicate source normalization",
    )
    normalized_by_file = {row["file"]: row for row in normalizations}
    for filename, row in normalized_by_file.items():
        require(filename in source_hashes, "unknown normalized source")
        require(
            row["transform"] == "xml-1.0-crlf-to-lf",
            "unknown source normalization",
        )
        require(
            row["original_source_sha256"] == provenance_by_file[filename]["source_sha256"],
            "normalization origin mismatch",
        )
        require(filename not in redacted_by_file, "redacted normalization is ambiguous")
        original = (root / "sources" / filename).read_bytes()
        normalized = original.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        require(normalized != original, "normalization made no change")
        require(
            digest_bytes(normalized) == row["jenkins_source_sha256"],
            "normalization digest mismatch",
        )
        require(
            str(len(original)) == row["original_bytes"]
            and str(len(normalized)) == row["jenkins_bytes"],
            "normalization byte count mismatch",
        )
    require({row["file"] for row in index} == set(source_hashes), "index source set mismatch")
    require({row["file"] for row in job_map} == set(source_hashes), "job-map source set mismatch")
    require(all(row["enabled"] == "false" for row in job_map), "enabled source job is forbidden")
    require(all(row["all_jobs_disabled"] == "true" for row in index), "index disabled state mismatch")
    admitted = [row for row in index if row["migration_class"] != "unsupported"]
    require(len(admitted) == 1, "expected exactly one compile-only admitted case")
    require(
        admitted[0]["file"] == "cinqict_jenkinsdev.Jenkinsfile"
        and admitted[0]["migration_class"] == "admitted-compile-only"
        and admitted[0]["worker_v1"] == "compiled-disabled-import",
        "unexpected compile-only admitted case",
    )
    require(
        all(
            row["worker_v1"] == "E_COMPILER_SUBSET_NOT_IMPLEMENTED"
            for row in index
            if row["migration_class"] == "unsupported"
        ),
        "unsupported compiler disposition drift",
    )
    require(all(row["certified_equivalence"] == "false" for row in index), "premature equivalence claim")
    require(all(row["linux_case"] == "denied-no-execution-authority" for row in index), "Linux authority leak")
    require(all(row["windows_case"] == "denied-no-execution-authority" for row in index), "Windows authority leak")
    require(all(row["repository_source_sha256"] == source_hashes[row["file"]] for row in index), "index repository digest mismatch")
    require(sum(row["redacted"] == "true" for row in index) == 2, "index redaction count mismatch")
    index_by_file = {row["file"]: row for row in index}
    require(
        sum(row["jenkins_source_normalization"] != "none" for row in index) == 4,
        "index normalization count mismatch",
    )
    for mapping in job_map:
        filename = mapping["file"]
        expected = (
            normalized_by_file[filename]["jenkins_source_sha256"]
            if filename in normalized_by_file
            else provenance_by_file[filename]["source_sha256"]
        )
        require(
            mapping["inventory_inline_sha256"] == expected,
            "unexplained inventory source digest",
        )
        require(
            index_by_file[filename]["jenkins_source_sha256"] == expected,
            "index Jenkins source digest mismatch",
        )
        require(
            index_by_file[filename]["jenkins_source_normalization"]
            == ("xml-1.0-crlf-to-lf" if filename in normalized_by_file else "none"),
            "index Jenkins source normalization mismatch",
        )

    lint_rows = jsonl(root / "oracle" / "jenkins-lint-results.jsonl")
    job_rows = jsonl(root / "oracle" / "jenkins-job-results.jsonl")
    require(len(lint_rows) == 228 and len(job_rows) == 228, "oracle row count mismatch")
    for oracle_rows in (lint_rows, job_rows):
        require(len({row["file"] for row in oracle_rows}) == 228, "duplicate oracle source")
        for row in oracle_rows:
            require(row["file"] in source_hashes, "unknown oracle source")
            require(
                row["sha256"] == provenance_by_file[row["file"]]["source_sha256"],
                "oracle original-source substitution",
            )

    require(
        collections.Counter(row["verdict"] for row in lint_rows) == EXPECTED_ORACLE,
        "Jenkins lint count drift",
    )
    require(
        collections.Counter(row["jenkins_job"] for row in index) == EXPECTED_JOB,
        "Jenkins job count drift",
    )
    require(sum(row["jenkins_compiled"] == "true" for row in index) == 199, "compile count drift")
    require(sum(row["jenkins_reached_agent"] == "true" for row in index) == 119, "agent count drift")

    compiler_root = root / "compiler-v1"
    require(
        digest(compiler_root / "worker-response.edn")
        == "2eec55ccd153f7692b1cfd1b2d606a1a45af434a154bebdd62f9ab0bd89aef52",
        "compiler response drift",
    )
    require(
        "state=disabled" in (compiler_root / "rust-admission.receipt").read_text(),
        "disabled Rust admission receipt missing",
    )
    require(
        "effect_authority: false" in (compiler_root / "expected-trace.yaml").read_text(),
        "compiler evidence grants effect authority",
    )

    require(EXPECTED_PROFILE in (root / "SCENARIO_CONTRACT.yaml").read_text(), "profile binding missing")
    require(EXPECTED_INVENTORY in (root / "SCENARIO_CONTRACT.yaml").read_text(), "inventory binding missing")
    require(EXPECTED_PLUGIN_MANIFEST in (root / "SCENARIO_CONTRACT.yaml").read_text(), "plugin binding missing")
    markers = [b"MCLOVING-CORPUS-SECRET-MARKER-A7E4", b"MCLOVING-CORPUS-SECRET-MARKER-D19C"]
    for path in bundle_files(root):
        if path.name == "SCENARIO_CONTRACT.yaml":
            continue
        content = path.read_bytes()
        require(not any(marker in content for marker in markers), f"secret marker escaped: {path}")

    print(
        "corpus-ok "
        f"sources={len(index)} jobs={len(job_map)} "
        "lint-valid=80 compiled=199 reached-agent=119 "
        f"manifest-sha256={digest(root / 'SHA256SUMS')}"
    )


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in {"seal", "verify"}:
        raise SystemExit("usage: verify-jenkins-corpus.py seal|verify CORPUS_ROOT")
    root = pathlib.Path(sys.argv[2]).resolve()
    if sys.argv[1] == "seal":
        seal(root)
    else:
        verify(root)


if __name__ == "__main__":
    main()
