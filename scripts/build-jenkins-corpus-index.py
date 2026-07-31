#!/usr/bin/env python3
"""Build deterministic joined views over the sealed Jenkins corpus evidence."""

import csv
import hashlib
import json
import pathlib
import sys

import yaml


def rows(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def keyed(values, field):
    result = {}
    for value in values:
        key = value[field]
        if key in result:
            raise ValueError(f"duplicate {field}: {key}")
        result[key] = value
    return result


def jsonl(path):
    with path.open() as stream:
        return [json.loads(line) for line in stream if line.strip()]


def write_tsv(path, fields, values):
    if path.exists():
        raise FileExistsError(f"refusing to replace {path}")
    with path.open("x", newline="") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=fields, delimiter="\t", lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(values)


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: build-jenkins-corpus-index.py CORPUS_ROOT INVENTORY_ROOT")
    root = pathlib.Path(sys.argv[1]).resolve()
    inventory_root = pathlib.Path(sys.argv[2]).resolve()

    provenance = keyed(rows(root / "source-provenance.tsv"), "file")
    redactions = rows(root / "typed-redactions.tsv")
    redacted_files = {row["file"]: row for row in redactions}
    projects = keyed(rows(root / "oracle" / "projects.tsv"), "file")
    lint = keyed(jsonl(root / "oracle" / "jenkins-lint-results.jsonl"), "file")
    jobs = keyed(jsonl(root / "oracle" / "jenkins-job-results.jsonl"), "file")
    inventory = yaml.safe_load((inventory_root / "job-graph.yaml").read_text())

    job_map = []
    by_file = {}
    for job in inventory["jobs"]:
        filename = job["canonical_source"].rsplit("/", 1)[-1]
        record = {
            "file": filename,
            "job_id": job["id"],
            "inventory_inline_sha256": job["source_sha256"],
            "config_sha256": job["config_sha256"],
            "enabled": str(bool(job["operational_state"]["enabled"])).lower(),
            "state_generation": job["operational_state"]["generation"],
            "state_reason": job["operational_state"]["reason"],
            "node_authority": job["node_authority"],
        }
        job_map.append(record)
        by_file.setdefault(filename, []).append(record)

    normalizations = []
    jenkins_source = {}
    for filename, source in sorted(provenance.items()):
        mappings = by_file.get(filename, [])
        if not mappings:
            raise ValueError(f"source has no inventory job mapping: {filename}")
        inventory_hashes = {
            mapping["inventory_inline_sha256"] for mapping in mappings
        }
        if len(inventory_hashes) != 1:
            raise ValueError(f"inconsistent Jenkins source hashes: {filename}")
        inventory_hash = inventory_hashes.pop()
        if inventory_hash == source["source_sha256"]:
            jenkins_source[filename] = (inventory_hash, "none")
            continue
        if filename in redacted_files:
            raise ValueError(f"redacted source also requires normalization: {filename}")
        original = (root / "sources" / filename).read_bytes()
        if sha256(original) != source["source_sha256"]:
            raise ValueError(f"normalization source substitution: {filename}")
        normalized = original.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        if normalized == original or sha256(normalized) != inventory_hash:
            raise ValueError(f"unexplained Jenkins source normalization: {filename}")
        normalizations.append(
            {
                "file": filename,
                "transform": "xml-1.0-crlf-to-lf",
                "original_source_sha256": source["source_sha256"],
                "jenkins_source_sha256": inventory_hash,
                "original_bytes": str(len(original)),
                "jenkins_bytes": str(len(normalized)),
            }
        )
        jenkins_source[filename] = (inventory_hash, "xml-1.0-crlf-to-lf")

    index = []
    for filename in sorted(provenance):
        source = provenance[filename]
        project = projects[filename]
        lint_result = lint[filename]
        job_result = jobs[filename]
        mappings = by_file.get(filename, [])
        if not mappings:
            raise ValueError(f"source has no inventory job mapping: {filename}")
        index.append(
            {
                "file": filename,
                "repo": source["repo"],
                "source_sha256": source["source_sha256"],
                "repository_source_sha256": (
                    redacted_files.get(filename, {}).get("repository_source_sha256")
                    or source["source_sha256"]
                ),
                "jenkins_source_sha256": jenkins_source[filename][0],
                "jenkins_source_normalization": jenkins_source[filename][1],
                "redacted": str(filename in redacted_files).lower(),
                "bytes": source["bytes"],
                "commit_sha1": source["commit_sha1"],
                "license_spdx": source["license_spdx"],
                "license_disposition": (
                    "evidence-only-noassertion"
                    if source["license_spdx"] == "NOASSERTION"
                    else "declared-license"
                ),
                "inventory_job_count": str(len(mappings)),
                "all_jobs_disabled": str(
                    all(mapping["enabled"] == "false" for mapping in mappings)
                ).lower(),
                "jenkins_lint": lint_result["verdict"],
                "jenkins_job": project["jenkins_job"],
                "jenkins_compiled": project["jenkins_compiled"].lower(),
                "jenkins_reached_agent": project["jenkins_reached_agent"].lower(),
                "jenkins_console_sha256": job_result["console_sha256"],
                "linux_case": "denied-no-execution-authority",
                "windows_case": "denied-no-execution-authority",
                "migration_class": "unsupported",
                "worker_v1": "E_COMPILER_SUBSET_NOT_IMPLEMENTED",
                "certified_equivalence": "false",
            }
        )

    job_map.sort(key=lambda item: (item["file"], item["job_id"]))
    write_tsv(
        root / "jenkins-source-normalization.tsv",
        [
            "file",
            "transform",
            "original_source_sha256",
            "jenkins_source_sha256",
            "original_bytes",
            "jenkins_bytes",
        ],
        normalizations,
    )
    write_tsv(
        root / "source-job-map.tsv",
        [
            "file",
            "job_id",
            "inventory_inline_sha256",
            "config_sha256",
            "enabled",
            "state_generation",
            "state_reason",
            "node_authority",
        ],
        job_map,
    )
    write_tsv(
        root / "corpus-index.tsv",
        [
            "file",
            "repo",
            "source_sha256",
            "repository_source_sha256",
            "jenkins_source_sha256",
            "jenkins_source_normalization",
            "redacted",
            "bytes",
            "commit_sha1",
            "license_spdx",
            "license_disposition",
            "inventory_job_count",
            "all_jobs_disabled",
            "jenkins_lint",
            "jenkins_job",
            "jenkins_compiled",
            "jenkins_reached_agent",
            "jenkins_console_sha256",
            "linux_case",
            "windows_case",
            "migration_class",
            "worker_v1",
            "certified_equivalence",
        ],
        index,
    )
    print(f"corpus-index-ok sources={len(index)} jobs={len(job_map)}")


if __name__ == "__main__":
    main()
