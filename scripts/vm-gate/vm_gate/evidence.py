"""Retain every run directory, but attribute stage verdicts only to the SHA."""

import json
import re
from pathlib import Path, PurePosixPath
import tarfile
from .errors import Infrastructure


def collect_archive(archive, sha, destination):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    stages = []
    summaries = []
    links = []
    with tarfile.open(archive) as t:
        for item in t:
            rel = PurePosixPath(item.name)
            target = destination.joinpath(*rel.parts)
            if (
                rel.is_absolute()
                or ".." in rel.parts
                or not target.resolve().is_relative_to(destination)
            ):
                raise Infrastructure("unsafe archive path; raw archive retained")
            if item.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            if not item.isfile():
                links.append(item.name)
                continue
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            source = t.extractfile(item)
            with target.open("wb") as output:
                while chunk := source.read(1024 * 1024):
                    output.write(chunk)
            if (
                len(rel.parts) == 3
                and rel.parts[0] == "tmp"
                and rel.parts[2] == "summary.tsv"
                and (
                    rel.parts[1] == "aweb-candidate-gate-" + sha
                    or rel.parts[1].startswith("aweb-candidate-gate-" + sha + "-")
                )
            ):
                summaries.append(item.name)
                for line in target.read_text().splitlines():
                    fields = line.split("\t")
                    if len(fields) < 4:
                        raise Infrastructure("incomplete gate summary row")
                    try:
                        seconds = float(fields[3].removesuffix("s"))
                    except ValueError:
                        raise Infrastructure("invalid gate stage duration") from None
                    stages.append(
                        {
                            "stage": fields[0],
                            "status": fields[1],
                            "seconds": seconds,
                            "summary": item.name,
                        }
                    )
    output = destination / "var/log/vm-gate/gate-output.log"
    if output.exists():
        for stage, log in re.findall(
            r"^gate: tree [0-9a-f]{40} already passed ([a-z-]+); original log (.+)$",
            output.read_text(errors="replace"),
            re.M,
        ):
            stages.append(
                {
                    "stage": stage,
                    "status": "REUSED",
                    "seconds": None,
                    "original_log": log,
                }
            )
    memory_path = destination / "var/log/vm-gate/memory.jsonl"
    memory = None
    if memory_path.exists():
        samples = [
            json.loads(line) for line in memory_path.read_text().splitlines() if line
        ]
        valid = [s for s in samples if "meminfo_kib" in s and not s.get("sample_error")]
        if valid:
            memory = {
                "samples": len(samples),
                "valid": len(valid),
                "host_sample_errors": sum("sample_error" in s for s in samples),
                "container_read_errors": sum(
                    len(s.get("container_errors", [])) for s in samples
                ),
                "host_sampled_used_peak_bytes": max(
                    (s["meminfo_kib"]["MemTotal"] - s["meminfo_kib"]["MemAvailable"])
                    * 1024
                    for s in valid
                ),
                "concurrent_cgroup_current_peak_sum_bytes": max(
                    sum(int(c["memory.current"]) for c in s.get("containers", []))
                    for s in valid
                ),
            }
    supervision_path = destination / "var/log/vm-gate/supervisor-receipt.json"
    supervision = json.loads(supervision_path.read_text()) if supervision_path.exists() else None
    return {
        "supervision": supervision,
        "stages": stages,
        "gate_summaries": summaries,
        "memory": memory,
        "archive_links_omitted": links,
    }
