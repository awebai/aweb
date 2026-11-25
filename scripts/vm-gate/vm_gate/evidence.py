"""Retain every run directory, but attribute stage verdicts only to the SHA."""

import json
import re
import tarfile
from pathlib import Path, PurePosixPath

from .errors import Infrastructure
from .memory import load_samples, summarize_samples


def collect_archive(archive, sha, destination):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    stages = []
    targets = []
    summaries = []
    budget = None
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
            gate_run = (
                len(rel.parts) == 3
                and rel.parts[0] == "tmp"
                and (
                    rel.parts[1] == "aweb-candidate-gate-" + sha
                    or rel.parts[1].startswith("aweb-candidate-gate-" + sha + "-")
                )
            )
            if gate_run and rel.parts[2] == "budget.tsv":
                budget = {}
                for line in target.read_text().splitlines():
                    name, _, value = line.partition("\t")
                    budget[name] = int(value) if value.isdigit() else value
            if gate_run and rel.parts[2] == "summary.tsv":
                summaries.append(item.name)
                for line in target.read_text().splitlines():
                    fields = line.split("\t")
                    if len(fields) < 4:
                        raise Infrastructure("incomplete gate summary row")
                    try:
                        seconds = float(fields[3].removesuffix("s"))
                    except ValueError:
                        raise Infrastructure("invalid gate stage duration") from None
                    stage, _, target = fields[0].partition("/")
                    row = {
                        "stage": stage,
                        "status": fields[1],
                        "seconds": seconds,
                        "summary": item.name,
                    }
                    if target:
                        targets.append(
                            {
                                **row,
                                "target": target,
                                "log": fields[2],
                                "detail": fields[4] if len(fields) > 4 else "",
                            }
                        )
                    else:
                        stages.append(row)
    output = destination / "var/log/vm-gate/gate-output.log"
    if output.exists():
        for stage, log in re.findall(
            r"^gate: tree [0-9a-f]{40} already passed ([a-z-]+); original log (.+)$",
            output.read_text(errors="replace"),
            re.MULTILINE,
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
        samples = load_samples(memory_path)
        memory = summarize_samples(samples)
    supervision_path = destination / "var/log/vm-gate/supervisor-receipt.json"
    supervision = (
        json.loads(supervision_path.read_text()) if supervision_path.exists() else None
    )
    return {
        "supervision": supervision,
        "budget": budget,
        "stages": stages,
        "targets": targets,
        "gate_summaries": summaries,
        "memory": memory,
        "archive_links_omitted": links,
    }
