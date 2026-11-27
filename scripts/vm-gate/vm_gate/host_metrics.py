"""Read guest-visible CPU identity and raw Linux contention counters."""

import json
import os
import sys
import time
from pathlib import Path

CPU_FIELDS = (
    "user",
    "nice",
    "system",
    "idle",
    "iowait",
    "irq",
    "softirq",
    "steal",
    "guest",
    "guest_nice",
)
MODEL_FIELDS = {
    "vendor_id",
    "model name",
    "cpu family",
    "model",
    "stepping",
    "CPU implementer",
    "CPU architecture",
    "CPU part",
    "Hardware",
}


def capture(proc=Path("/proc")):
    result = {
        "time": time.time(),
        "monotonic": time.monotonic(),
        "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
        "errors": {},
    }

    def read(name):
        try:
            text = (proc / name).read_text()
            if not text.strip():
                result["errors"][name] = {"type": "EmptyRead"}
                return None
            return text
        except OSError as error:
            result["errors"][name] = {
                "type": type(error).__name__,
                "errno": error.errno,
            }
            return None

    info = read("cpuinfo")
    if info is not None:
        models = []
        for block in info.strip().split("\n\n"):
            model = {
                key.strip(): value.strip()
                for line in block.splitlines()
                if ":" in line
                for key, value in [line.split(":", 1)]
                if key.strip() in MODEL_FIELDS
            }
            if model and model not in models:
                models.append(model)
        result["cpu_models"] = models
        if not models:
            result["errors"]["cpuinfo"] = {"type": "ModelUnavailable"}
    stat = read("stat")
    if stat is not None:
        result["proc_stat"] = stat
        try:
            aggregate = next(
                line.split()[1:]
                for line in stat.splitlines()
                if line.startswith("cpu ")
            )
            if len(aggregate) < 8:
                raise ValueError("aggregate lacks steal/iowait fields")
            result["cpu_ticks"] = dict(
                zip(CPU_FIELDS, map(int, aggregate), strict=False)
            )
        except (StopIteration, ValueError) as error:
            result["errors"]["stat"] = {"type": type(error).__name__}
    result["pressure"] = {name: read("pressure/" + name) for name in ("cpu", "io")}
    # Preserve raw before/after values: iowait can decrease, and guest time is
    # already included in user/nice. No guessed utilization or diagnosis here.
    result["status"] = "partial" if result["errors"] else "complete"
    return result


if __name__ == "__main__":
    Path(sys.argv[1]).write_text(json.dumps(capture(), indent=2) + "\n")
