"""Shared runs and exclusive snapshot changes lock a stable sidecar inode."""

import fcntl
import json
from pathlib import Path
from .errors import Refused


class ConfigLease:
    def __init__(self, config, exclusive=False):
        self.config = config
        self.exclusive = exclusive
        self.handle = None

    def __enter__(self):
        path = Path(self.config["config_path"])
        self.handle = Path(str(path) + ".lock").open("a")
        try:
            fcntl.flock(
                self.handle,
                (fcntl.LOCK_EX if self.exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB,
            )
        except BlockingIOError:
            self.handle.close()
            self.handle = None
            raise Refused(
                "snapshot configuration is in use; no provider access attempted"
            ) from None
        try:
            current = json.loads(path.read_text())
            if self.config.get("host_profile") == "native-arm64-oci-v1":
                if (
                    current.get("host_profile") != self.config["host_profile"]
                    or current.get("native_profile")
                    != self.config["native_profile_path"]
                    or json.loads(Path(self.config["native_profile_path"]).read_text())
                    != self.config["native_profile"]
                ):
                    raise Refused("native profile changed during local admission")
                return self
            if any(
                current.get(k) != self.config.get(k)
                for k in ["snapshot_id", "snapshot_manifest"]
            ):
                raise Refused(
                    "snapshot configuration changed during local admission; restart with current config"
                )
            if self.config.get("snapshot_manifest"):
                actual = json.loads(Path(self.config["snapshot_manifest"]).read_text())
                if actual != self.config["manifest"]:
                    raise Refused(
                        "snapshot configuration changed: recorded manifest differs"
                    )
        except BaseException:
            self.handle.close()
            self.handle = None
            raise
        return self

    def __exit__(self, *args):
        if self.handle:
            self.handle.close()
            self.handle = None
