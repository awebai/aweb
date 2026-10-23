import sys
from pathlib import Path

import pytest

from aweb_secrets_runner.errors import Refused
from aweb_secrets_runner.oci_platform import require_memory_directory


@pytest.mark.skipif(
    sys.platform == "linux", reason="Linux storage covered by explicit runtime proof"
)
def test_unsupported_platform_never_treats_a_directory_as_memory_backed(tmp_path: Path):
    with pytest.raises(Refused, match="runner_runtime_unavailable"):
        require_memory_directory(tmp_path)
