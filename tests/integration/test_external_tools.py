import shutil
from pathlib import Path

import pytest

from sigmatcher.cli import _get_apktool_version  # pyright: ignore[reportPrivateUsage]
from sigmatcher.grep import rip_regex

EXPECTED_HELLO_COUNT = 2


@pytest.mark.integration
@pytest.mark.external
def test_ripgrep_is_available_and_counts_matches(tmp_path: Path) -> None:
    if shutil.which("rg") is None:
        pytest.skip("rg is not installed")

    smali = tmp_path / "Sample.smali"
    _ = smali.write_text('const-string v0, "hello"\nconst-string v1, "hello"\n')
    counts = rip_regex(r'const-string v\d+, "hello"', [smali])
    assert counts[smali] == EXPECTED_HELLO_COUNT


@pytest.mark.integration
@pytest.mark.external
def test_apktool_version_command_runs_when_available() -> None:
    if shutil.which("apktool") is None:
        pytest.skip("apktool is not installed")

    version = _get_apktool_version("apktool")
    assert version
