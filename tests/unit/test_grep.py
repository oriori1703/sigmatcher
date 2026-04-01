import subprocess
from pathlib import Path

from _pytest.monkeypatch import MonkeyPatch

import sigmatcher.grep

PARSED_COUNT = 12


def test_parse_rg_line() -> None:
    path, count = sigmatcher.grep.parse_rg_line("/tmp/test.smali:12")
    assert path == Path("/tmp/test.smali")
    assert count == PARSED_COUNT


def test_rip_regex_single_file_output_without_filename(monkeypatch: MonkeyPatch) -> None:
    search_file = Path("/tmp/sample.smali")

    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="3")

    def fake_is_file(path: Path) -> bool:
        return path == search_file

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(Path, "is_file", fake_is_file)

    result = sigmatcher.grep.rip_regex("needle", [search_file])
    assert result == {search_file: 3}


def test_rip_regex_returns_empty_on_nonzero_exit(monkeypatch: MonkeyPatch) -> None:
    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = sigmatcher.grep.rip_regex("needle", [Path("/tmp")])
    assert result == {}
