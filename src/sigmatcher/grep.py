import re
import subprocess
from pathlib import Path
from typing import Dict, Tuple, Union


def parse_rg_line(line: str) -> Tuple[Path, int]:
    path, _, count = line.rpartition(":")
    return Path(path), int(count)


def rip_regex(pattern: "Union[str, re.Pattern[str]]", unpacked_path: Path) -> Dict[Path, int]:
    if isinstance(pattern, re.Pattern):
        pattern = pattern.pattern
    process = subprocess.run(
        ["rg", "--count-matches", "--multiline", "--no-ignore", "--hidden", "--regexp", pattern, unpacked_path],
        stdout=subprocess.PIPE,
        text=True,
    )

    if bool(process.returncode):
        return {}

    return dict(parse_rg_line(line) for line in process.stdout.splitlines())
