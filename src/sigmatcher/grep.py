import re
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Union


def parse_rg_line(line: str) -> Tuple[Path, int]:
    path, _, count = line.rpartition(":")
    return Path(path), int(count)


def rip_regex(pattern: "Union[str, re.Pattern[str]]", search_paths: List[Path]) -> Dict[Path, int]:
    if isinstance(pattern, re.Pattern):
        pattern = pattern.pattern
    args = [
        "rg",
        "--count-matches",
        "--multiline",
        "--no-ignore",
        "--hidden",
        "--regexp",
        pattern,
        *[str(path) for path in search_paths],
    ]
    process = subprocess.run(args, stdout=subprocess.PIPE, text=True)

    if bool(process.returncode):
        return {}

    if len(search_paths) == 1 and search_paths[0].is_file():
        # if the search path is a single file, ripgrep will not print the filename
        return {search_paths[0]: int(process.stdout)}

    return dict(parse_rg_line(line) for line in process.stdout.splitlines())
