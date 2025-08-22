import re
import subprocess
from collections.abc import Iterable
from pathlib import Path


def parse_rg_line(line: str) -> tuple[Path, int]:
    path, _, count = line.rpartition(":")
    return Path(path), int(count)


def rip_regex(pattern: str | re.Pattern[str], search_paths: Iterable[Path]) -> dict[Path, int]:
    if isinstance(pattern, re.Pattern):
        pattern = pattern.pattern
    str_search_paths = [str(path) for path in search_paths]
    args = [
        "rg",
        "--count-matches",
        "--multiline",
        "--no-ignore",
        "--hidden",
        "--regexp",
        pattern,
        *str_search_paths,
    ]
    process = subprocess.run(args, stdout=subprocess.PIPE, text=True, check=False)

    if bool(process.returncode):
        return {}

    if len(str_search_paths) == 1 and (path := next(iter(search_paths))).is_file():
        # if the search path is a single file, ripgrep will not print the filename
        return {path: int(process.stdout)}

    return dict(parse_rg_line(line) for line in process.stdout.splitlines())
