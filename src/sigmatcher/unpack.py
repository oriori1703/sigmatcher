import shutil
import subprocess
import sys
from pathlib import Path

import yaml
from packaging import version

from sigmatcher.cache import Cache


def get_apktool_version(apktool: str) -> str:
    # APKTool in non-interactive mode will run the `pause` command after execution on Windows
    proc = subprocess.run([apktool, "--version"], check=True, capture_output=True, input=b"\n")
    # Take only the first line, since the `pause` command prints output as well
    return proc.stdout.decode().splitlines()[0]


def unpack_apk(apktool: str, apk: Path, cache: Cache, suppress_output: bool) -> None:
    unpacked_path = cache.get_apktool_cache_dir()
    if unpacked_path.exists():
        return

    if version.parse(get_apktool_version(apktool)) >= version.parse("2.12.0"):
        only_manifest_flags = ["--only-manifest"]
    else:
        only_manifest_flags = ["--no-res", "--force-manifest"]

    # APKTool in non-interactive mode will run the `pause` command on Windows, so send a newline as input
    _ = subprocess.run(
        [
            apktool,
            "decode",
            apk,
            *only_manifest_flags,
            "--no-assets",
            "-f",
            "--output",
            unpacked_path.with_suffix(".tmp"),
        ],
        check=True,
        stdout=sys.stderr if not suppress_output else subprocess.DEVNULL,
        input=b"\n",
    )
    _ = shutil.move(unpacked_path.with_suffix(".tmp"), unpacked_path)


def get_apk_version(unpacked_path: Path) -> str | None:
    apktool_yaml_file = unpacked_path / "apktool.yml"
    with apktool_yaml_file.open() as f:
        apk_version = yaml.safe_load(f)["versionInfo"]["versionName"]  # pyright: ignore[reportAny]

    if isinstance(apk_version, float | int):
        apk_version = str(apk_version)
    assert isinstance(apk_version, str) or apk_version is None
    return apk_version
