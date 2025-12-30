"""
Handles unpacking APK, XAPK, and APKM files to smali directories.
"""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml
from packaging import version

from sigmatcher.cache import Cache
from sigmatcher.errors import DuplicateSmaliError


@dataclass
class ApkSource:
    """Represents resolved APK file(s) ready for unpacking."""

    apk_paths: tuple[Path, ...]
    """Paths to the APK files to unpack."""

    base_apk_index: int = 0
    """Index of the base APK in apk_paths (used for metadata like version)."""

    _temp_dir: tempfile.TemporaryDirectory[str] | None = field(default=None, repr=False)
    """Temporary directory for extracted bundle contents (if any)."""

    def cleanup(self) -> None:
        """Clean up temporary files if any."""
        if self._temp_dir is not None:
            self._temp_dir.cleanup()


# --- File type detection ---


def detect_file_type(path: Path) -> Literal["apk", "xapk", "apkm"]:
    """
    Detect whether a file is APK, XAPK, or APKM based on ZIP contents.

    All three formats are ZIP files, but:
    - XAPK contains manifest.json
    - APKM contains info.json
    - APK contains AndroidManifest.xml (or is not a valid ZIP for our purposes)
    """
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
            if "manifest.json" in names:
                return "xapk"
            if "info.json" in names:
                return "apkm"
            return "apk"
    except zipfile.BadZipFile:
        # Not a valid ZIP, assume it's an APK (apktool will handle the error)
        return "apk"


# --- Bundle extraction ---


def _get_apk_paths_from_xapk(zf: zipfile.ZipFile) -> tuple[list[str], int]:
    """
    Parse manifest.json to get list of APK files in XAPK.

    Returns a tuple of (apk_paths, base_apk_index).
    """
    manifest_data = json.loads(zf.read("manifest.json"))
    split_apks: list[dict[str, str]] = manifest_data.get("split_apks", [])

    if not split_apks:
        # Fallback: look for any .apk files
        apk_files = [name for name in zf.namelist() if name.endswith(".apk")]
        return apk_files, 0

    apk_paths: list[str] = []
    base_index = 0

    for apk_info in split_apks:
        apk_file = apk_info.get("file", "")
        if apk_file:
            apk_paths.append(apk_file)
            # Check if this is the base APK
            if apk_info.get("id") == "base":
                base_index = len(apk_paths) - 1

    return apk_paths, base_index


def _get_apk_paths_from_apkm(zf: zipfile.ZipFile) -> tuple[list[str], int]:
    """
    Parse info.json or scan for APK files in APKM.

    Returns a tuple of (apk_paths, base_apk_index).
    """
    apk_paths: list[str] = []
    base_index = 0

    try:
        info_data = json.loads(zf.read("info.json"))
        apks_list: list[dict[str, str]] = info_data.get("apks", [])

        for apk_info in apks_list:
            apk_file = apk_info.get("file", "")
            if apk_file:
                apk_paths.append(apk_file)
                # Check if this is the base APK (usually named "base.apk" or first one)
                if "base" in apk_file.lower():
                    base_index = len(apk_paths) - 1
    except (KeyError, json.JSONDecodeError):
        pass

    if not apk_paths:
        # Fallback: scan for .apk files
        apk_paths = [name for name in zf.namelist() if name.endswith(".apk")]
        # Try to find base APK by name
        for i, name in enumerate(apk_paths):
            if "base" in name.lower():
                base_index = i
                break

    return apk_paths, base_index


def _extract_bundle(bundle_path: Path, bundle_type: Literal["xapk", "apkm"]) -> ApkSource:
    """
    Extract APKs from XAPK/APKM bundle to a temporary directory.

    Returns an ApkSource with paths to the extracted APK files.
    """
    temp_dir = tempfile.TemporaryDirectory(prefix="sigmatcher_bundle_")
    temp_path = Path(temp_dir.name)

    try:
        with zipfile.ZipFile(bundle_path, "r") as zf:
            if bundle_type == "xapk":
                apk_names, base_index = _get_apk_paths_from_xapk(zf)
            else:
                apk_names, base_index = _get_apk_paths_from_apkm(zf)

            if not apk_names:
                raise ValueError(f"No APK files found in {bundle_type.upper()} bundle: {bundle_path}")

            # Extract only the APK files
            apk_paths: list[Path] = []
            for apk_name in apk_names:
                _ = zf.extract(apk_name, temp_path)
                apk_paths.append(temp_path / apk_name)

        return ApkSource(
            apk_paths=tuple(apk_paths),
            base_apk_index=base_index,
            _temp_dir=temp_dir,
        )
    except Exception:
        temp_dir.cleanup()
        raise


# --- APK input resolution ---


def resolve_apk_inputs(apk_inputs: Sequence[Path]) -> ApkSource:
    """
    Resolve APK inputs to actual APK file paths.

    - Single APK: return as-is
    - Single XAPK/APKM: extract to temp dir, return contained APKs
    - Multiple files: return all as-is (assumes all are APKs)
    """
    if len(apk_inputs) == 0:
        raise ValueError("At least one APK input is required")

    if len(apk_inputs) == 1:
        input_path = apk_inputs[0]
        file_type = detect_file_type(input_path)

        if file_type == "xapk" or file_type == "apkm":  # noqa: PLR1714
            return _extract_bundle(input_path, file_type)
        return ApkSource(apk_paths=(input_path,), base_apk_index=0)

    # Multiple inputs - assume all are APKs, first one is base
    # Try to find base APK by name if possible
    base_index = 0
    for i, path in enumerate(apk_inputs):
        if "base" in path.name.lower():
            base_index = i
            break

    return ApkSource(apk_paths=tuple(apk_inputs), base_apk_index=base_index)


# --- Apktool operations ---


def get_apktool_version(apktool: str) -> str:
    """Get the version string from apktool."""
    # APKTool in non-interactive mode will run the `pause` command after execution on Windows
    proc = subprocess.run([apktool, "--version"], check=True, capture_output=True, input=b"\n")
    # Take only the first line, since the `pause` command prints output as well
    return proc.stdout.decode().splitlines()[0]


def _unpack_single_apk(apktool: str, apk: Path, output_dir: Path, suppress_output: bool) -> None:
    """
    Unpack a single APK using apktool.

    The output_dir should not exist; this function will create it.
    """
    if version.parse(get_apktool_version(apktool)) >= version.parse("2.12.0"):
        only_manifest_flags = ["--only-manifest"]
    else:
        only_manifest_flags = ["--no-res", "--force-manifest"]

    # APKTool in non-interactive mode will run the `pause` command on Windows, so send a newline as input
    _ = subprocess.run(
        [
            apktool,
            "decode",
            str(apk),
            *only_manifest_flags,
            "--no-assets",
            "-f",
            "--output",
            str(output_dir),
        ],
        check=True,
        stdout=sys.stderr if not suppress_output else subprocess.DEVNULL,
        input=b"\n",
    )


# --- Merging ---


def _hash_file(path: Path) -> str:
    """Compute SHA256 hash of a file's contents."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _merge_unpacked_apks(source_dirs: list[Path], target_dir: Path, base_index: int = 0) -> None:
    """
    Merge multiple unpacked APK directories into target.

    - Smali files: error if same file has different content, otherwise keep one copy
    - Other files (AndroidManifest.xml, apktool.yml, etc.): keep from base APK

    Args:
        source_dirs: List of unpacked APK directories to merge
        target_dir: Target directory for merged output
        base_index: Index of the base APK directory (used for metadata files)
    """
    target_dir.mkdir(parents=True, exist_ok=True)

    # Track files we've seen: relative_path -> (hash, source_dir)
    seen_files: dict[str, tuple[str, Path]] = {}

    # Process base APK first to ensure its metadata files take precedence
    ordered_dirs = [source_dirs[base_index]] + [d for i, d in enumerate(source_dirs) if i != base_index]

    for source_dir in ordered_dirs:
        for source_file in source_dir.rglob("*"):
            if source_file.is_dir():
                continue

            relative_path = source_file.relative_to(source_dir)
            target_file = target_dir / relative_path

            # Check if we've seen this file before
            relative_path_str = str(relative_path)

            if relative_path_str in seen_files:
                # File already exists - check for conflicts
                if relative_path.suffix == ".smali":
                    # For smali files, check content hash
                    new_hash = _hash_file(source_file)
                    existing_hash, existing_source = seen_files[relative_path_str]

                    if new_hash != existing_hash:
                        raise DuplicateSmaliError(relative_path_str, existing_source, source_dir)
                    # Same content, skip
                # For non-smali files, keep the first one (from base APK)
                continue

            # New file - copy it
            target_file.parent.mkdir(parents=True, exist_ok=True)
            _ = shutil.copy2(source_file, target_file)

            # Track this file
            file_hash = _hash_file(source_file) if relative_path.suffix == ".smali" else ""
            seen_files[relative_path_str] = (file_hash, source_dir)


# --- Main entry points ---


def unpack_apks(apktool: str, apk_source: ApkSource, cache: Cache, suppress_output: bool) -> None:
    """
    Unpack APK(s) to the cache directory.

    Handles single APK, multiple APKs, and merging split APKs.
    Skips unpacking if already cached.
    """
    final_unpacked_path = cache.get_apktool_cache_dir()

    if final_unpacked_path.exists():
        # Already cached
        return

    if len(apk_source.apk_paths) == 1:
        # Single APK - simple case
        temp_output = final_unpacked_path.with_suffix(".tmp")
        try:
            _unpack_single_apk(apktool, apk_source.apk_paths[0], temp_output, suppress_output)
            _ = shutil.move(temp_output, final_unpacked_path)
        except Exception:
            if temp_output.exists():
                shutil.rmtree(temp_output)
            raise
        return

    # Multiple APKs - unpack each to temp directory, then merge
    with tempfile.TemporaryDirectory(prefix="sigmatcher_unpack_") as temp_dir:
        temp_path = Path(temp_dir)
        unpacked_dirs: list[Path] = []

        for i, apk in enumerate(apk_source.apk_paths):
            apk_output_dir = temp_path / f"apk_{i}"
            _unpack_single_apk(apktool, apk, apk_output_dir, suppress_output)
            unpacked_dirs.append(apk_output_dir)

        # Merge all unpacked directories
        temp_merged = final_unpacked_path.with_suffix(".tmp")
        try:
            _merge_unpacked_apks(unpacked_dirs, temp_merged, apk_source.base_apk_index)
            _ = shutil.move(temp_merged, final_unpacked_path)
        except Exception:
            if temp_merged.exists():
                shutil.rmtree(temp_merged)
            raise


def get_apk_version(unpacked_path: Path) -> str | None:
    """Extract version from unpacked APK's apktool.yml."""
    apktool_yaml_file = unpacked_path / "apktool.yml"
    with apktool_yaml_file.open() as f:
        apk_version = yaml.safe_load(f)["versionInfo"]["versionName"]  # pyright: ignore[reportAny]

    if isinstance(apk_version, float | int):
        apk_version = str(apk_version)
    assert isinstance(apk_version, str) or apk_version is None
    return apk_version
