import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

import yaml
from packaging import version

from sigmatcher.cache import Cache
from sigmatcher.input_paths import InputKind, get_input_kind, list_archive_apk_members, list_directory_apk_files


def get_apktool_version(apktool: str) -> str:
    # APKTool in non-interactive mode will run the `pause` command after execution on Windows
    proc = subprocess.run([apktool, "--version"], check=True, capture_output=True, input=b"\n")
    # Take only the first line, since the `pause` command prints output as well
    return proc.stdout.decode().splitlines()[0]


def _decode_apk(apktool: str, apk: Path, output: Path, suppress_output: bool) -> None:
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
            output,
        ],
        check=True,
        stdout=sys.stderr if not suppress_output else subprocess.DEVNULL,
        input=b"\n",
    )


def _resolve_bundle_output_dir_name(part_name: str) -> str:
    raw_name = Path(part_name).with_suffix("").as_posix()
    return "".join(char if char.isalnum() or char in {"-", "_", "."} else "_" for char in raw_name) or "part"


def _resolve_safe_archive_member_path(extraction_root: Path, member: str) -> Path:
    member_path = PurePosixPath(member.replace("\\", "/"))

    extracted_path = extraction_root / member_path
    resolved_extracted_path = extracted_path.resolve()
    if not resolved_extracted_path.is_relative_to(extraction_root.resolve()):
        raise ValueError(f"Unsafe archive member path: {member!s}")

    return resolved_extracted_path


def _decode_bundle_parts(
    apktool: str,
    parts: tuple[tuple[str, Path], ...],
    unpacked_tmp_path: Path,
    suppress_output: bool,
) -> None:
    parts_root = unpacked_tmp_path / "parts"
    parts_root.mkdir(parents=True, exist_ok=True)
    for part_name, apk_part in parts:
        part_output = parts_root / _resolve_bundle_output_dir_name(part_name)
        _decode_apk(apktool, apk_part, part_output, suppress_output)


def unpack_input(apktool: str, app_input: Path, cache: Cache, suppress_output: bool) -> None:
    unpacked_path = cache.get_apktool_cache_dir()
    if unpacked_path.exists():
        return

    unpacked_tmp_path = unpacked_path.with_suffix(".tmp")
    if unpacked_tmp_path.exists():
        shutil.rmtree(unpacked_tmp_path)

    input_kind = get_input_kind(app_input)

    if input_kind is InputKind.APK:
        _decode_apk(apktool, app_input, unpacked_tmp_path, suppress_output)
    elif input_kind is InputKind.DIRECTORY:
        directory_parts = tuple(
            (part.relative_to(app_input).as_posix(), part) for part in list_directory_apk_files(app_input)
        )
        _decode_bundle_parts(apktool, directory_parts, unpacked_tmp_path, suppress_output)
    else:
        archive_members = list_archive_apk_members(app_input)
        with tempfile.TemporaryDirectory(prefix="sigmatcher-bundle-") as raw_tmp_dir:
            extraction_root = Path(raw_tmp_dir)
            with zipfile.ZipFile(app_input) as archive_file:
                archive_parts: list[tuple[str, Path]] = []
                for member in archive_members:
                    extracted_path = _resolve_safe_archive_member_path(extraction_root, member)
                    extracted_path.parent.mkdir(parents=True, exist_ok=True)
                    with archive_file.open(member) as source:
                        _ = extracted_path.write_bytes(source.read())
                    archive_parts.append((member, extracted_path))
            _decode_bundle_parts(apktool, tuple(archive_parts), unpacked_tmp_path, suppress_output)

    _ = shutil.move(unpacked_tmp_path, unpacked_path)


def unpack_apk(apktool: str, apk: Path, cache: Cache, suppress_output: bool) -> None:
    unpack_input(apktool, apk, cache, suppress_output)


def _get_apk_version_from_yaml(apktool_yaml_file: Path) -> str | None:
    try:
        with apktool_yaml_file.open() as f:
            apk_version = yaml.safe_load(f)["versionInfo"]["versionName"]  # pyright: ignore[reportAny]
    except KeyError:
        return None

    if isinstance(apk_version, float | int):
        apk_version = str(apk_version)
    assert isinstance(apk_version, str) or apk_version is None
    return apk_version


def get_apk_version(unpacked_path: Path) -> str | None:
    root_apktool_yaml_file = unpacked_path / "apktool.yml"
    if root_apktool_yaml_file.exists():
        return _get_apk_version_from_yaml(root_apktool_yaml_file)

    apktool_yaml_files = sorted(unpacked_path.rglob("apktool.yml"), key=lambda path: path.as_posix())

    preferred_apktool_yaml_files: list[Path] = []
    non_preferred_apktool_yaml_files: list[Path] = []

    for apktool_yaml_file in apktool_yaml_files:
        part_name = apktool_yaml_file.parent.name.casefold()
        if part_name.startswith("base") or "_base" in part_name:
            preferred_apktool_yaml_files.append(apktool_yaml_file)
        else:
            non_preferred_apktool_yaml_files.append(apktool_yaml_file)

    for apktool_yaml_file in [*preferred_apktool_yaml_files, *non_preferred_apktool_yaml_files]:
        apk_version = _get_apk_version_from_yaml(apktool_yaml_file)
        if apk_version is not None:
            return apk_version

    return None
