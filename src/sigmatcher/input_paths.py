import enum
import hashlib
import zipfile
from pathlib import Path


class InputKind(enum.Enum):
    APK = "apk"
    ARCHIVE = "archive"
    DIRECTORY = "directory"


SUPPORTED_ARCHIVE_SUFFIXES = frozenset({".apkm", ".xapk"})
SUPPORTED_FILE_SUFFIXES = frozenset({".apk", ".apkm", ".xapk"})


def _hash_file(path: Path) -> bytes:
    hasher = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.digest()


def get_input_kind(app_input: Path) -> InputKind:
    if app_input.is_dir():
        return InputKind.DIRECTORY

    suffix = app_input.suffix
    if suffix == ".apk":
        return InputKind.APK
    if suffix in SUPPORTED_ARCHIVE_SUFFIXES:
        return InputKind.ARCHIVE

    supported_suffixes = ", ".join(sorted(SUPPORTED_FILE_SUFFIXES))
    raise ValueError(f"Unsupported input file type for {app_input!s}. Supported file suffixes: {supported_suffixes}")


def list_directory_apk_files(directory_input: Path) -> tuple[Path, ...]:
    apk_files = [path for path in directory_input.rglob("*.apk") if path.is_file()]
    apk_files.sort(key=lambda path: path.relative_to(directory_input).as_posix())
    return tuple(apk_files)


def list_archive_apk_members(archive_input: Path) -> tuple[str, ...]:
    with zipfile.ZipFile(archive_input) as archive_file:
        apk_members = [member for member in archive_file.namelist() if Path(member).suffix == ".apk"]
    apk_members.sort()
    return tuple(apk_members)


def validate_input_path(app_input: Path) -> None:
    if not app_input.exists():
        raise ValueError(f"Input path does not exist: {app_input!s}")

    input_kind = get_input_kind(app_input)
    if input_kind is InputKind.APK:
        return

    if input_kind is InputKind.DIRECTORY:
        if len(list_directory_apk_files(app_input)) == 0:
            raise ValueError(f"Directory input contains no .apk files: {app_input!s}")
        return

    assert input_kind is InputKind.ARCHIVE
    try:
        archive_members = list_archive_apk_members(app_input)
    except zipfile.BadZipFile as e:
        raise ValueError(f"Input archive is not a valid zip file: {app_input!s}") from e

    if len(archive_members) == 0:
        raise ValueError(f"Input archive contains no .apk files: {app_input!s}")


def hash_input_path(app_input: Path) -> str:
    input_kind = get_input_kind(app_input)

    if input_kind is not InputKind.DIRECTORY:
        return _hash_file(app_input).hex()

    hasher = hashlib.sha256()
    for apk_file in list_directory_apk_files(app_input):
        relative_path = apk_file.relative_to(app_input).as_posix().encode()
        hasher.update(relative_path)
        hasher.update(b"\0")
        hasher.update(_hash_file(apk_file))
    return hasher.hexdigest()
