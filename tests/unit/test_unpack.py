import subprocess
import zipfile
from pathlib import Path

from _pytest.monkeypatch import MonkeyPatch

from sigmatcher.cache import Cache
from sigmatcher.input_paths import list_archive_apk_members, list_directory_apk_files, validate_input_path
from sigmatcher.unpack import get_apk_version, unpack_input

EXPECTED_PARTS_COUNT = 2


def test_validate_input_path_directory_without_apks_raises(tmp_path: Path) -> None:
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()

    try:
        validate_input_path(bundle_dir)
        raise AssertionError("Expected ValueError")
    except ValueError as e:
        assert "contains no .apk files" in str(e)


def test_list_directory_apk_files_is_recursive_and_sorted(tmp_path: Path) -> None:
    bundle_dir = tmp_path / "bundle"
    (bundle_dir / "z").mkdir(parents=True)
    (bundle_dir / "a").mkdir(parents=True)
    _ = (bundle_dir / "z" / "split.apk").write_bytes(b"z")
    _ = (bundle_dir / "a" / "base.apk").write_bytes(b"a")

    apk_files = list_directory_apk_files(bundle_dir)
    assert tuple(path.relative_to(bundle_dir).as_posix() for path in apk_files) == ("a/base.apk", "z/split.apk")


def test_list_archive_apk_members_sorted(tmp_path: Path) -> None:
    archive_path = tmp_path / "bundle.xapk"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("z/split.apk", b"z")
        archive.writestr("a/base.apk", b"a")
        archive.writestr("assets/readme.txt", b"ignored")

    members = list_archive_apk_members(archive_path)
    assert members == ("a/base.apk", "z/split.apk")


def test_unpack_input_decodes_directory_parts(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    _ = (bundle_dir / "base.apk").write_bytes(b"base")
    _ = (bundle_dir / "split_config.en.apk").write_bytes(b"split")

    cache = Cache(tmp_path / "cache")

    call_args: list[list[str | Path]] = []

    def fake_get_apktool_version(_apktool: str) -> str:
        return "2.12.0"

    def fake_run(args: list[str | Path], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        call_args.append(args)
        output_flag_index = args.index("--output")
        output_path = Path(args[output_flag_index + 1])
        output_path.mkdir(parents=True, exist_ok=True)
        _ = (output_path / "apktool.yml").write_text("versionInfo:\n  versionName: 1.0.0\n")
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr("sigmatcher.unpack.get_apktool_version", fake_get_apktool_version)
    monkeypatch.setattr(subprocess, "run", fake_run)

    unpack_input("apktool", bundle_dir, cache, suppress_output=True)

    unpacked_path = cache.get_apktool_cache_dir()
    assert unpacked_path.exists()
    assert len(call_args) == EXPECTED_PARTS_COUNT
    assert all("decode" in args for args in call_args)
    assert all("--only-manifest" in args for args in call_args)


def test_unpack_input_decodes_archive_parts(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    archive_path = tmp_path / "bundle.apkm"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("base.apk", b"base")
        archive.writestr("config.en.apk", b"config")

    cache = Cache(tmp_path / "cache")
    decoded_inputs: list[Path] = []

    def fake_get_apktool_version(_apktool: str) -> str:
        return "2.12.0"

    def fake_run(args: list[str | Path], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        decoded_inputs.append(Path(args[2]))
        output_flag_index = args.index("--output")
        output_path = Path(args[output_flag_index + 1])
        output_path.mkdir(parents=True, exist_ok=True)
        _ = (output_path / "apktool.yml").write_text("versionInfo:\n  versionName: 1.0.0\n")
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr("sigmatcher.unpack.get_apktool_version", fake_get_apktool_version)
    monkeypatch.setattr(subprocess, "run", fake_run)

    unpack_input("apktool", archive_path, cache, suppress_output=True)

    assert len(decoded_inputs) == EXPECTED_PARTS_COUNT
    assert {path.name for path in decoded_inputs} == {"base.apk", "config.en.apk"}


def test_get_apk_version_prefers_base_part(tmp_path: Path) -> None:
    unpacked_path = tmp_path / "apktool"
    (unpacked_path / "parts" / "feature").mkdir(parents=True)
    (unpacked_path / "parts" / "base").mkdir(parents=True)
    _ = (unpacked_path / "parts" / "feature" / "apktool.yml").write_text("versionInfo:\n  versionName: 9.9.9\n")
    _ = (unpacked_path / "parts" / "base" / "apktool.yml").write_text("versionInfo:\n  versionName: 1.2.3\n")

    assert get_apk_version(unpacked_path) == "1.2.3"


def test_get_apk_version_returns_first_available_for_bundle(tmp_path: Path) -> None:
    unpacked_path = tmp_path / "apktool"
    (unpacked_path / "parts" / "feature").mkdir(parents=True)
    _ = (unpacked_path / "parts" / "feature" / "apktool.yml").write_text("versionInfo:\n  versionName: 5.6.7\n")

    assert get_apk_version(unpacked_path) == "5.6.7"


def test_unpack_input_reuses_existing_cache_without_decoding(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    apk_path = tmp_path / "app.apk"
    _ = apk_path.write_bytes(b"app")

    cache = Cache(tmp_path / "cache")
    cache.get_apktool_cache_dir().mkdir(parents=True)

    def fail_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise AssertionError("subprocess.run should not be called when cache exists")

    monkeypatch.setattr(subprocess, "run", fail_run)
    unpack_input("apktool", apk_path, cache, suppress_output=True)


def test_validate_input_path_rejects_bad_archive(tmp_path: Path) -> None:
    archive_path = tmp_path / "broken.xapk"
    _ = archive_path.write_text("not a zip")

    try:
        validate_input_path(archive_path)
        raise AssertionError("Expected ValueError")
    except ValueError as e:
        assert "not a valid zip file" in str(e)


def test_unpack_input_cleans_partial_tmp_before_decode(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    apk_path = tmp_path / "app.apk"
    _ = apk_path.write_bytes(b"app")
    cache = Cache(tmp_path / "cache")
    partial_tmp = cache.get_apktool_cache_dir().with_suffix(".tmp")
    partial_tmp.mkdir(parents=True)

    def fake_get_apktool_version(_apktool: str) -> str:
        return "2.12.0"

    def fake_run(args: list[str | Path], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        output_flag_index = args.index("--output")
        output_path = Path(args[output_flag_index + 1])
        output_path.mkdir(parents=True, exist_ok=True)
        _ = (output_path / "apktool.yml").write_text("versionInfo:\n  versionName: 1.0.0\n")
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr("sigmatcher.unpack.get_apktool_version", fake_get_apktool_version)
    monkeypatch.setattr(subprocess, "run", fake_run)

    unpack_input("apktool", apk_path, cache, suppress_output=True)
    assert cache.get_apktool_cache_dir().exists()
    assert not partial_tmp.exists()
