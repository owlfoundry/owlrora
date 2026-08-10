#!/usr/bin/env python3

import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/release/prepare_release.py"
FILES = (
    Path("Cargo.lock"),
    Path("crates/owlrora-cli/Cargo.toml"),
    Path("crates/owlrora-key-provider/Cargo.toml"),
    Path("crates/owlrora-server/Cargo.toml"),
)
DEVELOPMENT_VERSION = "0.0.0-dev"


def fixture() -> Path:
    root = Path(tempfile.mkdtemp(prefix="owlrora-release-test."))
    for relative in FILES:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    return root


def run(root: Path, component: str, version: str, check: bool = True):
    return subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--root",
            str(root),
            "--component",
            component,
            "--version",
            version,
        ],
        check=check,
        capture_output=True,
        text=True,
    )


def package_entry(lockfile: str, package: str, version: str) -> str:
    return f'name = "{package}"\nversion = "{version}"'


def assert_cli_materialized(root: Path, version: str) -> None:
    lockfile = (root / FILES[0]).read_text(encoding="utf-8")
    cli = (root / FILES[1]).read_text(encoding="utf-8")
    key_provider = (root / FILES[2]).read_text(encoding="utf-8")
    server = (root / FILES[3]).read_text(encoding="utf-8")

    assert f'version = "{version}"' in cli
    assert package_entry(lockfile, "owlrora-cli", version) in lockfile
    assert f'version = "{DEVELOPMENT_VERSION}"' in key_provider
    assert f'version = "{DEVELOPMENT_VERSION}"' in server
    assert (
        f'owlrora-key-provider = {{ version = "={DEVELOPMENT_VERSION}",' in server
    )
    for package in ("owlrora-key-provider", "owlrora-server"):
        assert package_entry(lockfile, package, DEVELOPMENT_VERSION) in lockfile


def assert_server_materialized(root: Path, version: str) -> None:
    lockfile = (root / FILES[0]).read_text(encoding="utf-8")
    cli = (root / FILES[1]).read_text(encoding="utf-8")
    key_provider = (root / FILES[2]).read_text(encoding="utf-8")
    server = (root / FILES[3]).read_text(encoding="utf-8")

    assert f'version = "{DEVELOPMENT_VERSION}"' in cli
    assert package_entry(lockfile, "owlrora-cli", DEVELOPMENT_VERSION) in lockfile
    assert f'version = "{version}"' in key_provider
    assert f'version = "{version}"' in server
    assert f'owlrora-key-provider = {{ version = "={version}",' in server
    for package in ("owlrora-key-provider", "owlrora-server"):
        assert package_entry(lockfile, package, version) in lockfile


def test_component(component: str) -> None:
    root = fixture()
    try:
        run(root, component, "1.2.3-rc.1")
        if component == "cli":
            assert_cli_materialized(root, "1.2.3-rc.1")
        else:
            assert_server_materialized(root, "1.2.3-rc.1")
        before = {relative: (root / relative).read_bytes() for relative in FILES}
        run(root, component, "1.2.3-rc.1")
        after = {relative: (root / relative).read_bytes() for relative in FILES}
        assert before == after
    finally:
        shutil.rmtree(root)


def test_invalid_and_partial_state() -> None:
    root = fixture()
    try:
        assert run(root, "server", "not-semver", check=False).returncode != 0
        assert run(root, "cli", "1.2.3+build.1", check=False).returncode != 0
        manifest = root / "crates/owlrora-key-provider/Cargo.toml"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(
                f'version = "{DEVELOPMENT_VERSION}"', 'version = "9.9.9"', 1
            ),
            encoding="utf-8",
        )
        result = run(root, "server", "1.2.3", check=False)
        assert result.returncode != 0
        assert "partially prepared" in result.stderr
    finally:
        shutil.rmtree(root)


def test_refuses_a_stale_unrelated_component() -> None:
    root = fixture()
    try:
        cli = root / "crates/owlrora-cli/Cargo.toml"
        cli.write_text(
            cli.read_text(encoding="utf-8").replace(
                f'version = "{DEVELOPMENT_VERSION}"', 'version = "9.9.9"', 1
            ),
            encoding="utf-8",
        )
        result = run(root, "server", "1.2.3", check=False)
        assert result.returncode != 0
        assert "partially prepared" in result.stderr
    finally:
        shutil.rmtree(root)


def main() -> None:
    test_component("cli")
    test_component("server")
    test_invalid_and_partial_state()
    test_refuses_a_stale_unrelated_component()
    print("release preparation tests passed")


if __name__ == "__main__":
    main()
