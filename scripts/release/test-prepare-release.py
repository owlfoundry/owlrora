#!/usr/bin/env python3

import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/release/prepare_release.py"
FILES = (
    Path("Cargo.lock"),
    Path("crates/owlrora-key-provider/Cargo.toml"),
    Path("crates/owlrora-server/Cargo.toml"),
)


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


def assert_materialized(root: Path, version: str) -> None:
    key_provider = (root / FILES[1]).read_text(encoding="utf-8")
    server = (root / FILES[2]).read_text(encoding="utf-8")
    lockfile = (root / FILES[0]).read_text(encoding="utf-8")
    assert f'version = "{version}"' in key_provider
    assert f'version = "{version}"' in server
    assert f'owlrora-key-provider = {{ version = "={version}",' in server
    for package in ("owlrora-key-provider", "owlrora-server"):
        assert f'name = "{package}"\nversion = "{version}"' in lockfile
    assert "0.0.0-dev" not in "\n".join((key_provider, server, lockfile))


def test_component(component: str) -> None:
    root = fixture()
    try:
        run(root, component, "1.2.3-rc.1")
        assert_materialized(root, "1.2.3-rc.1")
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
        manifest = root / "crates/owlrora-key-provider/Cargo.toml"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(
                'version = "0.0.0-dev"', 'version = "9.9.9"', 1
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
    print("release preparation tests passed")


if __name__ == "__main__":
    main()
