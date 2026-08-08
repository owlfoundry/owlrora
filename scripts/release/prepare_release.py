#!/usr/bin/env python3

import argparse
import os
import re
import tomllib
from pathlib import Path

DEVELOPMENT_VERSION = "0.0.0-dev"
TAG_PREFIX = "server-v"
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


def package_version(manifest: Path) -> str:
    with manifest.open("rb") as source:
        return str(tomllib.load(source)["package"]["version"])


def replace_once(path: Path, pattern: str, replacement: str) -> None:
    source = path.read_text(encoding="utf-8")
    updated, count = re.subn(pattern, replacement, source, count=1, flags=re.MULTILINE)
    if count != 1:
        raise RuntimeError(f"expected exactly one version entry in {path}")
    path.write_text(updated, encoding="utf-8")


def prepare(root: Path) -> None:
    manifest = root / "crates/owlrora-server/Cargo.toml"
    lockfile = root / "Cargo.lock"
    current_version = package_version(manifest)
    if current_version != DEVELOPMENT_VERSION:
        raise RuntimeError(
            f"expected development version {DEVELOPMENT_VERSION}, got {current_version}"
        )

    ref_type = os.environ.get("GITHUB_REF_TYPE")
    ref_name = os.environ.get("GITHUB_REF_NAME", "")
    if ref_type != "tag":
        return
    if not ref_name.startswith(TAG_PREFIX):
        raise RuntimeError("release preparation requires a server-v* tag")

    version = ref_name.removeprefix(TAG_PREFIX)
    if version == DEVELOPMENT_VERSION or SEMVER.fullmatch(version) is None:
        raise RuntimeError(f"invalid release version: {version}")

    replace_once(
        manifest,
        r'^version = "0\.0\.0-dev"$',
        f'version = "{version}"',
    )
    replace_once(
        lockfile,
        r'(name = "owlrora-server"\nversion = ")0\.0\.0-dev("\n)',
        rf"\g<1>{version}\g<2>",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    arguments = parser.parse_args()
    prepare(arguments.root)
