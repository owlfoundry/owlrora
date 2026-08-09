#!/usr/bin/env python3

import argparse
import os
import re
import tomllib
from pathlib import Path

DEVELOPMENT_VERSION = "0.0.0-dev"
TAG_PREFIXES = {"cli": "cli-v", "server": "server-v"}
PACKAGE_MANIFESTS = (
    Path("crates/owlrora-key-provider/Cargo.toml"),
    Path("crates/owlrora-server/Cargo.toml"),
)
LOCK_PACKAGES = ("owlrora-key-provider", "owlrora-server")
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


def package_version(manifest: Path) -> str:
    with manifest.open("rb") as source:
        return str(tomllib.load(source)["package"]["version"])


def dependency_version(manifest: Path, dependency: str) -> str:
    with manifest.open("rb") as source:
        value = tomllib.load(source)["dependencies"][dependency]
    if not isinstance(value, dict) or "version" not in value:
        raise RuntimeError(f"expected versioned {dependency} dependency in {manifest}")
    return str(value["version"])


def lock_version(lockfile: Path, package: str) -> str:
    pattern = re.compile(
        rf'^\[\[package\]\]\nname = "{re.escape(package)}"\nversion = "([^"]+)"$',
        re.MULTILINE,
    )
    matches = pattern.findall(lockfile.read_text(encoding="utf-8"))
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one {package} entry in {lockfile}")
    return matches[0]


def observed_versions(root: Path) -> list[str]:
    values = [package_version(root / manifest) for manifest in PACKAGE_MANIFESTS]
    values.append(
        dependency_version(
            root / "crates/owlrora-server/Cargo.toml", "owlrora-key-provider"
        ).removeprefix("=")
    )
    values.extend(lock_version(root / "Cargo.lock", package) for package in LOCK_PACKAGES)
    return values


def validate_uniform_state(root: Path, expected: str) -> None:
    values = observed_versions(root)
    if any(value != expected for value in values):
        raise RuntimeError(
            f"release state is not uniformly {expected}: {', '.join(values)}"
        )


def replace_once(path: Path, pattern: str, replacement: str) -> None:
    source = path.read_text(encoding="utf-8")
    updated, count = re.subn(pattern, replacement, source, count=1, flags=re.MULTILINE)
    if count != 1:
        raise RuntimeError(f"expected exactly one release version match in {path}")
    path.write_text(updated, encoding="utf-8")


def materialize(root: Path, version: str) -> None:
    for relative in PACKAGE_MANIFESTS:
        replace_once(
            root / relative,
            rf'^version = "{re.escape(DEVELOPMENT_VERSION)}"$',
            f'version = "{version}"',
        )

    replace_once(
        root / "crates/owlrora-server/Cargo.toml",
        rf'(owlrora-key-provider = \{{ version = ")={re.escape(DEVELOPMENT_VERSION)}(", path = "\.\./owlrora-key-provider" \}})',
        rf"\g<1>={version}\g<2>",
    )

    lockfile = root / "Cargo.lock"
    for package in LOCK_PACKAGES:
        replace_once(
            lockfile,
            rf'(\[\[package\]\]\nname = "{re.escape(package)}"\nversion = "){re.escape(DEVELOPMENT_VERSION)}("$)',
            rf"\g<1>{version}\g<2>",
        )


def validate_request(component: str, version: str) -> None:
    if component not in TAG_PREFIXES:
        raise RuntimeError(f"unknown release component: {component}")
    if version == DEVELOPMENT_VERSION or SEMVER.fullmatch(version) is None:
        raise RuntimeError(f"invalid release version: {version}")


def prepare(root: Path, component: str, version: str) -> None:
    validate_request(component, version)
    values = observed_versions(root)
    if all(value == version for value in values):
        return
    if not all(value == DEVELOPMENT_VERSION for value in values):
        raise RuntimeError(
            "refusing partially prepared or stale release state: " + ", ".join(values)
        )
    materialize(root, version)
    validate_uniform_state(root, version)


def environment_request() -> tuple[str, str] | None:
    if os.environ.get("GITHUB_REF_TYPE") != "tag":
        return None
    ref_name = os.environ.get("GITHUB_REF_NAME", "")
    for component, prefix in TAG_PREFIXES.items():
        if ref_name.startswith(prefix):
            return component, ref_name.removeprefix(prefix)
    raise RuntimeError("release preparation requires a cli-v* or server-v* tag")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--component", choices=sorted(TAG_PREFIXES))
    parser.add_argument("--version")
    arguments = parser.parse_args()

    if (arguments.component is None) != (arguments.version is None):
        parser.error("--component and --version must be supplied together")
    request = (
        (arguments.component, arguments.version)
        if arguments.component is not None and arguments.version is not None
        else environment_request()
    )
    if request is not None:
        prepare(arguments.root, *request)


if __name__ == "__main__":
    main()
