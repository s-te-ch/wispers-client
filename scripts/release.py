#!/usr/bin/env python3
"""Release tooling for the wispers-client repo.

Two subcommands:

    release.py bump 0.16.0            # rewrite version strings across manifests
    release.py build 0.16.0           # build every artifact, tag, and publish

The version is `X.Y.Z`, optionally with a `-rcN` pre-release suffix, and may be
given with or without a leading `v` (it's only a git-tag convention; the code
adds or drops it per system — see the Version type). A `-rcN` suffix is what
marks a build as a pre-release, so there is no separate flag: `build 0.16.0` is
a final release, `build 0.16.0-rc1` a pre-release.

`bump` only edits files, for review before a release. `build` does the whole
release in the one order that avoids the checksum chicken-and-egg: it builds
the xcframework and the Go static libraries *before* the tag, pins their
checksums into Package.swift and MODULE.bazel, and only then commits, tags,
and uploads those exact bytes.

macOS only (it builds the Swift xcframework). Needs: Rust with the iOS targets,
an authenticated `gh`, `swift`, and a clean working tree.
"""

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

CLIENT_DIR = Path(__file__).resolve().parent.parent
REPO = "s-te-ch/wispers-client"

# The five prebuilt Go static libraries the Bazel module pins by checksum.
PLATFORMS = ["darwin_arm64", "darwin_amd64", "linux_amd64", "linux_arm64", "windows_amd64"]


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    hint = "X.Y.Z or X.Y.Z-rcN (a leading v is fine); the -rcN suffix marks a pre-release"
    b = sub.add_parser("bump", help="rewrite version strings across manifests")
    b.add_argument("version", type=Version.parse, help=hint)

    r = sub.add_parser("build", help="build artifacts, tag, and publish a release")
    r.add_argument("version", type=Version.parse, help=hint)

    args = parser.parse_args()
    if args.cmd == "bump":
        bump(args.version)
    else:
        build(args.version)


@dataclass(frozen=True)
class Version:
    """A release version in the several spellings the tooling needs.

    You type one thing — `0.16.0` or `v0.16.0`, either is accepted — and the
    `v` becomes an internal detail: it's only a git-tag convention. Every
    consumer reads the exact spelling it wants off this, so the X.Y.Z / vX.Y.Z
    distinction lives here and nowhere else.
    """
    number: str

    # X.Y.Z, optionally a -rcN pre-release suffix — nothing else. That suffix
    # is what makes a build a pre-release, so there's no separate flag to
    # forget or contradict.
    _FORMAT = re.compile(r"\d+\.\d+\.\d+(?:-rc\d+)?")

    @classmethod
    def parse(cls, s: str) -> "Version":
        number = s.strip().removeprefix("v")
        if not cls._FORMAT.fullmatch(number):
            raise argparse.ArgumentTypeError(
                f"invalid version {s!r}: expected X.Y.Z or X.Y.Z-rcN")
        return cls(number=number)

    @property
    def tag(self) -> str:
        """v0.16.0 — the git tag, GitHub release, and archive-URL form."""
        return f"v{self.number}"

    @property
    def pep440(self) -> str:
        """0.16.0rc1 — PyPI drops the dash before the rc tag."""
        return self.number.replace("-rc", "rc")

    @property
    def prerelease(self) -> bool:
        """True for a -rcN version; the format allows a dash nowhere else."""
        return "-" in self.number


# --- bump -------------------------------------------------------------------

def bump(version: Version) -> None:
    """Rewrite the version string in every package manifest.

    Cargo, PyPI (PEP 440), Kotlin, and the Bazel module version. The Bazel
    archive URLs and checksums are stamped later, at release time, by build().
    """
    print(f"==> Bumping versions to {version.number}")

    # Cargo: the [package] version is the first `version = ` line in each crate.
    edit("wispers-connect/Cargo.toml", r'(?m)(^version = ")[^"]*(")', version.number)
    edit("wcadm/Cargo.toml", r'(?m)(^version = ")[^"]*(")', version.number)

    # wconnect has both its own [package] version and a wispers-connect dep
    # version; scope the first to the [package] section so the dep line is
    # only touched by the explicit rule below.
    edit(
        "wconnect/Cargo.toml",
        r'(\[package\]\n(?:(?!\[).*\n)*?version = ")[^"]*(")', version.number)
    edit(
        "wconnect/Cargo.toml",
        r'(wispers-connect = \{ path = "\.\./wispers-connect", version = ")[^"]*(")', version.number)

    edit("wrappers/python/pyproject.toml", r'(?m)(^version = ")[^"]*(")', version.pep440)

    # Kotlin: the fallback in the `coordinates(... ?: "x")` call, same line.
    edit("wrappers/kotlin/build.gradle.kts", r'(coordinates\(.*\?: ")[^"]*(")', version.number)

    # Bazel: the module() block version only, never the bazel_dep versions.
    edit("MODULE.bazel", r'(module\((?:(?!\)).*\n)*?\s*version = ")[^"]*(")', version.number)

    print("\n==> Done. Verify with: git diff")


# --- build ------------------------------------------------------------------

def build(version: Version) -> None:
    out = Path(tempfile.mkdtemp(prefix="wispers-release-"))
    kind = "pre-release" if version.prerelease else "release"
    print(f"==> Building {kind} artifacts for {version.tag}\n    Output: {out}")

    require_clean_tree()
    sync_go_header()
    checksum = build_xcframework(out)
    build_go_libs(out)
    stamp_module_bazel(version, out)
    update_package_swift(version, checksum)

    print("\n==> Artifacts:")
    run("ls", "-lh", str(out))

    if not confirm(f"Commit, tag {version.tag}, and push?"):
        print(f"Aborted. Artifacts are in {out}\nPackage.swift has been modified but not committed.")
        return
    commit_tag_push(version)
    create_release(version, out)
    print_remaining_steps()


def require_clean_tree() -> None:
    if git("status", "--porcelain").strip():
        sys.exit("ERROR: Working tree is not clean. Commit or stash changes first.")


def sync_go_header() -> None:
    """Ship the canonical C header at the Go wrapper's package root.

    Gazelle only auto-detects sources at the top level of a package, so the
    Bazel consumer needs the header there. A no-op when the two files match;
    a cbindgen API change is captured in the release commit.
    """
    print("\n==> Syncing wispers_connect.h into wrappers/go/...")
    shutil.copyfile(
        CLIENT_DIR / "wispers-connect/include/wispers_connect.h",
        CLIENT_DIR / "wrappers/go/wispers_connect.h")


def build_xcframework(out: Path) -> str:
    """Build the Swift xcframework, zip it, and return its SPM checksum."""
    print("\n==> Building Swift xcframework...")
    swift_dir = CLIENT_DIR / "wrappers/swift"
    run("scripts/build-xcframework.sh", "--release", cwd=swift_dir)
    zip_path = out / "CWispersConnect.xcframework.zip"
    run("zip", "-r", str(zip_path), "CWispersConnect.xcframework", cwd=swift_dir)
    checksum = run(
        "swift", "package", "compute-checksum", str(zip_path),
        cwd=swift_dir, capture=True).strip()
    print(f"    Checksum: {checksum}")
    # The header goes into the release too.
    shutil.copyfile(
        CLIENT_DIR / "wispers-connect/include/wispers_connect.h",
        out / "wispers_connect.h")
    return checksum


def build_go_libs(out: Path) -> None:
    """Build the prebuilt Go static libraries and drop them in `out`.

    Runs build-go-libs.yml as a dry run and downloads its artifacts, so the
    checksums stamped into MODULE.bazel are computed over the very bytes the
    release will carry — never a rebuild that could drift. The archives are
    compiled from Rust source only, so the ref they build from is irrelevant;
    main is fine.
    """
    print("\n==> Building Go static libraries (build-go-libs.yml, dry run)...")
    before = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    run(
        "gh", "workflow", "run", "build-go-libs.yml", "-R", REPO, "--ref", "main",
        "-f", "dry_run=true")

    print("    Waiting for the run to appear...")
    time.sleep(8)
    run_id = poll_for_run(before)
    print(f"    Run: https://github.com/{REPO}/actions/runs/{run_id}")
    run("gh", "run", "watch", run_id, "-R", REPO, "--exit-status")

    dl = out / "go-libs"
    run("gh", "run", "download", run_id, "-R", REPO, "-D", str(dl))
    # Flatten libwispers_connect-<platform>/libwispers_connect-<platform>.a -> out/.
    for archive in dl.glob("*/libwispers_connect-*.a"):
        archive.rename(out / archive.name)
    shutil.rmtree(dl)


def poll_for_run(since: str) -> str:
    """Find the databaseId of the build-go-libs run dispatched after `since`."""
    query = (
        f'[.[] | select(.createdAt >= "{since}")] '
        '| sort_by(.createdAt) | last | .databaseId')
    for _ in range(12):
        run_id = run(
            "gh", "run", "list", "-R", REPO, "--workflow=build-go-libs.yml",
            "--event=workflow_dispatch", "--json", "databaseId,createdAt",
            "-q", query, capture=True).strip()
        if run_id and run_id != "null":
            return run_id
        time.sleep(5)
    sys.exit("ERROR: could not find the dispatched build-go-libs run.")


def stamp_module_bazel(version: Version, out: Path) -> None:
    """Pin the module version, archive URLs, and per-platform checksums."""
    print("\n==> Stamping MODULE.bazel (version, archive URLs, checksums)...")

    edit("MODULE.bazel", r'(module\((?:(?!\)).*\n)*?\s*version = ")[^"]*(")', version.number)
    # Every archive URL points at this release's tag.
    edit("MODULE.bazel", r'(releases/download/)[^/]+(/libwispers_connect-)', version.tag, count=len(PLATFORMS))

    for platform in PLATFORMS:
        archive = out / f"libwispers_connect-{platform}.a"
        if not archive.exists():
            sys.exit(f"ERROR: missing archive for {platform}.")
        digest = sha256(archive)
        edit(
            "MODULE.bazel",
            r'(name = "wispers_connect_lib_' + re.escape(platform) +
            r'",\n\s*downloaded_file_path = "[^"]*",\n\s*sha256 = ")[0-9a-f]+(")',
            digest)
    print(f"    MODULE.bazel stamped: {version.number} {version.tag}")


def update_package_swift(version: Version, checksum: str) -> None:
    """Point the SPM binary target at this release's zip and checksum."""
    print("\n==> Updating Package.swift...")
    url = f"https://github.com/{REPO}/releases/download/{version.tag}/CWispersConnect.xcframework.zip"
    edit("Package.swift", r'(url: ")https://github\.com/' + re.escape(REPO) + r'/releases/download/[^"]*(")', url)
    edit("Package.swift", r'(checksum: ")[a-f0-9]*(")', checksum)
    print("    Updated Package.swift")


def commit_tag_push(version: Version) -> None:
    tag = version.tag
    git("add", "Package.swift", "wrappers/go/wispers_connect.h", "MODULE.bazel")
    git("commit", "-m", f"Release {tag}: Package.swift + MODULE.bazel checksums")
    git("tag", "-a", tag, "-m", f"Release {tag}")
    git("tag", "-a", f"wrappers/go/{tag}", "-m", f"Go module release {tag}")
    git("push", "origin", "main", tag, f"wrappers/go/{tag}")
    print("    Pushed main + tags")


def create_release(version: Version, out: Path) -> None:
    tag = version.tag
    print("\n==> Writing SHA256SUMS...")
    files = sorted(p for p in out.iterdir() if p.is_file())
    sums = out / "SHA256SUMS"
    sums.write_text("".join(f"{sha256(a)}  {a.name}\n" for a in files))
    assets = files + [sums]

    print("\n==> Creating GitHub release...")
    cmd = [
        "gh", "release", "create", tag, "--repo", REPO, "--verify-tag",
        "--title", tag, "--notes", f"Release {tag}"]
    if version.prerelease:
        cmd.append("--prerelease")
    cmd += [str(a) for a in assets]
    run(*cmd)
    print(f"==> Release created: https://github.com/{REPO}/releases/tag/{tag}")


def print_remaining_steps() -> None:
    # Mirrors the post-`build` steps in docs/connect/releases.md; keep in sync.
    # (The Go static libs are built above and attached to the release, and
    # MODULE.bazel pins them, so that doc step has no manual work left.)
    # Ordered shell-first: crates/Maven/outer-repo stay in the shell; the two
    # workflow triggers (CLI binaries, PyPI) need the browser, so they go last.
    steps = [
        ("Publish to crates.io", "cargo publish -p wispers-connect && cargo publish -p wcadm && cargo publish -p wconnect"),
        ("Publish to Maven", "cd wrappers/kotlin && ANDROID_HOME=$HOME/Library/Android/sdk ./gradlew buildNativeLibs publishAllPublicationsToMavenCentralRepository"),
        ("Update the outer repo", "pin connect/client + move oss/connect/hub git_override to the new tag"),
        ("Build CLI binaries", "Trigger build-cli-binaries.yml workflow"),
        ("Publish to PyPI", "Trigger publish-python.yml workflow"),
    ]
    width = max(len(label) for label, _ in steps)
    print("\n==> Done. Remaining steps:")
    for n, (label, command) in enumerate(steps, 1):
        print(f"    {n}. {label + ':':{width + 1}} {command}")


# --- shared plumbing --------------------------------------------------------

def edit(rel_path: str, pattern: str, value: str, *, count: int = 1) -> None:
    """Replace a captured span in a file, asserting the expected match count.

    `pattern` must have two capture groups bracketing the text to replace; the
    span between them is swapped for `value`. Fails loudly if the number of
    matches isn't `count`, so a manifest that drifted out of the shape we
    expect stops the release instead of being silently left stale.
    """
    path = CLIENT_DIR / rel_path
    text = path.read_text()
    new, n = re.subn(pattern, lambda m: m.group(1) + value + m.group(2), text)
    if n != count:
        sys.exit(f"ERROR: {rel_path}: expected {count} match(es), found {n}")
    path.write_text(new)
    print(f"    {rel_path}")


def confirm(prompt: str) -> bool:
    return input(f"{prompt} [y/N] ").strip().lower() in ("y", "yes")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args: str) -> str:
    return run("git", "-C", str(CLIENT_DIR), *args, capture=True)


def run(*args: str, cwd: Path = None, capture: bool = False) -> str:
    """Run a command, streaming or capturing, and abort the release on failure."""
    result = subprocess.run(
        args, cwd=cwd, text=True,
        stdout=subprocess.PIPE if capture else None)
    if result.returncode != 0:
        sys.exit(f"ERROR: command failed ({result.returncode}): {' '.join(args)}")
    return result.stdout if capture else ""


if __name__ == "__main__":
    main()
