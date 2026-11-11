#!/usr/bin/env python3
"""Calculate a release version from Conventional Commits since the latest tag."""
import re
import subprocess
import sys

TAG = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
COMMIT = re.compile(
    r"^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)"
    r"(?:\([^)]+\))?(!)?: .+$"
)


def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()


tags = []
for tag in git("tag", "--list").splitlines():
    match = TAG.fullmatch(tag)
    if match:
        tags.append((tuple(map(int, match.groups())), tag))
if not tags:
    raise SystemExit("No stable vMAJOR.MINOR.PATCH tag exists yet")
base, previous = max(tags)
raw = subprocess.check_output(
    ["git", "log", "--no-merges", "--format=%H%x1f%B%x1e", f"{previous}..HEAD"],
    text=True,
)
commits = []
for record in raw.split("\x1e"):
    if "\x1f" in record:
        sha, message = record.split("\x1f", 1)
        if sha.strip():
            commits.append((sha.strip(), message.strip()))
if not commits:
    raise SystemExit(0)

bump = 0  # 0: no release, 1: patch, 2: minor, 3: major
invalid = []
for sha, message in commits:
    lines = message.splitlines()
    subject = lines[0] if lines else ""
    match = COMMIT.fullmatch(subject)
    if not match:
        # Preserve a safe patch release path for commits made before the
        # Conventional Commit template was introduced.
        invalid.append(f"{sha[:12]} {subject}")
        bump = max(bump, 1)
        continue
    breaking = bool(match.group(2)) or any(
        line.startswith(("BREAKING CHANGE:", "BREAKING-CHANGE:")) for line in lines[1:]
    )
    kind = subject.split("(", 1)[0].split("!", 1)[0].split(":", 1)[0]
    if breaking:
        bump = max(bump, 3)
    elif kind == "feat":
        bump = max(bump, 2)
    elif kind in {"fix", "perf", "revert"}:
        bump = max(bump, 1)

if bump == 0:
    raise SystemExit(0)

major, minor, patch = base
if bump == 3:
    major, minor, patch = major + 1, 0, 0
elif bump == 2:
    minor, patch = minor + 1, 0
else:
    patch += 1
print(f"v{major}.{minor}.{patch}")
if invalid:
    print("Legacy non-Conventional commits treated as patch changes:", file=sys.stderr)
    print("\n".join(invalid), file=sys.stderr)
