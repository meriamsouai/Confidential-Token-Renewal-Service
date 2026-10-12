#!/usr/bin/env python3
"""Assert GitLab project JSON path_with_namespace matches CI_PROJECT_PATH.

Usage:
  assert_project_path.py PROJECT_JSON_FILE CI_PROJECT_PATH
  assert_project_path.py - CI_PROJECT_PATH   # read JSON from stdin
"""

import json
import sys


def main() -> None:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} PROJECT_JSON_FILE_OR_- CI_PROJECT_PATH", file=sys.stderr)
        sys.exit(2)

    source, expected = sys.argv[1], sys.argv[2]
    if source == "-":
        body = sys.stdin.read()
    else:
        with open(source, encoding="utf-8") as f:
            body = f.read()

    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        print(f"ERROR: invalid JSON from GitLab API: {exc}", file=sys.stderr)
        print(body[:500], file=sys.stderr)
        sys.exit(1)

    actual = data.get("path_with_namespace") or data.get("path") or ""
    if actual != expected:
        print(f"ERROR: path mismatch: API={actual!r} CI_PROJECT_PATH={expected!r}", file=sys.stderr)
        sys.exit(1)

    print(f"OK: path_with_namespace={actual}")
    print(f"OK: project id={data.get('id')} name={data.get('name')}")


if __name__ == "__main__":
    main()
