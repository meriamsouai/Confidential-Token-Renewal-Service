#!/usr/bin/env python3
"""GitLab API GET using stdlib only."""

import sys
import urllib.error
import urllib.request


def main() -> None:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} URL TOKEN", file=sys.stderr)
        sys.exit(2)
    url, token = sys.argv[1], sys.argv[2]
    req = urllib.request.Request(url, headers={"PRIVATE-TOKEN": token})
    try:
        with urllib.request.urlopen(req) as resp:
            print(f"__HTTP_CODE__:{resp.status}")
            print(resp.read().decode())
    except urllib.error.HTTPError as exc:
        print(f"__HTTP_CODE__:{exc.code}")
        print(exc.read().decode())


if __name__ == "__main__":
    main()
