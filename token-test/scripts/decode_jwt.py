#!/usr/bin/env python3
"""Decode JWT header and payload without verification (for lab inspection only)."""

import base64
import json
import sys


def b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_part(label: str, segment: str) -> None:
    data = json.loads(b64url_decode(segment))
    print(f"--- {label} ---")
    print(json.dumps(data, indent=2, sort_keys=True))


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: decode_jwt.py <jwt>", file=sys.stderr)
        sys.exit(1)

    token = sys.argv[1].strip()
    parts = token.split(".")
    if len(parts) != 3:
        print("Not a JWT (expected 3 dot-separated segments)", file=sys.stderr)
        sys.exit(1)

    decode_part("header", parts[0])
    decode_part("payload", parts[1])
  # signature (parts[2]) intentionally not printed — verify in production with JWKS


if __name__ == "__main__":
    main()
