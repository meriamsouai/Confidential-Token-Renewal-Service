#!/bin/sh
# Decode JWT header and payload without Python (base64url + openssl/base64).

set -eu

jwt="${1:?JWT required}"

decode_part() {
  label="$1"
  segment="$2"
  padded=$(printf '%s' "$segment" | tr '_-' '/+')
  pad_len=$((4 - ${#padded} % 4))
  if [ "$pad_len" -lt 4 ]; then
    padded=$(printf '%s%*s' "$padded" "$pad_len" '' | tr ' ' '=')
  fi
  echo "--- $label ---"
  if command -v openssl >/dev/null 2>&1; then
    printf '%s' "$padded" | openssl base64 -d -A 2>/dev/null || true
  else
    printf '%s' "$padded" | base64 -d 2>/dev/null || true
  fi
  echo ""
}

part1=$(printf '%s' "$jwt" | cut -d. -f1)
part2=$(printf '%s' "$jwt" | cut -d. -f2)
part3=$(printf '%s' "$jwt" | cut -d. -f3)

if [ -z "$part1" ] || [ -z "$part2" ] || [ -z "$part3" ]; then
  echo "Not a JWT (expected 3 dot-separated segments)" >&2
  exit 1
fi

decode_part "header" "$part1"
decode_part "payload" "$part2"
