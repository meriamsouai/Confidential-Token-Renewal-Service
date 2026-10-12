#!/bin/sh
# GitLab API GET without requiring a specific tool. Tries python, then wget, then curl.
# Prints __HTTP_CODE__:<n> on the first line, response body after.

set -eu

url="${1:?URL required}"
token="${2:?TOKEN required}"
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)

strip_cr() {
  sed 's/\r$//'
}

run_with_python() {
  py="$1"
  "$py" "$script_dir/gitlab_api_get.py" "$url" "$token"
}

for py in python3 python python2; do
  if command -v "$py" >/dev/null 2>&1; then
    run_with_python "$py"
    exit 0
  fi
done

if command -v wget >/dev/null 2>&1; then
  body_file=$(mktemp)
  hdr_file=$(mktemp)
  # wget returns non-zero on 4xx/5xx; we still want the status code.
  wget -q -S -O "$body_file" --header="PRIVATE-TOKEN: $token" "$url" 2>"$hdr_file" || true
  code=$(grep -i '^  HTTP/' "$hdr_file" | tail -1 | awk '{print $2}')
  if [ -z "$code" ]; then
    code="000"
  fi
  printf '__HTTP_CODE__:%s\n' "$code"
  strip_cr < "$body_file"
  rm -f "$body_file" "$hdr_file"
  exit 0
fi

if command -v curl >/dev/null 2>&1; then
  response=$(curl -sS -w "\n__HTTP_CODE__:%{http_code}" --header "PRIVATE-TOKEN: $token" "$url")
  code=$(printf '%s\n' "$response" | tail -n1 | sed 's/^__HTTP_CODE__://')
  body=$(printf '%s\n' "$response" | sed '$d')
  printf '__HTTP_CODE__:%s\n' "$code"
  printf '%s\n' "$body" | strip_cr
  exit 0
fi

echo "ERROR: need python3, python, wget, or curl for GitLab API calls" >&2
exit 127
