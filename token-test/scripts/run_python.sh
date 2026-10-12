#!/bin/sh
# Run a Python script with the first available interpreter on minimal runners.

for py in python3 python python2; do
  if command -v "$py" >/dev/null 2>&1; then
    exec "$py" "$@"
  fi
done

echo "ERROR: no Python found (tried python3, python, python2)" >&2
exit 127
