#!/usr/bin/env bash
# Block agent reads of obvious secret files (LLM02).
set -euo pipefail

input=$(cat)
path=$(COMMAND_JSON="$input" python3 -c 'import json,os; d=json.loads(os.environ["COMMAND_JSON"]); print(d.get("path") or d.get("file_path") or d.get("filePath") or "")')

secret_re='(^|/)\.env($|\.)|(^|/)(.*credentials.*|.*secret.*)($|/)|(^|/).*\.(pem|key|p12|pfx)$|(^|/)id_(rsa|ed25519)$'

if [[ -n "$path" && "$path" =~ $secret_re ]]; then
  # allow .env.example
  if [[ "$path" =~ \.env\.example$ ]]; then
    echo '{ "permission": "allow" }'
    exit 0
  fi
  python3 -c 'import json; print(json.dumps({
    "permission": "deny",
    "user_message": "Blocked read of likely secret file.",
    "agent_message": "Do not load secrets into context. Use .env.example or redacted placeholders instead."
  }))'
  exit 0
fi

echo '{ "permission": "allow" }'
exit 0
