#!/usr/bin/env bash
# Gate high-risk shell commands (LLM03). Plain git push is deny (IDE Agent shell).
set -euo pipefail

input=$(cat)
command=$(COMMAND_JSON="$input" python3 -c 'import json,os; print(json.loads(os.environ["COMMAND_JSON"]).get("command",""))')

deny_re='(^|[[:space:]])(sudo|rm[[:space:]]+-rf|rm[[:space:]]+-fr)($|[[:space:]])|git[[:space:]]+push($|[[:space:]])|git[[:space:]]+push[[:space:]]+(-f|--force)|git[[:space:]]+reset[[:space:]]+--hard|git[[:space:]]+clean[[:space:]]+-f|git[[:space:]]+branch[[:space:]]+-D|curl[^|]*\|[[:space:]]*(ba)?sh|wget[^|]*\|[[:space:]]*(ba)?sh|chmod[[:space:]]+777'

ask_re='(^|[[:space:]])(curl|wget|nc|ncat|ssh|scp)($|[[:space:]])|pip[[:space:]]+install|npm[[:space:]]+install|pnpm[[:space:]]+add|yarn[[:space:]]+add|brew[[:space:]]+install'

if [[ "$command" =~ $deny_re ]]; then
  python3 -c 'import json; print(json.dumps({
    "permission": "deny",
    "user_message": "Blocked dangerous shell command (least privilege).",
    "agent_message": "Hook denied a destructive/high-risk command. Ask the user to run it manually if truly required."
  }))'
  exit 0
fi

if [[ "$command" =~ $ask_re ]]; then
  python3 -c 'import json; print(json.dumps({
    "permission": "ask",
    "user_message": "Network / package command — review before allowing.",
    "agent_message": "HITL required for network or package install."
  }))'
  exit 0
fi

echo '{ "permission": "allow" }'
exit 0
