#!/usr/bin/env bash
# Score a PreToolUse guardrail hook against a list of commands, without executing any of them.
#
#   bench.sh <cases file> -- <hook command...>
#   bench.sh cases.txt -- bash ../../hooks/deny-destructive-commands.sh
#   bench.sh cases.txt -- node .../cc-safety-net.js hook --coding-cli
#
# Each case is "deny|command" or "allow|command". The hook receives the JSON Claude Code
# sends before a Bash call on stdin (hook_event_name, tool_name, tool_input.command...).
# A hook blocks by exiting 2, or by printing hookSpecificOutput.permissionDecision
# "deny" or "ask". An "ask" interrupts the user: it counts as blocked, and is listed.
set -u
cases=${1:?usage: bench.sh <cases file> -- <hook command...>}
shift
[[ ${1:-} == -- ]] && shift
(( $# )) || { echo "missing hook command after --" >&2; exit 2; }

blocked_ok=0 blocked_total=0 allowed_ok=0 allowed_total=0 asks=0
while IFS='|' read -r want cmd; do
  [[ -z $want || $want == \#* ]] && continue
  json=$(jq -cn --arg c "$cmd" --arg cwd "$PWD" '{hook_event_name:"PreToolUse",session_id:"bench",transcript_path:"/dev/null",cwd:$cwd,permission_mode:"default",tool_name:"Bash",tool_input:{command:$c}}')
  out=$(printf '%s' "$json" | "$@" 2>/dev/null); code=$?
  decision=$(printf '%s' "$out" | jq -r '.hookSpecificOutput.permissionDecision // empty' 2>/dev/null)
  if (( code == 2 )) || [[ $decision == deny ]]; then got=deny
  elif [[ $decision == ask ]]; then got=ask; ((asks++))
  else got=allow; fi
  if [[ $want == deny ]]; then
    ((blocked_total++))
    if [[ $got != allow ]]; then ((blocked_ok++)); else echo "MISSED  (let through): $cmd"; fi
  else
    ((allowed_total++))
    if [[ $got == allow ]]; then ((allowed_ok++)); else echo "BLOCKED (normal work, got $got): $cmd"; fi
  fi
done < "$cases"
echo "destructive blocked: $blocked_ok / $blocked_total"
echo "legitimate allowed:  $allowed_ok / $allowed_total"
(( asks )) && echo "prompts to the user:  $asks"
(( blocked_ok == blocked_total && allowed_ok == allowed_total ))
