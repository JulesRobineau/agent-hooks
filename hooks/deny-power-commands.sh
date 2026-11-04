#!/usr/bin/env bash
# PreToolUse hook: deny shutdown/reboot/poweroff/halt only when invoked as a command,
# not when the word merely appears (commit messages, grep patterns, Go identifiers).
# Run with --test to check the pattern against known cases.

pattern='(^|[;&|({`]|\$\(|(sh|bash|zsh|dash|ksh)[[:space:]]+-[a-z]*c[[:space:]]+["'\'']?)[[:space:]]*((sudo|doas|exec|nohup|command|env|timeout[[:space:]]+[0-9.]+[smhd]?|[A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*)[[:space:]]+(-[^[:space:]]+[[:space:]]+)*)*(/[^[:space:]]*/)?(shutdown|poweroff|halt|reboot|(systemctl|loginctl)([[:space:]]+-[^[:space:]]+)*[[:space:]]+(poweroff|reboot|halt|kexec)|(tel)?init[[:space:]]+[06])([[:space:]]|$|[;&|)}`"'\''])'

is_power_command() { grep -qE "$pattern" <<<"$1"; }

if [[ $1 == --test ]]; then
  fail=0
  while IFS='|' read -r want cmd; do
    if is_power_command "$cmd"; then got=deny; else got=allow; fi
    [[ $got == "$want" ]] || { echo "FAIL want=$want got=$got: $cmd"; fail=1; }
  done <<'CASES'
deny|shutdown now
deny|sudo shutdown -h now
deny|sudo -n reboot
deny|cd /tmp && reboot
deny|echo ok; poweroff
deny|/sbin/shutdown -r +1
deny|systemctl reboot
deny|sudo systemctl --no-wall poweroff
deny|loginctl reboot
deny|bash -c "reboot"
deny|sh -c 'shutdown now'
deny|bash -lc reboot
deny|echo $(reboot)
deny|init 0
deny|sudo telinit 6
deny|nohup reboot &
deny|timeout 5 shutdown now
deny|FOO=1 halt
allow|git commit -m "fix graceful shutdown"
allow|grep -rn shutdown .
allow|grep -c "reboot" /var/log/syslog
allow|grep -n "systemctl reboot" docs/ops.md
allow|go test ./... -run TestShutdown
allow|echo "reboot required"
allow|cat /var/run/reboot-required
allow|journalctl -b -1 | grep -i shutdown
allow|kubectl rollout restart deploy/api
allow|docker restart api
allow|git log --grep halt
allow|ls /etc/init.d
allow|./reboot.sh --dry-run
CASES
  [[ $fail == 0 ]] && echo "all cases pass"
  exit $fail
fi

cmd=$(jq -r '.tool_input.command // ""')
if is_power_command "$cmd"; then
  jq -n '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny",
    permissionDecisionReason: "Blocked: shutdown/poweroff/halt/reboot commands are prohibited. Ask the user to run this manually if needed."}}'
fi
exit 0
