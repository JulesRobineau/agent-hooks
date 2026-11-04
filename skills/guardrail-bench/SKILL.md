---
name: guardrail-bench
description: Score a coding-agent guardrail (a PreToolUse hook that blocks destructive shell commands) against a list of commands to block and a list of everyday commands to let through, without executing any of them. Use when installing, replacing, configuring or updating a guardrail hook, when the user asks whether their agent is protected against rm -rf and similar commands, or when a hook interrupts normal work too often.
---

# Guardrail bench

A guardrail is code. It is tested like code: a list of commands it must block, a list of
commands it must let through, and two scores. A hook that blocks everything scores 17/17 on
the first list and is unusable. A hook that never interrupts scores 16/16 on the second and
protects nothing. You need both numbers.

Nothing in this bench is ever executed. The hook receives each command as text on stdin, in
the JSON Claude Code sends before a Bash call, and answers allow, ask or deny.

## Steps

1. Find the hook commands in `~/.claude/settings.json` (`hooks.PreToolUse[].hooks[].command`),
   or in `.claude/settings.json` of the project.
2. Run the bench against each one, from this skill's folder:
   ```bash
   ./bench.sh cases.txt -- bash ../../hooks/deny-power-commands.sh
   ./bench.sh cases.txt -- node ~/.claude/scripts/cc-safety-net/node_modules/cc-safety-net/dist/bin/cc-safety-net.js hook --coding-cli
   ```
   The script prints every miss (a destructive command let through) and every false alarm
   (normal work blocked or sent to the user for approval), then the two scores.
3. Add the user's own cases to `cases.txt`: the commands their agents run every day, and the
   variants a regex forgets (`-fr` instead of `-rf`, `~` instead of `$HOME`, a variable, a
   `bash -c "..."` wrapper, `find ... -delete`).
4. Report the two scores as measured, never as a guarantee. 17/17 on 33 cases means those 33
   cases, nothing more.
5. Prefer a hook that denies with a reason over a hook that asks: the agent reads the reason
   and changes approach alone, the user is not interrupted.
6. Pin the guardrail's version in a folder of its own, and rerun the bench before every update.
7. Write down the known holes. Two that stay open with a syntax-based hook: a path hidden in a
   variable (`W=/home/dev/projects; rm -rf $W`) and a deletion done by another program
   (`python3 -c "import shutil; shutil.rmtree(...)"`). The safety net for those is git and a
   backup the agent cannot reach.

## Files

- `cases.txt`: 17 destructive commands and 16 everyday ones, the bench described in the
  article below. Edit it, it is yours.
- `bench.sh`: the runner. Needs bash and jq.
- `../../hooks/deny-power-commands.sh`: a 57-line hook that denies the commands that switch
  the machine off or restart it, only in command position (not in a commit message or a
  grep). Run it with `--test` to replay its 31 built-in cases. Use it as the model for a hook
  that carries its own bench. It is one of the hooks this bench was built for: the author
  saw it block a heredoc because one line of a README started with the name of such a command,
  which is the rule working as written.

## What this bench found

In October 2026 the author's regex hook blocked 4 destructive commands out of 17 and
interrupted 5 everyday commands out of 16. It let `rm -rf ~` through because `~` does not start
with `/`, and `rm -fr /` because the options were not in the order the regex expected. A hook
that parses the command like the shell does (cc-safety-net 2.5.1, level Standard) scored
17/17 and 16/16 on the same cases. Details: https://jrobineau.com/fr/blog/2026-11-04-ai-agent-guardrail-let-rm-rf-through.html
