# agent-hooks

Small skills and hooks for coding agents (Claude Code, Codex, and any agent that reads a `SKILL.md`).
Each one comes from a problem I hit on my own machine, and ships with the number that made me
write it. They come out one at a time, announced first on
[LinkedIn](https://www.linkedin.com/in/jules-robineau-paris/).

| Skill | What it does | The number |
|---|---|---|
| [guardrail-bench](skills/guardrail-bench/) | Scores a guardrail hook against 17 destructive and 16 everyday commands, without running any of them | My regex hook blocked 4 destructive commands out of 17 and stopped 5 everyday ones out of 16. Its replacement: 17 out of 17, 16 out of 16 |

Plus one hook, [hooks/deny-destructive-commands.sh](hooks/deny-destructive-commands.sh): a
PreToolUse hook in bash that reads each command the way the shell does and denies the destructive
ones. It scores 17/17 and 16/16 on the bench, carries 191 test cases of its own (`--test`), and
let every one of the 312 real commands of one working session through.

## Install

Claude Code, as a plugin (the skill and the hook together):

```
/plugin marketplace add JulesRobineau/agent-hooks
/plugin install agent-hooks@jrobineau
```

Or in one step: `/plugin install agent-hooks --marketplace JulesRobineau/agent-hooks`.

With the skills CLI (Claude Code, Codex, Cursor and the other agents it knows), the skill
only, without the hook:

```bash
npx skills add JulesRobineau/agent-hooks
```

Any agent, by copying the folder:

```bash
git clone https://github.com/JulesRobineau/agent-hooks.git
cp -r agent-hooks/skills/guardrail-bench ~/.claude/skills/     # Claude Code, every project
cp -r agent-hooks/skills/guardrail-bench .claude/skills/       # Claude Code, this project only
cp -r agent-hooks/skills/guardrail-bench .agents/skills/       # Codex
```

The scripts need bash and jq. Nothing else.

## guardrail-bench

A guardrail is code, so it is tested like code: a list to block, a list to let through, two
scores. The hook receives each command as text on stdin, the way Claude Code sends it before
a Bash call. Nothing is executed.

```bash
cd skills/guardrail-bench
./bench.sh cases.txt -- bash ../../hooks/deny-destructive-commands.sh
./bench.sh cases.txt -- node ~/.claude/scripts/cc-safety-net/node_modules/cc-safety-net/dist/bin/cc-safety-net.js hook --coding-cli
```

Measured on 8 November 2026 with the shipped `cases.txt`:

| Guardrail | Destructive blocked | Everyday allowed |
|---|---|---|
| hooks/deny-destructive-commands.sh (this repository) | 17 / 17 | 16 / 16 |
| cc-safety-net 2.5.1, level Standard | 16 / 17 | 16 / 16 |

cc-safety-net's one miss is `chmod -R 777 /`, a permissions change, not a deletion. The bench
told me, which is the point. On my own October bench (same shape, my own 33 cases), my old regex
hook scored 4/17 and 11/16, cc-safety-net 17/17 and 16/16. A hook that passes its author's list
has passed its author's list, nothing more. The cases file is yours to edit: add the commands
your agents run every day and the variants a regex forgets.

## deny-destructive-commands

The hook does not look for words. It splits the command like a shell: words outside quotes,
segments at `;`, `&&`, `||`, `|`, `&`, newlines, `( )`, `{ }`, backticks and `$( )`. It skips
heredoc bodies and comments, peels `sudo`, `env`, `nohup`, `timeout`, `nice`, `bash -c "..."`,
`eval` and `su -c`, remembers the assignments made in the same command (`W=~; rm -rf $W` is
caught) and resolves relative paths against the directory the agent works in (`rm -rf .` is
denied in your home, allowed in a project). `rm -rf` inside a commit message, a grep pattern or
an echo is text, not a command, and passes.

What it denies, with the reason sent back to the agent so it changes approach on its own:

| Family | Denied |
|---|---|
| power | `shutdown`, `poweroff`, `halt`, `reboot`, `systemctl` or `loginctl` poweroff, reboot, halt, kexec, `init 0`, `init 6` |
| rm | `rm -r` on `/`, the home directory, a top-level folder of the home directory (`~/.ssh`, `~/projects`), a system directory (`/etc`, `/usr`, `/var`...), `--no-preserve-root` |
| find, mv | `find -delete` or `-exec rm` on one of those paths, `mv` of one of those paths |
| permissions | `chmod`, `chown` or `chgrp -R` on one of those paths, `chmod` on `/` itself |
| disks | `dd of=/dev/<disk>`, `mkfs*`, `mkswap`, `wipefs`, `blkdiscard`, `shred /dev/...`, a partition editor without `-l`, a redirection into `/dev/<disk>` |
| git | `push --force`, `-f` or `+ref` (`--force-with-lease` passes), `reset --hard`, `clean -f` (a dry run passes), `checkout .` and `restore .` |
| misc | `curl` or `wget` piped into a shell, `kill ... -1`, `crontab -r`, the fork bomb |

Try it on one command:

```bash
bash hooks/deny-destructive-commands.sh --check 'rm -rf ~'
# deny: rm -r on the home directory
bash hooks/deny-destructive-commands.sh --check 'git commit -m "remove rm -rf from the build script"'
# allow
bash hooks/deny-destructive-commands.sh --test
# all 191 cases pass
```

Known holes, on purpose and written at the top of the script: a path hidden in a variable set in
an earlier command, a deletion done by another program (`python3 -c "shutil.rmtree(...)"`), `rm`
fed by `xargs`. Git and a backup the agent cannot reach are the safety net for those. 714 lines
of bash, 191 of them test cases. It needs bash 3.2 and jq.

To use it outside the plugin, add it to `~/.claude/settings.json`:

```json
"PreToolUse": [{ "matcher": "Bash", "hooks": [{ "type": "command", "command": "bash /path/to/hooks/deny-destructive-commands.sh" }] }]
```

## Where the numbers come from

- [My AI agent guardrail let rm -rf ~ through](https://jrobineau.com/fr/blog/2026-11-04-ai-agent-guardrail-let-rm-rf-through.html) (4 November 2026)

## Licence

MIT. Jules Robineau, freelance Go developer and DevSecOps engineer, Paris.
[jrobineau.com](https://jrobineau.com) · [LinkedIn](https://www.linkedin.com/in/jules-robineau-paris/)
