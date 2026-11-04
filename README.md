# agent-skills

Small skills for coding agents (Claude Code, Codex, and any agent that reads a `SKILL.md`).
Each one comes from a problem I hit on my own machine, and ships with the number that made me
write it. They come out one at a time, announced first on
[LinkedIn](https://www.linkedin.com/in/jules-robineau-paris/).

| Skill | What it does | The number |
|---|---|---|
| [guardrail-bench](skills/guardrail-bench/) | Scores a guardrail hook against 17 destructive and 16 everyday commands, without running any of them | My regex hook blocked 4 destructive commands out of 17 and stopped 5 everyday ones out of 16. Its replacement: 17 out of 17, 16 out of 16 |

Plus one hook, [hooks/deny-power-commands.sh](hooks/deny-power-commands.sh): 57 lines that
deny the commands that switch the machine off or restart it, only in command position, with
31 built-in test cases (`--test`). It is the model for "a hook that carries its own bench".

## Install

Claude Code, as a plugin (the skill and the hook together):

```
/plugin marketplace add JulesRobineau/agent-skills
/plugin install agent-skills@jrobineau
```

Or in one step: `/plugin install agent-skills --marketplace JulesRobineau/agent-skills`.

With the skills CLI (Claude Code, Codex, Cursor and the other agents it knows), the skill
only, without the hook:

```bash
npx skills add JulesRobineau/agent-skills
```

Any agent, by copying the folder:

```bash
git clone https://github.com/JulesRobineau/agent-skills.git
cp -r agent-skills/skills/guardrail-bench ~/.claude/skills/     # Claude Code, every project
cp -r agent-skills/skills/guardrail-bench .claude/skills/       # Claude Code, this project only
cp -r agent-skills/skills/guardrail-bench .agents/skills/       # Codex
```

The scripts need bash and jq. Nothing else.

## guardrail-bench

A guardrail is code, so it is tested like code: a list to block, a list to let through, two
scores. The hook receives each command as text on stdin, the way Claude Code sends it before
a Bash call. Nothing is executed.

```bash
cd skills/guardrail-bench
./bench.sh cases.txt -- node ~/.claude/scripts/cc-safety-net/node_modules/cc-safety-net/dist/bin/cc-safety-net.js hook --coding-cli
```

Measured on 4 November 2026 with the shipped `cases.txt`:

| Guardrail | Destructive blocked | Everyday allowed |
|---|---|---|
| cc-safety-net 2.5.1, level Standard | 16 / 17 | 16 / 16 |

The one miss is `chmod -R 777 /`, a permissions change, not a deletion. The bench told me, which
is the point. On my own October bench (same shape, my own 33 cases), my old regex hook scored
4/17 and 11/16, cc-safety-net 17/17 and 16/16. The cases file is yours to edit: add the
commands your agents run every day and the variants a regex forgets.

## Where the numbers come from

- [My AI agent guardrail let rm -rf ~ through](https://jrobineau.com/fr/blog/2026-11-04-ai-agent-guardrail-let-rm-rf-through.html) (4 November 2026)

## Licence

MIT. Jules Robineau, freelance Go developer and DevSecOps engineer, Paris.
[jrobineau.com](https://jrobineau.com) · [LinkedIn](https://www.linkedin.com/in/jules-robineau-paris/)
