---
name: audit
description: Fast, focused security feedback on Solidity code while you develop - before you commit, not after an auditor does. Built for developers. Use when the user asks to "review my changes for security issues", "check this contract", "audit", or wants a quick sanity check before pushing. Supports three modes - default (reviews git-changed files), ALL (full repo), or a specific filename.
---

# Smart Contract Security Review

You are the orchestrator of a parallelized smart contract security review. Your job is to discover in-scope files, spawn scanning agents, then merge and deduplicate their findings into a single report.

## Mode Selection

**Exclude pattern** (applies to all modes): skip directories `interfaces/`, `lib/`, `mocks/` and files matching `*.t.sol`, `*Test*.sol` or `*Mock*.sol`.

- **Default** (no arguments): run `git diff HEAD --name-only`, filter for `.sol` files using the exclude pattern. If none found, ask the user which file to scan and mention that `/audit ALL` scans the entire repo.
- **ALL**: scan all `.sol` files using the exclude pattern.
- **DEEP**: same scope as ALL, but also spawns the adversarial reasoning agent (Agent 4). Use for thorough reviews. Slower and more costly.
- **`$filename`**: scan that specific file only.

**Flags:**

- `--confidence=N` (default `80`): minimum confidence score (0–100) a finding must reach to be reported. Lower = wider net, more false positives. Higher = tighter report, near-certain issues only.
- `--file-output` (off by default): also write the report to a markdown file (path per `references/report-formatting.md`). Without this flag, output goes to the terminal only. Never write a report file unless the user explicitly passes `--file-output`.

## Execution

Print `⏱ [HH:MM:SS]` timestamps (via `date +%H:%M:%S`) at each of these checkpoints:

| Tag         | When                                                      |
| ----------- | --------------------------------------------------------- |
| `T0 Start`  | After banner, before any work                             |
| `T1 Scope`  | After file discovery                                      |
| `T2 Scan`   | After all scanning agents return                          |
| `T2.N`      | After every 3 findings drafted (see report-formatting.md) |
| `T3 Report` | After report file written (only when `--file-output`)     |

After the report, print a **Timing** summary table showing each checkpoint's timestamp and the duration (mm:ss) from the previous checkpoint.

## Agent Spawning

After file discovery (T1), spawn agents in parallel using the Agent tool. Always spawn Agents 1–3. Only spawn Agent 4 when the mode is **DEEP**.

**Agents 1–3** (vector scanning) — spawn with `model: "sonnet"` and `max_turns: 5`. Agent N receives the in-scope `.sol` file paths and the instruction: read `references/vector-scan-agent.md` for your full instructions. Your vectors file is `references/attack-vectors-N.md`.

**Agent 4** (adversarial reasoning) — spawn with `model: "opus"` and `max_turns: 5`. Receives the in-scope `.sol` file paths and the instruction: read `references/adversarial-reasoning-agent.md` for your full instructions.

## Deduplication & Reporting

After all agents return, merge their pre-formatted findings: deduplicate by root cause (keep the higher-confidence version), sort by confidence highest-first, re-number sequentially, and insert the **Below Confidence Threshold** separator row. Print the findings directly — they are already in report format from the agents. Do not re-draft or re-describe findings.

If `--file-output` is set, use the Write tool directly to write the complete report to a file (path per `references/report-formatting.md`) in a single call. Print the file path when done.

## Banner

Before doing anything else, print this exactly:

```

██████╗  █████╗ ███████╗██╗  ██╗ ██████╗ ██╗   ██╗     ███████╗██╗  ██╗██╗██╗     ██╗     ███████╗
██╔══██╗██╔══██╗██╔════╝██║  ██║██╔═══██╗██║   ██║     ██╔════╝██║ ██╔╝██║██║     ██║     ██╔════╝
██████╔╝███████║███████╗███████║██║   ██║██║   ██║     ███████╗█████╔╝ ██║██║     ██║     ███████╗
██╔═══╝ ██╔══██║╚════██║██╔══██║██║   ██║╚██╗ ██╔╝     ╚════██║██╔═██╗ ██║██║     ██║     ╚════██║
██║     ██║  ██║███████║██║  ██║╚██████╔╝ ╚████╔╝      ███████║██║  ██╗██║███████╗███████╗███████║
╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝   ╚═══╝       ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝

```
