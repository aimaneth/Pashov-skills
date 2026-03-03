# audit

For **Solidity developers** who want fast security feedback while developing or before committing. Not a replacement for a formal audit, but the check you should run every time you touch a contract.

## Usage

```bash
# Scan the full repo (default)
/audit

# Review only changed files
/audit diff

# Full repo + adversarial reasoning agent (slower, more thorough)
/audit deep

# Review specific file(s)
/audit src/Vault.sol
/audit src/Vault.sol src/Router.sol

# Write report to a markdown file (terminal-only by default)
/audit --file-output
```

## What it does

- **Default mode**: scans all `.sol` files in the repo (excludes `interfaces/`, `lib/`, `mocks/`, `*.t.sol`, `*Test*.sol`, `*Mock*.sol`)
- **diff mode**: runs `git diff HEAD` and reviews only the `.sol` files you've changed
- **deep mode**: same scope as default, but adds an adversarial reasoning agent (Opus) alongside the vector scanners
- **File mode**: reviews one or more contracts you specify

Every run spawns 4 parallel scanning agents, each armed with a subset of 170 attack vectors covering reentrancy, access control, token standards, flash loans, integer issues, and more. Each agent triages its vectors against the codebase, then deep-analyzes only the survivors. Findings below the confidence threshold (75) are listed in the summary table but get no fix block. With `--file-output`, the full report is saved to `assets/findings/`.

## Why deep mode

In deep mode, a fifth agent (Opus) reasons adversarially from first principles — no checklist, just "find every way to steal funds, lock funds, grief users, or break invariants." It costs more tokens and can take more time, but consistently finds vulnerabilities that the vector scanners miss. Use it for pre-commit reviews on critical code or when preparing for a formal audit.

## Performance & Token Spend

Most runs complete in 3–5 minutes. Wall-clock is determined by the slowest agent, not the sum of all agents.

Expect ~100k–250k tokens depending on scope (200–2,000 lines of Solidity). DEEP mode adds ~25-30% on top. Token spend scales with the number of in-scope files — each scanning agent reads every file, so a single-file review will use significantly fewer tokens.

## Limitations

**Codebase size.** Each agent reads all in-scope code in a single pass, then analyzes from memory — no re-reads. This works well up to ~2,500 lines of Solidity, where triage and recall are near-lossless. Past that threshold, two things degrade: the agent's ability to remember whether a specific pattern exists in the code (triage accuracy), and its attention to code in the middle of the bundle (mid-context recall). At ~5,000 lines both drop noticeably — triage misclassifies ~15-20% of vectors, and details in mid-bundle files get less scrutiny than files at the start or end. For large codebases, run the skill on logical chunks (per module or contract group) rather than everything at once.
