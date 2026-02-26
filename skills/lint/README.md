# lint

Cleans up Solidity code without touching logic. Runs nine passes covering formatting, unused code, naming, visibility, custom errors, calldata optimization, magic numbers, declaration ordering, and NatSpec - then reports exactly what changed and why.

## What it fixes

| Pass | What gets cleaned |
|---|---|
| **Imports** | Bare imports replaced with named imports; unused imports removed |
| **Unused code** | Unused variables, parameters, events, errors, modifiers, private functions |
| **Naming** | PascalCase for types/events/errors, camelCase for functions/vars, `_camelCase` for private/internal, `UPPER_CASE` for constants and immutables, `I` prefix for interfaces |
| **Visibility** | Explicit visibility added everywhere it's missing; principle of least privilege applied |
| **Custom errors** | `require(cond, "string")` converted to `error CustomError()` + `revert` |
| **Calldata** | `memory` changed to `calldata` on external function params that aren't modified |
| **Magic numbers** | Unexplained literals extracted to named `constant`s; Solidity units (`7 days`, `1 ether`) used where applicable |
| **Ordering** | Contract members reordered to match the official Solidity style guide |
| **NatSpec** | Missing `@notice`, `@param`, `@return` added to external/public functions, contracts, events, errors |

## Usage

```
/lint                      # lint changed files (git diff)
/lint src/Vault.sol        # lint a specific file
/lint ALL                  # lint the entire repo
```

Runs `forge fmt` first if Foundry is detected, then applies the remaining passes on top.

## Output

A per-file summary of every change made, grouped by pass. No changes means the file is already clean - it says so explicitly rather than printing an empty list.

For security vulnerability scanning, see [`audit`](../audit/).
