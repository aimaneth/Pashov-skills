# Attack Vectors Reference (1/5)

170 total attack vectors. For each: detection pattern and false-positive signals.

---

**1. Precision Loss - Division Before Multiplication**

- **D:** `(a / b) * c` — truncation before multiplication amplifies error. E.g., `fee = (amount / 10000) * bps`. Correct: `(a * c) / b`.
- **FP:** `a` provably divisible by `b` (enforced by `require(a % b == 0)` or mathematical construction).

**2. DVN Collusion or Insufficient DVN Diversity**

- **D:** OApp configured with a single DVN (`1/1/1` security stack) or multiple DVNs controlled by the same entity / using the same underlying verification method. Compromising one entity approves fraudulent cross-chain messages. Pattern: `setConfig` with `requiredDVNCount = 1` and no optional DVNs.
- **FP:** Diverse DVN set (e.g., Google Cloud DVN + Axelar Adapter + protocol's own DVN) with `2/3+` threshold. DVNs use independent verification methods (light client, oracle, ZKP). Protocol runs its own required DVN.

**3. Missing or Incorrect Access Modifier**

- **D:** State-changing function (`setOwner`, `withdrawFunds`, `mint`, `pause`, `setOracle`) has no access guard or modifier references uninitialized variable. `public`/`external` on privileged operations with no restriction.
- **FP:** Function is intentionally permissionless with non-critical worst-case outcome (e.g., advancing a public time-locked process).

**4. Delegate Privilege Escalation**

- **D:** `setDelegate()` appoints an address that can manage OApp configurations including DVNs, Executors, message libraries, and can skip/clear payloads. If delegate is set to an insecure address (EOA, unrelated contract) or differs from owner without governance controls, the delegate can silently reconfigure the OApp's entire security stack.
- **FP:** Delegate == owner. Delegate is a governance timelock or multisig. `setDelegate` protected by the same access controls as `setPeer`.

**5. Missing `enforcedOptions` — Insufficient Gas for lzReceive**

- **D:** OApp does not call `setEnforcedOptions()` to mandate minimum gas for destination execution. User-supplied `_options` can specify insufficient gas, causing `lzReceive` to revert on destination. Funds debited on source but not credited on destination — stuck in limbo until manual recovery via `lzComposeAlert` or `skipPayload`.
- **FP:** `enforcedOptions` configured with tested gas limits for each message type. `lzReceive` logic is simple (single mapping update) requiring minimal gas. Executor provides guaranteed minimum gas.

**6. Paymaster Gas Penalty Undercalculation**

- **D:** Paymaster prefund formula omits 10% EntryPoint penalty on unused execution gas (`postOpUnusedGasPenalty`). Large `executionGasLimit` with low usage drains paymaster deposit.
- **FP:** Prefund explicitly adds unused-gas penalty. Conservative overestimation covers worst case.

**7. Free Memory Pointer Corruption**

- **D:** Assembly block writes to memory at fixed offsets (e.g., `mstore(0x80, val)`) without reading or updating the free memory pointer at `0x40`. Subsequent Solidity code allocates memory from stale pointer, overwriting the assembly-written data — or vice versa. Second pattern: assembly sets `mstore(0x40, newPtr)` to an incorrect value, causing later Solidity allocations to overlap prior data.
- **FP:** Assembly block reads `mload(0x40)`, writes only above that offset, then updates `mstore(0x40, newFreePtr)`. Or block only uses scratch space (`0x00`–`0x3f`). Block annotated `memory-safe` and verified to comply. Ref: Solidity optimizer bug in 0.8.13–0.8.14 mishandled cross-block memory writes.

**8. Non-Atomic Proxy Deployment Enabling CPIMP Takeover**

- **D:** Same non-atomic deploy+init pattern as V76, but attacker inserts malicious middleman implementation (CPIMP) that persists across upgrades by restoring itself in ERC-1967 slot.
- **FP:** Atomic init calldata in constructor. `_disableInitializers()` in implementation constructor.

**9. Cross-Chain Reentrancy via Safe Transfer Callbacks**

- **D:** Cross-chain receive function (`lzReceive`, `_credit`) calls `_safeMint` or `_safeTransfer` before updating supply/ownership counters. The `onERC721Received` / `onERC1155Received` callback re-enters to initiate another cross-chain send before state is finalized, creating duplicate tokens or double-spending.
- **FP:** State updates (counters, balances) committed before any safe transfer. `nonReentrant` on receive path. `_mint` used instead of `_safeMint` (no callback). Ref: Ackee Blockchain cross-chain reentrancy PoC.

**10. Flash Loan-Assisted Price Manipulation**

- **D:** Function reads price from on-chain source (AMM reserves, vault `totalAssets()`) manipulable atomically via flash loan + swap in same tx.
- **FP:** TWAP with >= 30min window. Multi-block cooldown between price reads. Separate-block enforcement.

---

**11. Arbitrary External Call with User-Supplied Target and Calldata**

- **D:** `target.call{value: v}(data)` where `target` or `data` (or both) are caller-supplied parameters. Attacker crafts calldata to invoke unintended functions on the target (e.g., `transferFrom` on an approved ERC20, or `safeTransferFrom` on held NFTs), stealing assets the contract holds or has approvals for.
- **FP:** Target restricted to hardcoded/whitelisted address. Calldata function selector restricted to known-safe set. No token approvals or asset holdings on the calling contract. `delegatecall` vector covered separately (V58/V105); this covers `call`.

**12. Missing chainId (Cross-Chain Replay)**

- **D:** Signed payload omits `chainId`. Valid signature replayable on forks/other EVM chains. Or `chainId` hardcoded at deployment instead of `block.chainid`.
- **FP:** EIP-712 domain separator includes dynamic `chainId: block.chainid` and `verifyingContract`.

**13. Deployer Privilege Retention Post-Deployment**

- **D:** Deployer EOA retains owner/admin/minter/pauser/upgrader after deployment script completes. Pattern: `Ownable` sets `owner = msg.sender` with no `transferOwnership()`. `AccessControl` grants `DEFAULT_ADMIN_ROLE` to deployer with no `renounceRole()`.
- **FP:** Script includes `transferOwnership(multisig)`. Admin role granted to timelock/governance, deployer renounces. `Ownable2Step` with pending owner set to multisig.

**14. extcodesize Zero in Constructor**

- **D:** `require(msg.sender.code.length == 0)` as EOA check. Contract constructors have `extcodesize == 0` during execution, bypassing the check.
- **FP:** Check is non-security-critical. Function protected by merkle proof, signed permit, or other mechanism unsatisfiable from constructor.

**15. Self-Liquidation Profit Extraction**

- **D:** Borrower liquidates their own undercollateralized position from a second address, collecting the liquidation bonus/discount on their own collateral. Profitable whenever liquidation incentive exceeds the cost of being slightly undercollateralized.
- **FP:** `require(msg.sender != borrower)` on liquidation. Liquidation penalty exceeds any collateral bonus. Liquidation incentive is small enough that self-liquidation is net-negative after gas.

**16. Spot Price Oracle from AMM**

- **D:** Price from AMM reserves: `reserve0 / reserve1`, `getAmountsOut()`, `getReserves()`. Flash-loan exploitable atomically.
- **FP:** TWAP >= 30 min window. Chainlink/Pyth as primary source.

**17. ERC4626 Preview Rounding Direction Violation**

- **D:** `previewDeposit` returns more shares than `deposit` mints, or `previewMint` charges fewer assets than `mint`. Custom `_convertToShares`/`_convertToAssets` with wrong `Math.mulDiv` rounding direction.
- **FP:** OZ ERC4626 base without overriding conversion functions. Custom impl explicitly uses `Floor` for share issuance, `Ceil` for share burning.

**18. ecrecover Returns address(0) on Invalid Signature**

- **D:** Raw `ecrecover` without `require(recovered != address(0))`. If `authorizedSigner` is uninitialized or `permissions[address(0)]` is non-zero, garbage signature gains privileges.
- **FP:** OZ `ECDSA.recover()` used (reverts on address(0)). Explicit zero-address check present.

**19. Signature Malleability**

- **D:** Raw `ecrecover` without `s <= 0x7FFF...20A0` validation. Both `(v,r,s)` and `(v',r,s')` recover same address. Bypasses signature-based dedup.
- **FP:** OZ `ECDSA.recover()` used (validates `s` range). Message hash used as dedup key, not signature bytes.

**20. Immutable / Constructor Argument Misconfiguration**

- **D:** Constructor sets `immutable` values (admin, fee, oracle, token) that can't change post-deploy. Multiple same-type `address` params where order can be silently swapped. No post-deploy verification.
- **FP:** Deployment script reads back and asserts every configured value. Constructor validates: `require(admin != address(0))`, `require(feeBps <= 10000)`.

---

**21. Missing or Expired Deadline on Swaps**

- **D:** `deadline = block.timestamp` (always valid), `deadline = type(uint256).max`, or no deadline. Tx holdable in mempool indefinitely.
- **FP:** Deadline is calldata parameter validated as `require(deadline >= block.timestamp)`, not derived from `block.timestamp` internally.

**22. ERC777 tokensToSend / tokensReceived Reentrancy**

- **D:** Token `transfer()`/`transferFrom()` called before state updates on a token that may implement ERC777 (ERC1820 registry). ERC777 hooks fire on ERC20-style calls, enabling reentry from sender's `tokensToSend` or recipient's `tokensReceived`.
- **FP:** CEI — all state committed before transfer. `nonReentrant` on all entry points. Token whitelist excludes ERC777.

**23. Missing `_debit` / `_debitFrom` Authorization in OFT**

- **D:** Custom OFT override of `_debit` or `_debitFrom` omits `require(msg.sender == _from || allowance[_from][msg.sender] >= amount)`. Anyone can bridge tokens from any holder's balance. Pattern: `_debit` that calls `_burn(_from, amount)` without verifying caller is authorized.
- **FP:** Standard LayerZero OFT implementation used without override. Custom `_debit` includes proper authorization. `_debit` only callable via `send()` which uses `msg.sender` as `_from`.

**24. Slippage Enforced at Intermediate Step, Not Final Output**

- **D:** Multi-hop swap checks `minAmountOut` on the first hop or an intermediate step, but the amount actually received by the user at the end of the pipeline has no independent slippage bound. Second/third hops can be sandwiched freely.
- **FP:** `minAmountOut` validated against the user's final received balance (delta check). Single-hop swap. User specifies per-hop minimums.

**25. Flash Loan Governance Attack**

- **D:** Voting uses `token.balanceOf(msg.sender)` or `getPastVotes(account, block.number)` (current block). Borrow tokens, vote, repay in one tx.
- **FP:** `getPastVotes(account, block.number - 1)` used. Timelock between snapshot and vote.

**26. Scratch Space Corruption Across Assembly Blocks**

- **D:** Data written to scratch space (`0x00`–`0x3f`) in one assembly block is expected to persist and be read in a later assembly block, but intervening Solidity code (or compiler-generated code for `keccak256`, `abi.encode`, etc.) overwrites scratch space between the two blocks. Pattern: `mstore(0x00, key); mstore(0x20, slot)` in block A, then `keccak256(0x00, 0x40)` in block B with Solidity statements between them.
- **FP:** All scratch space reads occur within the same contiguous assembly block as the writes. Developer explicitly rewrites scratch space before each use. No intervening Solidity code between blocks.

**27. ERC-1271 isValidSignature Delegated to Untrusted Module**

- **D:** `isValidSignature(hash, sig)` delegated to externally-supplied contract without whitelist check. Malicious module always returns `0x1626ba7e`, passing all signature checks.
- **FP:** Delegation only to owner-controlled whitelist. Module registry has timelock/guardian approval.

**28. ERC4626 Deposit/Withdraw Share-Count Asymmetry**

- **D:** `_convertToShares` uses `Rounding.Floor` for both deposit and withdraw paths. `withdraw(a)` burns fewer shares than `deposit(a)` minted, manufacturing free shares. Single rounding helper called on both paths without distinct rounding args.
- **FP:** `deposit` uses `Floor`, `withdraw` uses `Ceil` (vault-favorable both directions). OZ ERC4626 without custom conversion overrides.

**29. ERC4626 Inflation Attack (First Depositor)**

- **D:** `shares = assets * totalSupply / totalAssets`. When `totalSupply == 0`, deposit 1 wei + donate inflates share price, victim's deposit rounds to 0 shares. No virtual offset.
- **FP:** OZ ERC4626 with `_decimalsOffset()`. Dead shares minted to `address(0)` at init.

**30. Non-Atomic Proxy Initialization (Front-Running `initialize()`)**

- **D:** Proxy deployed in one tx, `initialize()` called in separate tx. Uninitialized proxy front-runnable. Pattern: `new TransparentUpgradeableProxy(impl, admin, "")` with empty data, separate `initialize()`. Ref: Wormhole (2022).
- **FP:** Proxy constructor receives init calldata atomically: `new TransparentUpgradeableProxy(impl, admin, abi.encodeCall(...))`. OZ `deployProxy()` used.

---

**31. Zero-Amount Transfer Revert**

- **D:** `token.transfer(to, amount)` where `amount` can be zero (rounded fee, unclaimed yield). Some tokens (LEND, early BNB) revert on zero-amount transfers, DoS-ing distribution loops.
- **FP:** `if (amount > 0)` guard before all transfers. Minimum claim amount enforced. Token whitelist verified to accept zero transfers.

**32. ERC721Enumerable Index Corruption on Burn or Transfer**

- **D:** Override of `_beforeTokenTransfer` (OZ v4) or `_update` (OZ v5) without calling `super`. Index structures (`_ownedTokens`, `_allTokens`) become stale — `tokenOfOwnerByIndex` returns wrong IDs, `totalSupply` diverges.
- **FP:** Override always calls `super` as first statement. Contract doesn't inherit `ERC721Enumerable`.

**33. Small Positions Unliquidatable Due to Insufficient Incentive (Bad Debt)**

- **D:** Positions below a certain USD value cost more gas to liquidate than the liquidation reward. During market downturns, these "dust positions" accumulate bad debt that no liquidator will process, eroding protocol solvency.
- **FP:** Minimum position size enforced at borrow time. Protocol-operated liquidation bot covers dust positions. Socialized bad debt mechanism (insurance fund, haircuts).

**34. ERC1155 safeBatchTransferFrom Unchecked Array Lengths**

- **D:** Custom `_safeBatchTransferFrom` iterates `ids`/`amounts` without `require(ids.length == amounts.length)`. Assembly-optimized paths may silently read uninitialized memory.
- **FP:** OZ ERC1155 base used unmodified. Custom override asserts equal lengths as first statement.
