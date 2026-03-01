# Attack Vectors Reference (2/3 — Vectors 45–88)

133 total attack vectors. For each: detection pattern (what to look for in code) and false-positive signals (what makes it NOT a vulnerability even if the pattern matches).

---

**45. Missing Storage Gap in Upgradeable Base Contract**

- **Detect:** Upgradeable base contract has no `uint256[N] private __gap;` at the end. A future version adding state variables to the base shifts the derived contract's storage layout, overwriting existing variables.
- **FP:** EIP-1967 namespaced storage slots used for all variables in the base contract. Single-contract (non-inherited) implementation where new variables can only be appended safely.

**46. Missing `_disableInitializers()` on Implementation Contract**

- **Detect:** The implementation contract behind a proxy does not call `_disableInitializers()` in its constructor. Even when the proxy is properly initialized, the implementation contract itself remains directly callable. An attacker calls `initialize()` on the implementation address (not the proxy), becomes its owner, then calls `upgradeTo()` to point it at a malicious contract containing `selfdestruct`. If the proxy delegates to this now-destroyed implementation, all calls to the proxy revert — bricking the system. This is exactly how the Wormhole whitehat exploit worked: the attacker initialized the implementation, became guardian, upgraded to a `selfdestruct` contract, and destroyed the bridge's implementation. Pattern: implementation contract inherits `Initializable` but its constructor is empty or missing. No `/// @custom:oz-upgrades-unsafe-allow constructor` + `_disableInitializers()` pair.
- **FP:** Constructor contains `_disableInitializers()`: `constructor() { _disableInitializers(); }`. Implementation uses the `@custom:oz-upgrades-unsafe-allow constructor` annotation with an explicit disable call. Contract is not behind a proxy (standalone deployment).

**47. Diamond Proxy Cross-Facet Storage Collision**

- **Detect:** EIP-2535 Diamond proxy where two or more facets declare storage variables without EIP-7201 namespaced storage structs — each facet using plain `uint256 foo` or `mapping(...)` declarations that Solidity places at sequential storage slots 0, 1, 2, …. Different facets independently start at slot 0, so both write to the same slot. Also flag: facet uses a library that writes to storage without EIP-7201 namespacing.
- **FP:** All facets store state exclusively in a single `DiamondStorage` struct retrieved via `assembly { ds.slot := DIAMOND_STORAGE_POSITION }` using a namespaced position (EIP-7201 formula). No facet declares top-level state variables. OpenZeppelin's ERC-7201 `@custom:storage-location` pattern used correctly.

**48. Force-Feeding ETH via selfdestruct or coinbase**

- **Detect:** Business logic relies on `address(this).balance` for invariant checks, share/deposit accounting, or as a denominator: `require(address(this).balance == trackingVar)`, `shares = msg.value * totalSupply / address(this).balance`. ETH can be force-sent without triggering `receive()`/`fallback()` via: (1) `selfdestruct(payable(target))` — even if target has no payable functions; (2) pre-deployment: computing a contract's deterministic address and sending ETH before it is deployed; (3) being set as the `coinbase` address for a mined block. Forced ETH inflates the balance above expected values, breaking any invariant or ratio built on it.
- **FP:** All accounting uses a private `uint256 _deposited` variable incremented only inside payable functions — never `address(this).balance`. `address(this).balance` appears only in informational view functions, not in guards or financial math.

**49. UUPS `_authorizeUpgrade` Missing Access Control**

- **Detect:** UUPS implementation overrides `_authorizeUpgrade()` but the override body is empty or has no access-control modifier (`onlyOwner`, `onlyRole`, etc.). Anyone can call `upgradeTo()` on the proxy and replace the implementation with arbitrary code. Pattern: `function _authorizeUpgrade(address) internal override {}` with no restriction. Real-world: CVE-2021-41264 -- >$50M at risk across KeeperDAO, Rivermen NFT, and others.
- **FP:** `_authorizeUpgrade()` has `onlyOwner` or equivalent modifier. OpenZeppelin `UUPSUpgradeable` base used, which forces the override. Multi-sig or governance controls the owner role.

**50. Multi-Block TWAP Oracle Manipulation**

- **Detect:** Protocol uses a Uniswap V2 or V3 TWAP with an observation window shorter than 30 minutes (~150 blocks). Post-Merge PoS validators who are elected to propose consecutive blocks can hold an AMM pool in a manipulated state across multiple blocks with no flash-loan repayment pressure. Each held block contributes a manipulated price sample to the TWAP accumulator. With short windows (e.g., 5–10 minutes), controlling 2–3 consecutive blocks shifts the TWAP enough to trigger profitable liquidations or over-collateralized borrows. Cost: only the capital to move the pool, held for a few blocks — far cheaper than equivalent single-block manipulation.
- **FP:** TWAP window ≥ 30 minutes. Chainlink or Pyth used as the price source instead of AMM TWAP. Protocol uses max-deviation circuit breaker that rejects price updates deviating more than X% from a secondary source.

**51. Paymaster ERC-20 Payment Deferred to postOp Without Pre-Validation**

- **Detect:** `validatePaymasterUserOp` does not transfer tokens or lock funds — payment is deferred entirely to `postOp` via `safeTransferFrom`. Between validation and execution the user can revoke the ERC-20 allowance (or drain their balance), causing `postOp` to revert. The paymaster still owes the bundler its gas costs, losing deposit without collecting payment. Pattern: `postOp` contains `token.safeTransferFrom(user, address(this), cost)` with no corresponding lock in the validation phase.
- **FP:** Tokens are transferred or locked (e.g., via `transferFrom` into the paymaster) during `validatePaymasterUserOp` itself. `postOp` is used only to refund excess, never to collect initial payment.

**52. Deployer Privilege Retention Post-Deployment**

- **Detect:** The deployer EOA retains elevated permissions (owner, admin, minter, pauser, upgrader) after the deployment script completes. The deployer's private key — which was necessarily hot during deployment — remains a single point of failure for the entire system. If the key is compromised later, the attacker inherits all admin capabilities. Pattern: deployment script calls `new Contract()` or `initialize()` but never transfers ownership to a multisig, timelock, or governance contract. `Ownable` constructor sets `owner = msg.sender` (the deployer) and no subsequent `transferOwnership()` call exists in the script. `AccessControl` grants `DEFAULT_ADMIN_ROLE` to the deployer without a later `renounceRole()`.
- **FP:** Deployment script includes explicit ownership transfer: `contract.transferOwnership(multisig)`. Admin role is granted to a timelock or governance contract, and deployer renounces its role in the same script. Two-step ownership transfer (`Ownable2Step`) used with pending owner set to the target multisig.

**53. UUPS Upgrade Logic Removed in New Implementation**

- **Detect:** New UUPS implementation version does not inherit `UUPSUpgradeable` or removes `upgradeTo()`/`upgradeToAndCall()`. After upgrading, the proxy permanently loses upgrade capability -- no further upgrades possible, contract is bricked at current version. Pattern: V2 inherits `OwnableUpgradeable` but not `UUPSUpgradeable`; no `_authorizeUpgrade` override; `upgradeTo` function absent from V2 ABI.
- **FP:** Every implementation version inherits `UUPSUpgradeable`. Integration tests verify `upgradeTo` works after each upgrade. `@openzeppelin/upgrades` plugin upgrade safety checks used in CI.

**54. Missing Input Validation on Critical Setters**

- **Detect:** Admin functions set numeric parameters with no validation: `setFee(uint256 fee)` with no `require(fee <= MAX_FEE)`; `setOracle(address o)` with no interface check. A misconfigured call — wrong argument, value exceeding 100% — silently bricks fee collection, enables 100% fee extraction, or points the oracle to a dead address.
- **FP:** Every setter has explicit `require` bounds on all parameters. Numeric parameters validated against documented protocol constants.

**55. ERC4626 Round-Trip Profit Extraction**

- **Detect:** A full operation cycle yields strictly more than the starting amount: `redeem(deposit(a)) > a`, `deposit(redeem(s)) > s`, `mint(withdraw(a)) > a`, or `withdraw(mint(s)) > s`. Possible when rounding errors in `_convertToShares` and `_convertToAssets` both truncate in the user's favor, so no value is lost in either direction and a net gain emerges with large inputs or a manipulated share price. Combined with the first-depositor inflation attack (Vector 86), the share price can be engineered so that round-trip profit scales with the amount — enabling systematic value extraction.
- **FP:** Rounding directions satisfy EIP-4626: shares issued on deposit/mint round down (vault-favorable), shares burned on withdraw/redeem round up (vault-favorable). OpenZeppelin ERC4626 with `_decimalsOffset()` used.

**56. Return Bomb (Returndata Copy DoS)**

- **Detect:** `(bool success, bytes memory data) = target.call(payload)` where `target` is user-supplied or unconstrained. Malicious target returns huge returndata; copying it costs enormous gas.
- **FP:** Returndata not copied (`assembly { success := call(...) }` without copy, or gas-limited call). Callee is a hardcoded immutable trusted contract.

**57. ERC1155 Batch Transfer Partial-State Callback Window**

- **Detect:** Custom ERC1155 batch mint or transfer processes IDs in a loop — updating `_balances[id][to]` one ID at a time and calling `onERC1155Received` per iteration, rather than committing all balance updates first and then calling the single `onERC1155BatchReceived` hook once. During the per-ID callback, later IDs in the batch have not yet been credited. A re-entrant call from the callback can read stale balances for uncredited IDs, enabling double-counting or theft of not-yet-transferred amounts. Pattern: `for (uint i; i < ids.length; i++) { _balances[ids[i]][to] += amounts[i]; _doSafeTransferAcceptanceCheck(...); }`.
- **FP:** All balance updates for the entire batch are committed before any callback fires — mirroring OZ's approach: update all balances in one loop, then call `_doSafeBatchTransferAcceptanceCheck` once. `nonReentrant` applied to all transfer and mint entry points.

**58. ERC721 Approval Not Cleared in Custom Transfer Override**

- **Detect:** Contract overrides `transferFrom` or `safeTransferFrom` with custom logic — fee collection, royalty payment, access checks — but does not call `super._transfer()` or `super.transferFrom()` internally. OpenZeppelin's `_transfer` is the function that executes `delete _tokenApprovals[tokenId]`. Skipping it leaves the previous approved address permanently approved on the token under the new owner. Pattern: custom `transferFrom` that calls a bespoke `_transferWithFee(from, to, tokenId)` without the approval-clear step.
- **FP:** Custom override calls `super.transferFrom(from, to, tokenId)` or `super._transfer(from, to, tokenId)` internally, preserving OZ's approval clearing. Or explicitly calls `delete _tokenApprovals[tokenId]` / `_approve(address(0), tokenId, owner)` before returning.

**59. Flash Loan-Assisted Price Manipulation**

- **Detect:** A function reads price/ratio from an on-chain source (AMM reserves, vault `totalAssets()`), and that source can be manipulated atomically in the same tx via flash loan + swap. Attacker sequence: borrow → move price → call function → restore → repay.
- **FP:** Price source is TWAP with a 30-minute or longer observation window. Multi-block cooldown enforced between price reads. Function can only be called in a separate block from any state that could be manipulated.

**60. Cross-Chain Deployment Replay**

- **Detect:** A deployment transaction from one EVM chain is replayed on another chain. If the deployer EOA has the same nonce on both chains, the CREATE opcode produces the same contract address on the second chain — but now controlled by whoever replayed the transaction. The Wintermute incident demonstrated this: an attacker replayed a deployment transaction across EVM-compatible chains to gain control of the same address on multiple networks. Pattern: deployer EOA reused across chains without nonce management. Deployment transactions lack EIP-155 chain ID protection. Script deploys to multiple chains from the same EOA without verifying per-chain nonce state.
- **FP:** Deployment transactions use EIP-155 (chain ID in v value of signature). Script uses `CREATE2` with a factory already deployed at the same address on all target chains (e.g., deterministic deployment proxies). Per-chain deployer EOAs or hardware wallets with chain-specific derivation paths.

**61. extcodesize Zero / isContract Bypass in Constructor**

- **Detect:** Access control or anti-bot check uses `require(msg.sender.code.length == 0)` or assembly `extcodesize(caller())` to assert the caller is an EOA. During a contract's constructor execution, `extcodesize` of that contract's own address returns zero — no code is stored until construction finishes. An attacker deploys a contract whose constructor calls the protected function, bypassing the check. Common targets: minting limits, presale allocation caps, "no smart contracts" whitelist enforcement.
- **FP:** The check is informational only and not security-critical. The function is independently protected by a merkle-proof allowlist, signed permit, or other mechanism that cannot be satisfied inside a constructor. Protocol explicitly states and accepts on-chain contract interaction.

**62. ERC721 onERC721Received Arbitrary Caller Spoofing**

- **Detect:** Contract implements `onERC721Received` and uses its parameters (`operator`, `from`, `tokenId`) to update state — recording ownership, incrementing counters, or crediting balances — without verifying that `msg.sender` is the expected NFT contract address. Anyone can call `onERC721Received(attacker, victim, fakeTokenId, "")` directly with fabricated parameters, fooling the contract into believing it received an NFT it never got. Pattern: `function onERC721Received(...) { credited[from][tokenId] = true; }` with no `require(msg.sender == nftContract)`.
- **FP:** `msg.sender` is validated against a known NFT contract address before any state update: `require(msg.sender == address(nft))`. The function is `view` or reverts unconditionally (acts as a sink only). State changes are gated on verifiable on-chain ownership (`IERC721(msg.sender).ownerOf(tokenId) == from`) before committing.

**63. Function Selector Clash in Proxy**

- **Detect:** Proxy and implementation share a 4-byte function selector collision. A call intended for the implementation gets routed to the proxy's own function (or vice versa), silently executing the wrong logic.
- **FP:** Transparent proxy pattern used — admin calls always route to the proxy admin and user calls always delegate, so the implementation selector space is the only relevant one for users. UUPS proxy with no custom functions in the proxy shell — all calls delegate unconditionally, making selector clashes between proxy and implementation impossible.

**64. ERC1155 safeBatchTransferFrom with Unchecked Mismatched Array Lengths**

- **Detect:** Custom ERC1155 overrides `_safeBatchTransferFrom` or iterates `ids` and `amounts` arrays in a loop without first asserting `require(ids.length == amounts.length)`. A caller passes `ids = [1, 2, 3]` and `amounts = [100]` — the loop processes only as many iterations as the shorter array (Solidity reverts on OOB access in 0.8+, but a `for (uint i = 0; i < ids.length; i++)` loop that reads `amounts[i]` will revert mid-batch rather than rejecting cleanly). In assembly-optimized or unchecked implementations, the shorter array access silently reads uninitialized memory or produces wrong transfers.
- **FP:** OZ ERC1155 base used without overriding batch transfer — OZ checks `ids.length == amounts.length` at the start and reverts with `ERC1155InvalidArrayLength`. Custom override explicitly asserts equal lengths as its first statement before any transfer logic.

**65. ERC4626 Inflation Attack (First Depositor)**

- **Detect:** Vault shares math: `shares = assets * totalSupply / totalAssets`. When `totalSupply == 0`, attacker deposits 1 wei, donates large amount to vault, victim's deposit rounds to 0 shares. No virtual offset or dead shares protection.
- **FP:** OpenZeppelin ERC4626 with `_decimalsOffset()` override. Dead shares minted to `address(0)` at init.

**66. ERC1155 setApprovalForAll Grants All-Token-All-ID Operator Access**

- **Detect:** Protocol requires `setApprovalForAll(protocol, true)` to enable deposits, staking, or settlement across a user's ERC1155 holdings. Unlike ERC20 allowances (per token, per amount) or ERC721 single-token approve, ERC1155 has no per-ID or per-amount approval granularity — `setApprovalForAll` is an all-or-nothing grant covering every token ID the user holds and any they acquire in the future. A single compromised or malicious operator can call `safeTransferFrom(victim, attacker, anyId, fullBalance, "")` for every ID in one or more transactions, draining everything. Pattern: protocol documents "approve all tokens to use our platform" as a required first step.
- **FP:** Protocol uses individual `safeTransferFrom(from, to, id, amount, data)` calls that each require the user as `msg.sender` directly. Operator is a formally verified immutable contract whose only transfer logic routes tokens to the protocol's own escrow. Users are prompted to revoke approval via `setApprovalForAll(protocol, false)` after each session.

**67. Non-Atomic Proxy Initialization (Front-Running `initialize()`)**

- **Detect:** Deployment script deploys a proxy contract in one transaction and calls `initialize()` in a separate, subsequent transaction. Between these two transactions the proxy sits on-chain in an uninitialized state. An attacker monitoring the mempool sees the deployment, front-runs the `initialize()` call, and becomes the owner/admin of the proxy. This is the root cause of the Wormhole bridge vulnerability ($10M bounty) and the broader CPIMP (Clandestine Proxy In the Middle of Proxy) attack class. Pattern: `deploy(proxy)` followed by a separate `proxy.initialize(...)` call in the script rather than passing initialization calldata to the proxy constructor. In Foundry scripts, look for `new TransparentUpgradeableProxy(impl, admin, "")` with empty `data` bytes followed by a later `initialize()` call. In Hardhat, look for two separate `await` calls — one for deploy, one for initialize.
- **FP:** Proxy constructor receives initialization calldata as the third argument: `new TransparentUpgradeableProxy(impl, admin, abi.encodeCall(Contract.initialize, (...)))`. OpenZeppelin `deployProxy()` helper used, which atomically deploys and initializes. Script uses a deployer factory contract that performs deploy+init in a single on-chain transaction.

**68. ERC721Consecutive (EIP-2309) Balance Corruption with Single-Token Batch**

- **Detect:** Contract uses OpenZeppelin's `ERC721Consecutive` extension (OZ < 4.8.2) and mints a batch of exactly one token via `_mintConsecutive(to, 1)`. A bug in that version fails to increment the recipient's balance for size-1 batches. `balanceOf(to)` returns 0 despite ownership being assigned. When the owner later calls `transferFrom`, the internal balance decrement underflows (reverts in checked math, or wraps in unchecked), leaving the token in a frozen state or causing downstream accounting errors in any contract that relies on `balanceOf` for reward distribution or collateral checks.
- **FP:** OZ version ≥ 4.8.2 used (patched via GHSA-878m-3g6q-594q). Batch size is always ≥ 2. Contract uses standard `ERC721._mint` (non-consecutive) where every mint writes the balance mapping directly.

**69. Storage Layout Collision Between Proxy and Implementation**

- **Detect:** Proxy contract declares state variables (e.g. `address admin`, `address implementation`) at standard sequential slots (0, 1, ...) instead of EIP-1967 randomized slots. Implementation also declares variables starting at slot 0. Proxy's admin address is non-zero so implementation reads it as `initialized = true` (or vice versa), enabling re-initialization or corrupting owner. Pattern: custom proxy with `address public admin` at slot 0; no EIP-1967 compliance. Real-world: Audius Governance (2022, ~$6M stolen -- `proxyAdmin` added to proxy storage, shadowing `initialized` flag).
- **FP:** Proxy uses EIP-1967 slots (`keccak256("eip1967.proxy.implementation") - 1`). OpenZeppelin Transparent or UUPS proxy pattern used correctly. No state variables declared in the proxy contract itself.

**70. ERC1155 Fungible / Non-Fungible Token ID Collision**

- **Detect:** Protocol uses ERC1155 to represent both fungible tokens (specific IDs with `supply > 1`) and unique items (other IDs with intended `supply == 1`), relying only on convention rather than enforcement. No `require(totalSupply(id) == 0)` before minting an "NFT" ID, or no check that prevents minting additional copies of an ID already at supply 1. An attacker who can call the public mint function mints a second copy of an "NFT" ID, breaking uniqueness. Or role tokens (e.g., `ROLE_ID = 1`) are fungible and freely tradeable, undermining access control that is gated on `balanceOf(user, ROLE_ID) > 0`.
- **FP:** Contract explicitly enforces `require(totalSupply(id) + amount <= maxSupply(id))` with `maxSupply` set to 1 for NFT IDs at creation time. Fungible and non-fungible ranges are disjoint and enforced with `require(id < FUNGIBLE_CUTOFF || id >= NFT_START)`. Role tokens are non-transferable (transfer overrides revert for role IDs).

**71. Cross-Contract Reentrancy**

- **Detect:** Two separate contracts share logical state (e.g., balances in A, collateral check in B). A makes an external call before syncing the state B reads. A's `ReentrancyGuard` does not protect B.
- **FP:** The state B reads is synchronized before A's external call. No re-entry path exists from A's external callee back into B — verified by tracing the full call graph.

**72. msg.value Reuse in Loop / Multicall**

- **Detect:** `msg.value` read inside a loop body, or inside a `delegatecall`-based multicall where each sub-call is dispatched via `address(this).delegatecall(data[i])`. `msg.value` is a transaction-level constant — it does not decrease as ETH is "spent" within the call. Direct loop: `for (uint i = 0; i < n; i++) { deposit(msg.value); }` credits `n × msg.value` while only `msg.value` was sent. Delegatecall multicall: each sub-call inherits the original `msg.value`, so including the same payable function `n` times receives credit for `n × msg.value` with one payment.
- **FP:** `msg.value` captured into a local variable before the loop; that local is decremented per iteration and the contract enforces that total allocated equals the captured value. Function is non-payable. Multicall dispatches via `call` (not `delegatecall`), so each sub-call only receives ETH explicitly forwarded to it.

**73. Insufficient Gas Forwarding / 63/64 Rule Exploitation**

- **Detect:** Contract forwards an external call without enforcing a minimum gas budget: `target.call(data)` (no explicit gas) or `target.call{gas: userProvidedGas}(data)`. The EVM's 63/64 rule means the callee receives at most 63/64 of the remaining gas. In meta-transaction and relayer patterns, a malicious relayer provides just enough gas for the outer function to complete but not enough for the subcall to succeed. The subcall returns `(false, "")` — which the outer function may misread as a business-logic rejection, marking the user's transaction as "processed" while the actual effect never happened. Silently censors user intent while consuming their allocated gas/fee.
- **FP:** `gasleft()` validated against a minimum threshold before the subcall: `require(gasleft() >= minGas)`. Return value and return data both checked after the call. Relayer pattern uses EIP-2771 with a verified gas parameter that the recipient contract re-validates.

**74. Transient Storage Low-Gas Reentrancy (EIP-1153)**

- **Detect:** Contract uses `transfer()` or `send()` (2300-gas stipend) as its reentrancy protection, AND either the contract or a called external contract uses `transient` variables or `TSTORE`/`TLOAD` in assembly. Post-Cancun (Solidity ≥0.8.24), `TSTORE` succeeds with fewer than 2300 gas — unlike `SSTORE`, which is blocked by EIP-2200. The 2300-gas-as-reentrancy-guard assumption is broken. Second pattern: transient reentrancy lock that is not explicitly cleared at the end of the call frame. Because transient storage persists for the entire transaction (not just the call), if the contract is invoked again in the same tx (e.g., via multicall or flash loan callback), the transient lock from the first invocation is still set, causing a permanent DoS for the remainder of the tx.
- **FP:** Reentrancy protection uses an explicit `nonReentrant` modifier backed by a regular storage slot (or a correctly implemented transient mutex cleared at call end). CEI pattern followed unconditionally regardless of gas stipend. Contract does not use transient storage at all.

**75. Minimal Proxy (EIP-1167) Implementation Destruction**

- **Detect:** EIP-1167 minimal proxies (clones) permanently `delegatecall` to a fixed implementation address with no upgrade mechanism. If the implementation is destroyed (`selfdestruct` pre-Dencun) or becomes non-functional, every clone is permanently bricked -- calls return success with no effect (empty code = no-op), funds are permanently locked. Pattern: `Clones.clone(implementation)` or `Clones.cloneDeterministic(...)` where the implementation contract has no protection against `selfdestruct` or is not initialized.
- **FP:** Implementation contract has no `selfdestruct` opcode and no path to one via delegatecall. `_disableInitializers()` called in implementation constructor. Post-Dencun (EIP-6780): `selfdestruct` no longer destroys pre-existing code. Beacon proxies used instead when future upgradeability is needed.

**76. DoS via Push Payment to Rejecting Contract**

- **Detect:** ETH/token distribution in a single loop using push model (`recipient.call{value:}("")`). If any recipient reverts on receive, the entire loop reverts. Also: `transfer()`/`send()` to contracts with expensive `fallback()`. (SWC-113)
- **FP:** Pull-over-push pattern used — recipients withdraw their own funds. Loop uses `try/catch` and continues on failure.

**77. Diamond Proxy Facet Selector Collision**

- **Detect:** EIP-2535 Diamond proxy where two facets register functions with the same 4-byte selector. One facet silently shadows the other. A malicious facet added via `diamondCut` can hijack calls intended for critical functions like `withdraw()` or `transfer()`. Pattern: `diamondCut` adds a new facet whose function selectors overlap with existing facets without on-chain collision validation.
- **FP:** `diamondCut` implementation validates no selector collisions before adding/replacing facets. `DiamondLoupeFacet` used to enumerate and verify all selectors post-cut. Multisig + timelock required for `diamondCut` operations.

**78. Chainlink Staleness / No Validity Checks**

- **Detect:** `latestRoundData()` called but any of these checks are missing: `answer > 0`, `updatedAt > block.timestamp - MAX_STALENESS`, `answeredInRound >= roundId`, fallback on failure.
- **FP:** All four checks present. Circuit breaker or fallback oracle used when any check fails.

**79. EIP-2981 Royalty Signaled But Never Enforced**

- **Detect:** Contract implements `IERC2981.royaltyInfo(tokenId, salePrice)` and `supportsInterface(0x2a55205a)` returns `true`, advertising royalty support. However, the protocol's own transfer, listing, or settlement logic never calls `royaltyInfo()` and never routes payment to the royalty recipient. EIP-2981 is a signaling standard — it cannot force payment. Any marketplace that does not voluntarily query and pay royalties will bypass them entirely. Pattern: `royaltyInfo()` implemented, but `transferFrom` and all settlement paths contain no corresponding payment call.
- **FP:** Protocol's own marketplace or settlement contract reads `royaltyInfo()` and transfers the royalty amount to the recipient before or after completing the sale — enforced on-chain. Royalties are intentionally zero (`royaltyBps = 0`) and this is documented.

**80. Merkle Tree Second Preimage Attack**

- **Detect:** `MerkleProof.verify(proof, root, leaf)` where the leaf is derived from variable-length or 32-byte user-supplied input without double-hashing or type-prefixing. An attacker can pass a 64-byte value (concatenation of two sibling hashes at an intermediate node) as if it were a leaf — the standard hash tree produces the same root, so verification passes with a shorter proof. Pattern: `leaf = keccak256(abi.encodePacked(account, amount))` without an outer hash or prefix; no length restriction enforced on leaf inputs.
- **FP:** Leaves are double-hashed (`keccak256(keccak256(data))`). Leaf includes a type prefix or domain tag that intermediate nodes cannot satisfy. Input length enforced to be ≠ 64 bytes. OpenZeppelin MerkleProof ≥ v4.9.2 with `processProofCalldata` or sorted-pair variant used correctly.

**81. Block Stuffing / Gas Griefing on Subcalls**

- **Detect:** Time-sensitive function can be blocked by filling blocks (SWC-126). For relayer gas-forwarding griefing via the 63/64 rule, see Vector 47.
- **FP:** Function is not time-sensitive or has a sufficiently long window that block stuffing is economically infeasible.

**82. Missing or Expired Deadline on Swaps**

- **Detect:** `deadline = block.timestamp` (computed inside the tx, always valid), `deadline = type(uint256).max`, or no deadline at all. Transaction can be held in mempool and executed at any future price.
- **FP:** Deadline is a calldata parameter validated on-chain as `require(deadline >= block.timestamp)` and is not derived from `block.timestamp` or set to `type(uint256).max` within the function itself.

**83. Bytecode Verification Mismatch (Source-to-Deployment Discrepancy)**

- **Detect:** The source code verified on a block explorer (Etherscan, Sourcify) does not faithfully represent the deployed bytecode's behavior. This can happen through: (a) different compiler settings (optimizer runs, EVM version) producing semantically different bytecode from the same source; (b) constructor arguments that alter behavior but are not visible in the verified source; (c) deliberately crafted source that passes verification but contains obfuscated malicious logic (e.g., a second contract in the same file with phishing/scam code verified under the victim's address). Research has shown that verification services can be abused to associate misleading source code with deployed contracts. Pattern: deployment script uses different `solc` version or optimizer settings than the verification step. Constructor arguments encode addresses or parameters not visible in source. Verification submitted with `--via-ir` but compilation used legacy pipeline (or vice versa). No reproducible build (no committed `foundry.toml` / `hardhat.config.ts` with pinned compiler settings).
- **FP:** Deterministic build: `foundry.toml` or `hardhat.config.ts` committed with pinned compiler version and optimizer settings. Verification is part of the deployment script (Foundry `--verify`, Hardhat `verify` task) using identical settings. Sourcify full match (metadata hash matches). Constructor arguments are ABI-encoded and published alongside verification.

---

**84. ecrecover Returns address(0) on Invalid Signature**

- **Detect:** Raw `ecrecover(hash, v, r, s)` used without checking that the returned address is not `address(0)`. An invalid or malformed signature does not revert — `ecrecover` silently returns `address(0)`. If the code then checks `recovered == authorizedSigner` and `authorizedSigner` is uninitialized (defaults to `address(0)`), or if `permissions[recovered]` is read from a mapping that has a non-zero default for `address(0)` (e.g., from a prior `grantRole(ROLE, address(0))`), an attacker passes any garbage signature to gain privileges.
- **FP:** OpenZeppelin `ECDSA.recover()` used — it explicitly reverts when `ecrecover` returns `address(0)`. Explicit `require(recovered != address(0))` check present before any comparison or lookup.

**85. Griefing via Dust Deposits Resetting Timelocks or Cooldowns**

- **Detect:** Time-based lock, cooldown, or delay is reset on any deposit or interaction with no minimum-amount guard: `lastActionTime[user] = block.timestamp` inside a `deposit(uint256 amount)` with no `require(amount >= MIN_AMOUNT)`. Attacker calls `deposit(1)` repeatedly, just before the victim's lock expires, resetting the cooldown indefinitely at negligible cost. Variant: vault that checks `totalSupply > 0` before first depositor can join — attacker donates 1 wei to permanently inflate the share price and trap subsequent depositors; or a contract guarded by `require(address(this).balance > threshold)` that the attacker manipulates by sending dust.
- **FP:** Minimum deposit enforced unconditionally: `require(amount >= MIN_DEPOSIT)`. Cooldown reset only for the depositing user, not system-wide. Time lock assessed independently of deposit amounts on a per-user basis.

**86. Missing or Incorrect Access Modifier**

- **Detect:** State-changing function (`setOwner`, `withdrawFunds`, `mint`, `pause`, `setOracle`, `updateFees`) has no access guard, or modifier references an uninitialized variable. `public`/`external` visibility on privileged operations with no restriction.
- **FP:** Function is genuinely permissionless by design — any caller can legitimately invoke it and the worst-case outcome is a non-critical state transition (e.g., triggering a public distribution, settling an open auction, or advancing a time-locked process that anyone can advance).

**87. Fee-on-Transfer Token Accounting**

- **Detect:** Deposit recorded as `deposits[user] += amount` then `transferFrom(..., amount)`. Fee-on-transfer tokens (SAFEMOON, STA) cause the contract to receive `amount - fee` but record `amount`. Subsequent withdrawals drain other users.
- **FP:** Balance measured before/after transfer: `uint256 before = token.balanceOf(this); token.transferFrom(...); uint256 received = token.balanceOf(this) - before;` and `received` used for accounting.

**88. Missing `__gap` in Upgradeable Base Contracts**

- **Detect:** Upgradeable base contract inherited by other contracts has no `uint256[N] private __gap;` at the end. A future version adding state variables to the base shifts every derived contract's storage layout. Pattern: `contract GovernableV1 { address public governor; }` with no gap -- adding `pendingGov` in V2 shifts all child-contract slots.
- **FP:** EIP-7201 namespaced storage used for all variables in the base contract. `__gap` array present and sized correctly (reduced by 1 for each new variable). Single-contract (non-inherited) implementation where new variables can only be appended safely.
