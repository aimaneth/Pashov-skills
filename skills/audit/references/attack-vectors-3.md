# Attack Vectors Reference (3/3 — Vectors 89–133)

133 total attack vectors. For each: detection pattern (what to look for in code) and false-positive signals (what makes it NOT a vulnerability even if the pattern matches).

---

**89. Diamond Shared-Storage Cross-Facet Corruption**

- **Detect:** EIP-2535 Diamond proxy where facets declare storage variables without EIP-7201 namespaced storage structs -- each facet using plain `uint256 foo` or `mapping(...)` declarations that Solidity places at sequential storage slots 0, 1, 2, .... Different facets independently start at slot 0, so both write to the same slot. A compromised or buggy facet can corrupt the entire Diamond's state. Pattern: facet with top-level state variable declarations (no `DiamondStorage` struct at a namespaced slot).
- **FP:** All facets store state exclusively in a single `DiamondStorage` struct retrieved via `assembly { ds.slot := DIAMOND_STORAGE_POSITION }` using a namespaced position (EIP-7201 formula). No facet declares top-level state variables. OpenZeppelin's ERC-7201 `@custom:storage-location` pattern used correctly.

**90. validateUserOp Missing EntryPoint Caller Restriction**

- **Detect:** `validateUserOp(UserOperation calldata, bytes32, uint256)` is `public` or `external` without a guard that enforces `msg.sender == address(entryPoint)`. Anyone can call the validation function directly, bypassing the EntryPoint's replay and gas-accounting protections. Also check `execute` and `executeBatch` — they should be similarly restricted to the EntryPoint or the wallet owner.
- **FP:** Function starts with `require(msg.sender == address(_entryPoint), ...)` or uses an `onlyEntryPoint` modifier. Internal visibility used.

**91. Metamorphic Contract via CREATE2 + SELFDESTRUCT**

- **Detect:** Contract deployed via `CREATE2` from a factory where the deployer can `selfdestruct` the contract and redeploy different bytecode to the same address. Governance voters verify code at proposal time, but the code can be swapped before execution. Pattern: `create2(0, ..., salt)` deployment + `selfdestruct` in the deployed contract or an intermediate deployer that resets its nonce. Real-world: Tornado Cash Governance (May 2023) -- attacker proposed legitimate contract, `selfdestruct`-ed it, redeployed malicious code at same address, gained 1.2M governance votes, drained ~$2.17M. Post-Dencun (EIP-6780): largely killed for pre-existing contracts, but same-transaction create-destroy-recreate may still work.
- **FP:** Post-Dencun (EIP-6780): `selfdestruct` no longer destroys code unless same transaction as creation. `EXTCODEHASH` verified at execution time, not just proposal time. Contract was not deployed via `CREATE2` from a mutable deployer.

**92. tx.origin Authentication**

- **Detect:** `require(tx.origin == owner)` or `require(tx.origin == authorized)` used for authentication. Vulnerable to phishing via malicious intermediary contract.
- **FP:** `tx.origin == msg.sender` used only to assert caller is not a contract (anti-bot pattern, not auth).

**93. ERC-1271 isValidSignature Delegated to Untrusted or Arbitrary Module**

- **Detect:** `validateUserOp` or the wallet's `isValidSignature` implementation calls `isValidSignature(hash, sig)` on an externally-supplied or user-registered contract address without verifying that the contract is an explicitly whitelisted module or owner-registered guardian. A malicious module that always returns `0x1626ba7e` (ERC-1271 magic value) passes all signature checks. Pattern: `ISignatureValidator(module).isValidSignature(...)` where `module` comes from user input or an unguarded registry.
- **FP:** `isValidSignature` is only delegated to contracts in an owner-controlled whitelist or to the wallet owner's EOA address directly. Module registry has a timelock or guardian approval before a new module can validate signatures.

---

**94. Staking Reward Front-Run by New Depositor**

- **Detect:** Reward checkpoint (`rewardPerTokenStored`, `lastUpdateTime`) is updated lazily — only when a user action triggers it — and the update happens AFTER the new stake is recorded in `_balances` or `totalSupply`. A new staker can join immediately before `notifyRewardAmount()` is called (or immediately before a large pending reward accrues), and the checkpoint then distributes the new rewards pro-rata over a supply that includes the attacker's stake. The attacker earns rewards for a period they were not staked. Pattern: `_balances[user] += amount; totalSupply += amount;` executed before `updateReward()`.
- **FP:** `updateReward(account)` is the very first step of `stake()` — executed before any balance update — so new stakers start from the current `rewardPerTokenStored` and earn nothing retroactively. `rewardPerTokenPaid[user]` correctly tracks per-user checkpoint.

**95. `selfdestruct` via Delegatecall Bricking**

- **Detect:** Implementation contract contains `selfdestruct`, or allows `delegatecall` to an arbitrary address that may contain `selfdestruct`. If an attacker gains execution in the implementation context (e.g. via uninitialized takeover), they can call `selfdestruct` which executes in the proxy's context, permanently bricking it. For UUPS, the upgrade logic is destroyed with the implementation -- no recovery. Pattern: `selfdestruct(...)` anywhere in implementation code, or `target.delegatecall(data)` where `target` is user-supplied. Real-world: Parity (2017), Wormhole (2022). Post-Dencun (EIP-6780): `selfdestruct` only fully deletes contracts created in the same transaction -- mitigates but does not fully eliminate this vector.
- **FP:** No `selfdestruct` opcode in implementation or any contract it delegatecalls to. No arbitrary delegatecall targets. `_disableInitializers()` called in constructor.

**96. Immutable / Constructor Argument Misconfiguration**

- **Detect:** Constructor sets `immutable` variables or critical storage values (admin address, fee basis points, token address, oracle address) that cannot be changed after deployment. If the deployment script passes wrong values — swapped argument order, wrong decimal precision, zero address, test values — the contract is permanently misconfigured with no recourse except redeployment. Pattern: constructor accepts multiple `address` parameters of the same type where argument order can be silently swapped. `immutable` variables set from constructor args without post-deployment validation. Fee parameters in basis points vs. percentage (100 vs. 10000) with no bounds checking. No deployment verification script that reads back on-chain state to confirm correct configuration.
- **FP:** Deployment script includes post-deploy assertions that read back every immutable/constructor-configured value and compare against expected values. Constructor validates arguments: `require(admin != address(0))`, `require(feeBps <= 10000)`. Integration test suite deploys and verifies the full configuration before mainnet deployment.

**97. L2 Sequencer Uptime Not Checked**

- **Detect:** Contract on Arbitrum/Optimism/Base/etc. uses Chainlink feeds but does not query the L2 Sequencer Uptime Feed before consuming prices. Stale data during sequencer downtime can trigger wrong liquidations.
- **FP:** Sequencer uptime feed queried explicitly (`answer == 0` = up), with a grace period enforced after restart.

**98. Banned Opcode in Validation Phase (Simulation-Execution Divergence)**

- **Detect:** `validateUserOp` or `validatePaymasterUserOp` references `block.timestamp`, `block.number`, `block.coinbase`, `block.prevrandao`, or `block.basefee`. Per ERC-7562, these opcodes are banned in the validation phase because their values can differ between bundler simulation (off-chain) and on-chain execution, causing ops that pass simulation to revert on-chain. The bundler pays gas for the failed inclusion.
- **FP:** Banned opcodes appear only in the execution phase (inside `execute`/`executeBatch` logic, not in validation). The entity using the banned opcode is staked and tracked under the ERC-7562 reputation system (reduces but does not eliminate risk).

**99. Missing Slippage Protection (Sandwich Attack)**

- **Detect:** Swap/deposit/withdrawal with `minAmountOut = 0`, or `minAmountOut` computed on-chain from current pool state (always passes). Pattern: `router.swap(..., 0, deadline)`.
- **FP:** `minAmountOut` set off-chain by the user and validated on-chain.

**100. Governance Flash-Loan Upgrade Hijack**

- **Detect:** Proxy upgrades controlled by on-chain governance that uses `token.balanceOf(msg.sender)` or `getPastVotes(account, block.number)` (current block) for vote weight. Attacker flash-borrows governance tokens, self-delegates, votes to approve a malicious upgrade, and executes -- all within one transaction or block if no timelock. Pattern: Governor with no voting delay, no timelock, or snapshot at current block.
- **FP:** Uses `getPastVotes(account, block.number - 1)` (prior block, un-manipulable in current tx). Timelock of 24-72h between proposal and execution. Quorum thresholds high enough to resist flash loan manipulation. Staking lockup required before voting power is active.

**101. Re-initialization Attack**

- **Detect:** Initialization guard is improperly implemented or reset during an upgrade, allowing `initialize()` to be called again to overwrite critical state (owner, token addresses, rates). Pattern: V2 uses `initializer` modifier instead of `reinitializer(2)` on its new init function; upgrade resets the initialized version counter; custom initialization flag uses a `bool` that gets storage-collided to `false`. Real-world: AllianceBlock (2024) -- upgrade reset `initialized` to false, attacker re-invoked initializer.
- **FP:** OpenZeppelin's `reinitializer(version)` used for V2+ initialization with correctly incrementing version numbers. `initializer` modifier on original init, `reinitializer(N)` on subsequent versions. Integration tests verify `initialize()` reverts after first call.

**102. Transparent Proxy Admin Routing Confusion**

- **Detect:** Transparent proxy routes calls from the admin address to proxy admin functions, and all other calls to the implementation. If the admin address accidentally interacts with the protocol as a user (e.g. deposits, withdraws), the call hits proxy admin routing instead of being delegated -- silently failing or executing unintended logic. Pattern: admin EOA or contract also used for regular protocol interactions; `ProxyAdmin` contract doubles as treasury or operator.
- **FP:** Dedicated `ProxyAdmin` contract used exclusively for admin calls, never for protocol interaction. OpenZeppelin `TransparentUpgradeableProxy` pattern enforces separate admin contract. Admin address documented and known to never make user-facing calls.

**103. Non-Atomic Proxy Deployment Enabling CPIMP Takeover**

- **Detect:** Deployment script deploys a proxy in one transaction and calls `initialize()` in a separate one, creating a window where an attacker front-runs initialization and inserts a malicious middleman implementation (CPIMP) that persists across upgrades by restoring itself in the ERC-1967 slot after each delegatecall. Pattern: `new TransparentUpgradeableProxy(impl, admin, "")` with empty `data` followed by a separate `proxy.initialize(...)`. In Foundry: `new ERC1967Proxy(address(impl), "")` then a later `initialize()`. In Hardhat: two separate `await` calls for deploy and initialize.
- **FP:** Proxy constructor receives initialization calldata atomically: `new TransparentUpgradeableProxy(impl, admin, abi.encodeCall(Contract.initialize, (...)))`. OpenZeppelin `deployProxy()` helper used. `_disableInitializers()` called in implementation constructor.

**104. EIP-2612 Permit Front-Run Causing DoS**

- **Detect:** Contract calls `token.permit(owner, spender, value, deadline, v, r, s)` inline as part of a combined permit-and-action function, with no `try/catch` around the permit call. The same permit signature can be submitted by anyone — if an attacker (or MEV bot) front-runs by submitting the permit signature first, the nonce is incremented; the subsequent victim transaction's inline `permit()` call then reverts (wrong nonce), causing the entire action to fail. Because the user only has the one signature, they may be permanently blocked from that code path.
- **FP:** Permit wrapped in `try { token.permit(...); } catch {}` — falls through and relies on pre-existing allowance if permit already consumed. Permit is a standalone user call; the main action function only calls `transferFrom` (not combined).

**105. Beacon Proxy Single-Point-of-Failure Upgrade**

- **Detect:** Multiple proxies read their implementation address from a single Beacon contract. Compromising the Beacon owner upgrades all proxies simultaneously. Pattern: `UpgradeableBeacon` with `owner()` returning a single EOA; tens or hundreds of `BeaconProxy` instances pointing to it. A single `upgradeTo()` on the Beacon replaces logic for every proxy at once.
- **FP:** Beacon owner is a multisig + timelock. `Upgraded` events on the Beacon are monitored for unauthorized changes. Per-proxy upgrade authority used where risk tolerance requires isolation.

**106. ERC4626 Caller-Dependent Conversion Functions**

- **Detect:** `convertToShares()` or `convertToAssets()` branches on `msg.sender`-specific state — per-user fee tiers, whitelist status, individual balances, or allowances — causing identical inputs to return different outputs for different callers. EIP-4626 requires these functions to be caller-independent. Downstream aggregators, routers, and on-chain interfaces call these functions to size positions before routing; a caller-dependent result silently produces wrong sizing for some users.
- **FP:** Implementation reads only global vault state (`totalSupply()`, `totalAssets()`, protocol-wide fee constants) with no `msg.sender`-dependent branching.

**107. ERC1155 Custom Burn Without Caller Authorization Check**

- **Detect:** Custom `burn(address from, uint256 id, uint256 amount)` or `burnBatch(address from, ...)` function is callable by any address without verifying that `msg.sender == from` or that `msg.sender` is an approved operator for `from`. Any caller can burn another user's tokens by passing their address as `from`. Pattern: `function burn(address from, uint256 id, uint256 amount) external { _burn(from, id, amount); }` with no authorization guard. Distinct from OZ's `_burn` (which is internal) — the risk is in public wrappers that expose it without access control.
- **FP:** Burn function requires `require(from == msg.sender || isApprovedForAll(from, msg.sender), "not authorized")` before calling `_burn`. OZ's `ERC1155Burnable` extension used — it includes the owner/operator check. Burn is restricted to a privileged role (admin/governance) and the `from` address is not user-supplied.

**108. ERC4626 Deposit/Withdraw Share-Count Asymmetry**

- **Detect:** For the same asset amount `a`, `withdraw(a)` burns fewer shares than `deposit(a)` minted — meaning a user can deposit, immediately withdraw the same assets, and retain surplus shares for free. Equivalently, `deposit(withdraw(a).assets)` returns more shares than `withdraw(a)` burned, manufacturing shares from nothing. Root cause: `_convertToShares` applies `Rounding.Floor` (rounds down) for both the deposit path (shares issued) and the withdraw path (shares required to burn), when EIP-4626 requires deposit to round down and withdraw to round up. The gap between the two floors is the free share. Pattern: a single `_convertToShares(assets, Rounding.Floor)` helper called on both code paths without distinct rounding arguments. (Covers `prop_RT_deposit_withdraw` and `prop_RT_withdraw_deposit` from the a16z ERC4626 property test suite.)
- **FP:** `deposit`/`previewDeposit` call `_convertToShares(assets, Math.Rounding.Floor)` and `withdraw`/`previewWithdraw` call `_convertToShares(assets, Math.Rounding.Ceil)` — opposite directions, vault-favorable in each case. OpenZeppelin ERC4626 used without custom conversion overrides.

**109. Read-Only Reentrancy**

- **Detect:** Protocol calls a `view` function (e.g., `get_virtual_price()`, `totalAssets()`, `convertToAssets()`) on an external contract from within a callback (`receive`, `onERC721Received`, flash loan hook). The external contract has no reentrancy guard on its view functions - a mid-execution call can return a transitional/manipulated value.
- **FP:** External contract's view functions are themselves `nonReentrant`. Protocol uses Chainlink or another oracle instead of the external view. External contract's reentrancy lock is public and the protocol reads and enforces it before calling any view function.

**110. ERC721 transferFrom with Unvalidated `from` Parameter**

- **Detect:** Custom ERC721 overrides `transferFrom(from, to, tokenId)` and verifies that `msg.sender` is the owner or approved, but does not verify that `from == ownerOf(tokenId)`. An attacker who is an approved operator for `tokenId` can call `transferFrom(victim, attacker, tokenId)` with a fabricated `from` address — the approval check passes for the operator, the token moves, but `from` was not the actual owner and may not be the intended origin for accounting, event logging, or protocol-level state. Pattern: `require(isApprovedOrOwner(msg.sender, tokenId))` without a subsequent `require(from == ownerOf(tokenId))`.
- **FP:** `super.transferFrom()` or OZ's `_transfer(from, to, tokenId)` called internally — OZ's `_transfer` explicitly checks `from == ownerOf(tokenId)` and reverts with `ERC721IncorrectOwner` if not. Custom override includes an explicit `require(ownerOf(tokenId) == from)` before transfer logic.

**111. Function Selector Clashing (Proxy Backdoor)**

- **Detect:** Proxy contract contains a function whose 4-byte selector collides with a function in the implementation. Two different function signatures can produce the same selector (e.g. `burn(uint256)` and `collate_propagate_storage(bytes16)` both = `0x42966c68`). When a user calls the implementation function, the proxy's function executes instead, silently running different logic. Pattern: proxy with any non-admin functions beyond `fallback()`/`receive()` -- check all selectors against implementation selectors for collisions.
- **FP:** Transparent proxy pattern used -- admin calls always route to the proxy admin and user calls always delegate, making selector clashes between proxy and implementation impossible. UUPS proxy with no custom functions in the proxy shell -- all calls delegate unconditionally.

**112. ERC1155 onERC1155Received Return Value Not Validated**

- **Detect:** Custom ERC1155 implementation calls `IERC1155Receiver(to).onERC1155Received(operator, from, id, value, data)` when transferring to a contract address, but does not check that the returned `bytes4` equals `IERC1155Receiver.onERC1155Received.selector` (`0xf23a6e61`). A recipient contract that returns any other value (including `bytes4(0)` or nothing) should cause the transfer to revert per EIP-1155, but without the check the transfer silently succeeds. Tokens are permanently locked in a contract that cannot handle them.
- **FP:** OZ ERC1155 used as base — it validates the selector and reverts with `ERC1155InvalidReceiver` on mismatch. Custom implementation explicitly checks: `require(retval == IERC1155Receiver.onERC1155Received.selector, "ERC1155: rejected")`.

**113. ERC721 Unsafe Transfer to Non-Receiver**

- **Detect:** `_transfer()` (unsafe) used instead of `_safeTransfer()`, or `_mint()` instead of `_safeMint()`, sending NFTs to contracts that may not implement `IERC721Receiver`. Tokens permanently locked in the recipient contract.
- **FP:** All transfer and mint paths use `safeTransferFrom` or `_safeMint`, which perform the `onERC721Received` callback check. Function is `nonReentrant` to prevent callback abuse.

**114. DoS via Unbounded Loop**

- **Detect:** Loop iterates over an array that grows with user interaction and is unbounded: `for (uint i = 0; i < users.length; i++) { ... }`. If anyone can push to `users`, the function will eventually hit the block gas limit. (SWC-128)
- **FP:** Array length capped at insertion time with a `require(arr.length < MAX)` check. Loop iterates a fixed small constant count.

**115. Missing chainId / Message Uniqueness in Bridge**

- **Detect:** Bridge/messaging contract processes incoming messages but lacks: `processedMessages[messageHash]` check (replay), `destinationChainId == block.chainid` validation, or source chain ID in the message hash. A message from Chain A to Chain B can be replayed on Chain C, or submitted twice on the destination.
- **FP:** Each message has a unique nonce per sender. Hash of `(sourceChain, destinationChain, nonce, payload)` stored in `processedMessages` and checked before execution. Contract address included in message hash.

**116. Proxy Admin Key Compromise**

- **Detect:** Proxy admin (the address authorized to call `upgradeTo`) is a single EOA rather than a multisig or governance contract. A compromised private key allows instant upgrade to a malicious implementation that drains all funds. Pattern: `ProxyAdmin.owner()` returns an EOA; no timelock between upgrade proposal and execution. Real-world: PAID Network (2021) -- attacker obtained admin key, upgraded token proxy to mint unlimited tokens; Ankr (2022) -- compromised deployer key, minted 6 quadrillion aBNBc (~$5M loss).
- **FP:** Admin is a multisig (Gnosis Safe) with threshold >= 2. Timelock enforced (24-72h delay). Proxy admin role is separate from operational roles. Admin key rotation and monitoring in place.

**117. Write to Arbitrary Storage Location**

- **Detect:** (1) Assembly block with `sstore(slot, value)` where `slot` is derived from user-supplied calldata, function parameters, or arithmetic over user-controlled values without bounds validation — allows overwriting any slot including `owner`, `implementation`, or balance mappings. (2) (Solidity <0.6) Direct assignment to a storage array's `.length` field (`arr.length = userValue`) followed by an indexed write `arr[largeIndex] = x`. The storage slot for `arr[i]` is `keccak256(arraySlot) + i`; with a crafted large index, slot arithmetic wraps around and overwrites arbitrary slots. (SWC-124)
- **FP:** Assembly is read-only (`sload` only, no `sstore`). Slot value is a compile-time constant or derived exclusively from non-user-controlled data (e.g., `keccak256("protocol.slot")` pattern). Solidity ≥0.6 used throughout (compiler disallows direct array length assignment). Slot arithmetic validated against a fixed known-safe range before use.

**118. Missing chainId (Cross-Chain Replay)**

- **Detect:** Signed payload doesn't include `chainId`. Valid signature on mainnet replayable on forks or other EVM chains where the contract is deployed. Or `chainId` hardcoded at deployment rather than read via `block.chainid`.
- **FP:** EIP-712 domain separator includes `chainId: block.chainid` (dynamic) and `verifyingContract`. Domain separator re-checked or invalidated if `block.chainid` changes.

**119. ERC777 tokensToSend / tokensReceived Reentrancy**

- **Detect:** Contract calls `transfer()` or `transferFrom()` on a token that may implement ERC777 (registered via ERC1820 registry) before completing state updates. ERC777 fires a `tokensToSend` hook on the sender's registered hook contract and a `tokensReceived` hook on the recipient's — these callbacks trigger on plain ERC20-style `transfer()` calls, not just ETH. A recipient's `tokensReceived` or sender's `tokensToSend` can re-enter the calling contract before balances are updated. Pattern: `token.transferFrom(msg.sender, address(this), amount)` followed by state updates, or `token.transfer(user, amount)` before clearing user balance, with no `nonReentrant` guard and no ERC777 exclusion.
- **FP:** Strict CEI — all state committed before any token transfer. `nonReentrant` applied to all public entry points. Protocol enforces a token whitelist that explicitly excludes ERC777-compatible tokens.

**120. ERC1155 totalSupply Inflation via Reentrancy Before Supply Update**

- **Detect:** Contract extends `ERC1155Supply` (or custom supply tracking) and increments `totalSupply[id]` AFTER calling `_mint`, which triggers the `onERC1155Received` callback on the recipient. During the callback, `totalSupply[id]` has not yet been updated. Any governance, reward, or share-price formula that reads `totalSupply[id]` inside the callback (directly or via a re-entrant call to the same contract) observes an artificially low total, inflating the caller's computed share. OZ pre-4.3.2 `ERC1155Supply` had exactly this ordering — supply updated post-callback. Real finding: ChainSecurity disclosure, OZ advisory GHSA-9c22-pwxw-p6hx (2021).
- **FP:** OZ ≥ 4.3.2 used — supply incremented before the mint callback in patched versions. `nonReentrant` on all mint functions. No totalSupply-dependent logic is callable from within a mint callback path.

**121. Weak On-Chain Randomness / Randomness Frontrunning**

- **Detect:** Randomness from `block.prevrandao` (RANDAO, validator-influenceable), `blockhash(block.number - 1)` (known before inclusion), `block.timestamp`, `block.coinbase`, or combinations. Validators can influence RANDAO; all block values are visible before tx inclusion, enabling front-running of randomness-dependent outcomes. (SWC-120)
- **FP:** Chainlink VRF v2+ used. Commit-reveal scheme with future-block reveal and a meaningful economic penalty (slashing or bond forfeiture) enforced in code for non-reveal.

**122. ERC721A / Lazy Ownership — ownerOf Uninitialized in Batch Range**

- **Detect:** Contract uses ERC721A (or OpenZeppelin `ERC721Consecutive`) for gas-efficient batch minting. Ownership is stored lazily: only the first token of a consecutive run has its ownership struct written; all subsequent IDs in the range inherit it by binary search. Before any transfer occurs, `ownerOf(id)` for IDs in the middle of a batch may return `address(0)` or the batch-start owner depending on implementation version. Access control that calls `ownerOf(tokenId) == msg.sender` on freshly minted tokens without an explicit transfer may fail or return incorrect results. Pattern: `require(ownerOf(tokenId) == msg.sender)` in a staking or approval function called immediately after a batch mint.
- **FP:** Protocol always waits for an explicit `transferFrom` or `safeTransferFrom` before checking ownership (each transfer initializes the packed slot). Contract uses standard OZ `ERC721` where every mint writes `_owners[tokenId]` directly.

**123. Storage Layout Shift on Upgrade**

- **Detect:** V2 implementation inserts a new state variable in the middle of the contract rather than appending it at the end. All subsequent variables shift to different storage slots, silently corrupting state. Pattern: V1 has `(owner, totalSupply, balances)` at slots (0, 1, 2); V2 inserts `pauser` at slot 1, pushing `totalSupply` to read from the `balances` mapping slot. Also: changing a variable's type between versions (e.g. `uint128` to `uint256`) shifts slot boundaries.
- **FP:** New variables are only appended after all existing ones. `@openzeppelin/upgrades` storage layout validation is used in CI and confirms no slot shifts. Variable types are unchanged between versions.

**124. Arbitrary `delegatecall` in Implementation**

- **Detect:** Implementation exposes a function that performs `delegatecall` to a user-supplied address, allowing arbitrary bytecode execution in the proxy's storage context -- overwriting owner, balances, or bricking the contract. Pattern: `function execute(address target, bytes calldata data) external { target.delegatecall(data); }` where `target` is not restricted. Real-world: Furucombo (2021, $14M stolen via unrestricted delegatecall to user-supplied handler addresses).
- **FP:** `target` is a hardcoded immutable verified library address that cannot be changed after deployment. Whitelist of approved delegatecall targets enforced. `call` used instead of `delegatecall` for external integrations.

**125. Rounding in Favor of the Attacker**

- **Detect:** `shares = assets / pricePerShare` rounds down for the user but up for shares redeemed. First-depositor vault manipulation: when `totalSupply == 0`, attacker donates to inflate `totalAssets`, subsequent deposits round to 0 shares. Division without explicit rounding direction.
- **FP:** `Math.mulDiv(a, b, c, Rounding.Up)` used with explicit rounding direction appropriate for the operation. Virtual offset (OpenZeppelin ERC4626 `_decimalsOffset()`) prevents first-depositor attack. Dead shares minted to `address(0)` at init.

**126. Proxy Storage Slot Collision**

- **Detect:** Proxy stores `implementation`/`admin` at sequential slots (0, 1) and implementation contract also declares variables from slot 0. Implementation's slot 0 write overwrites the proxy's `implementation` pointer.
- **FP:** Proxy uses EIP-1967 slots (`keccak256("eip1967.proxy.implementation") - 1`). OpenZeppelin Transparent or UUPS proxy pattern used correctly.

**127. validateUserOp Signature Not Bound to nonce or chainId**

- **Detect:** `validateUserOp` reconstructs the signed digest manually (not via `entryPoint.getUserOpHash(userOp)`) and omits `userOp.nonce` or `block.chainid` from the signed payload. Enables cross-chain replay (same signature valid on other chains sharing the contract address) or in-chain replay after the wallet state is reset. Pattern: `keccak256(abi.encode(userOp.sender, userOp.callData, ...))` without nonce/chainId.
- **FP:** Signed digest is computed via `entryPoint.getUserOpHash(userOp)` — EntryPoint includes sender, nonce, chainId, and entryPoint address. Custom digest explicitly includes `block.chainid` and `userOp.nonce`.

**128. Improper Flash Loan Callback Validation**

- **Detect:** `onFlashLoan` callback does not verify `msg.sender == lendingPool`, or does not verify `initiator`, or does not check `token`/`amount` match. Attacker can call the callback directly without a real flash loan.
- **FP:** Both `msg.sender == address(lendingPool)` and `initiator == address(this)` are validated. Token and amount checked against pre-stored values.

**129. Stale Cached ERC20 Balance from Direct Token Transfers**

- **Detect:** Contract tracks token holdings in a state variable (`totalDeposited`, `_reserves`, `cachedBalance`) that is only updated through the protocol's own deposit/receive functions. The actual `token.balanceOf(address(this))` can exceed the cached value via direct `token.transfer(contractAddress, amount)` calls made outside the protocol's accounting flow. When protocol logic uses the cached variable — not `balanceOf` live — for share pricing, collateral ratios, or withdrawal limits, an attacker donates tokens directly to inflate actual holdings, then exploits the gap between cached and real state (inflated share price, under-collateralized accounting). Distinct from ERC4626 first-depositor inflation attack (see Vector 86): applies to any contract with split accounting, not just vaults.
- **FP:** All accounting reads `token.balanceOf(address(this))` live — no cached balance variable used in financial math. Cached value is reconciled against `balanceOf` at the start of every state-changing function. Direct token transfers are explicitly considered in the accounting model (e.g., treated as protocol revenue, not phantom deposits).

**130. Small-Type Arithmetic Overflow Before Upcast**

- **Detect:** Arithmetic expression operates on `uint8`, `uint16`, `uint32`, `int8`, or other sub-256-bit types before the result is assigned to a wider type. Pattern: `uint256 result = a * b` where `a` and `b` are `uint8` — multiplication executes in `uint8` and overflows silently (wraps mod 256) before widening. Also: ternary returning a small literal `(condition ? 1 : 0)` inferred as `uint8`; addition `uint16(x) + uint16(y)` assigned to `uint32`. Underflow possible for signed sub-types.
- **FP:** Each operand is explicitly upcast before the operation: `uint256(a) * uint256(b)`. SafeCast used. Solidity 0.8+ overflow protection applies only within the type of the expression — if both operands are `uint8`, the check is still on `uint8` range, not `uint256`.

**131. setApprovalForAll Grants Permanent Unlimited Operator Access**

- **Detect:** Protocol requires users to call `nft.setApprovalForAll(protocol, true)` to enable staking, escrow, or any protocol-managed transfer. This grants the operator irrevocable, time-unlimited control over every current and future token the user holds in that collection. No expiry, no per-token scoping, and no per-amount limit. If the approved operator contract is exploited, upgraded maliciously, or its admin key is compromised, an attacker can drain all tokens from all users who granted approval in a single sweep. Pattern: `require(nft.isApprovedForAll(msg.sender, address(this)), "must approve")` at the entry point of a staking or escrow function.
- **FP:** Protocol uses individual `approve(address(this), tokenId)` before each transfer, requiring per-token user action. Operator is an immutable non-upgradeable contract with a formally verified transfer function. Protocol provides an on-chain `revokeAll()` helper users are trained to call after each interaction.

**132. Spot Price Oracle from AMM**

- **Detect:** Price computed from AMM reserves directly: `price = reserve0 / reserve1`, `getAmountsOut()`, `getReserves()`. Any lending, liquidation, or collateral logic built on spot price is flash-loan exploitable atomically.
- **FP:** TWAP oracle with a 30-minute or longer observation window. Chainlink or Pyth as primary source.

**133. Cross-Function Reentrancy**

- **Detect:** Two functions share a state variable. Function A makes an external call before updating shared state; Function B reads or modifies that same state. `nonReentrant` on A but not B.
- **FP:** Both functions are guarded by the same contract-level mutex. Shared state fully updated before any external call in A.
