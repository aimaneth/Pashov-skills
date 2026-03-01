# Attack Vectors Reference (1/3 — Vectors 1–44)

133 total attack vectors. For each: detection pattern (what to look for in code) and false-positive signals (what makes it NOT a vulnerability even if the pattern matches).

---

**1. Block Number as Timestamp Approximation**

- **Detect:** Time computed as `(block.number - startBlock) * 13` assuming fixed block times. Post-Merge Ethereum has variable block times; Polygon/Arbitrum/BSC have very different averages. Causes wrong interest accrual, vesting, or reward calculations.
- **FP:** `block.timestamp` used instead of `block.number` for all time-sensitive calculations.

**2. Rebasing / Elastic Supply Token Accounting**

- **Detect:** Contract holds rebasing tokens (stETH, AMPL, aTokens) and caches `token.balanceOf(this)` in a state variable used for future accounting. After a rebase, cached value diverges from actual balance.
- **FP:** Protocol enforces at the code level that rebasing tokens cannot be deposited (explicit revert or whitelist). Accounting always reads `balanceOf` live. Wrapper tokens (wstETH) used instead.

**3. Counterfactual Wallet Initialization Parameters Not Bound to Deployed Address**

- **Detect:** Factory's `createAccount` uses `CREATE2` but the salt does not incorporate all initialization parameters (especially the owner address). An attacker can call `createAccount` with a different owner before the legitimate user, deploying a wallet they control to the same counterfactual address. Pattern: `salt` is a plain user-supplied value or only includes a partial subset of init data; `CREATE2` address can be predicted and front-run with different constructor args.
- **FP:** Salt is derived from all initialization parameters: `salt = keccak256(abi.encodePacked(owner, ...))`. Factory reverts if the account already exists. Initializer is called atomically in the same transaction as deployment.

**4. Chainlink Feed Deprecation / Wrong Decimal Assumption**

- **Detect:** (a) Chainlink aggregator address is hardcoded in the constructor or an immutable with no admin path to update it. When Chainlink deprecates the feed and migrates to a new aggregator contract, the protocol continues reading from the frozen old feed, which may return a stale or zeroed price indefinitely. (b) Price normalization assumes `feed.decimals() == 8` (common for USD feeds) without calling `feed.decimals()` at runtime. Some feeds (e.g., ETH/ETH) return 18 decimals — the 10^10 scaling discrepancy produces wildly wrong collateral values, enabling instant over-borrowing or mass liquidations.
- **FP:** Feed address is updatable via a governance-gated setter. `feed.decimals()` called and stored; used to normalize `latestRoundData().answer` before any arithmetic. Deviation check against a secondary oracle rejects anomalous values.

**5. Non-Atomic Multi-Contract Deployment (Partial System Bootstrap)**

- **Detect:** Deployment script deploys multiple interdependent contracts across separate transactions without atomic guarantees. If the script fails midway (gas exhaustion, RPC error, nonce conflict, reverted transaction), the system is left in a half-deployed state: some contracts reference addresses that don't exist yet, or contracts are deployed but not wired together. A partially deployed lending protocol might have a vault deployed but no oracle configured, allowing deposits at a zero price. Pattern: Foundry script with multiple `vm.broadcast()` blocks or Hardhat deploy script with sequential `await deploy()` calls where later deployments depend on earlier ones. No idempotency checks (does the contract already exist?) or rollback mechanism. No deployment state file tracking which steps completed.
- **FP:** Script uses a single `vm.startBroadcast()` / `vm.stopBroadcast()` block that batches all transactions atomically (note: Foundry still sends individual txs, but script halts on first failure). Deployment uses a factory contract that deploys and wires all contracts in a single transaction. Script is idempotent — checks for existing deployments before each step. Hardhat-deploy module with tagged, resumable migrations.

**6. Precision Loss - Division Before Multiplication**

- **Detect:** Expression `(a / b) * c` in integer math. Division truncates first, then multiplication amplifies the error. Common in fee calculations: `fee = (amount / 10000) * bps`. Correct form: `(a * c) / b`.
- **FP:** `a` is provably divisible by `b` — enforced by a preceding explicit check (e.g., `require(a % b == 0)`) or by mathematical construction visible in the code.

**7. Flash Loan Governance Attack**

- **Detect:** Governance voting uses `token.balanceOf(msg.sender)` or `getPastVotes(account, block.number)` (current block). Attacker borrows governance tokens, votes, repays in one tx.
- **FP:** Uses `getPastVotes(account, block.number - 1)` (prior block, un-manipulable in current tx). Timelock between snapshot and vote. Staking required before voting.

**8. Hardcoded Network-Specific Addresses**

- **Detect:** Deployment script or constructor contains hardcoded addresses for external dependencies (oracles, routers, tokens, registries) that differ across networks. When the script is reused on a different chain or testnet, these addresses point to wrong contracts, EOAs, or undeployed addresses — silently misconfiguring the system. A USDC address hardcoded for Ethereum mainnet resolves to an unrelated contract (or an EOA) on Arbitrum or Polygon. Pattern: literal `address(0x...)` constants in deployment scripts or constructor arguments that represent external protocol addresses. No per-chain configuration mapping or environment variable lookup.
- **FP:** Addresses are loaded from a per-chain configuration file (JSON, TOML) keyed by chain ID. Script asserts `block.chainid` matches expected chain before using hardcoded addresses. Addresses are passed as constructor arguments from the deployment environment, not embedded in source. Deterministic addresses that are guaranteed identical across chains (e.g., CREATE2-deployed singletons like Permit2).

**9. Unsafe Downcast / Integer Truncation**

- **Detect:** Explicit cast to smaller type without bounds check: `uint128(largeUint256)`. Solidity ≥0.8 silently truncates on downcast (does NOT revert). Especially dangerous in price feeds, share calculations, timestamps.
- **FP:** Value validated against the target type's maximum before cast (e.g., `require(x <= type(uint128).max)`). OpenZeppelin `SafeCast` library used.

**10. NFT Staking / Escrow Records msg.sender Instead of ownerOf**

- **Detect:** Staking or escrow contract accepts an ERC721 via `nft.transferFrom(msg.sender, address(this), tokenId)` and records `depositor[tokenId] = msg.sender`. An operator (approved but not the owner) can call `stake(tokenId)` — the transfer succeeds because the operator holds approval, but `msg.sender` is the operator, not the real owner. The real owner loses their NFT; the operator is credited as depositor and receives all staking rewards and the right to unstake. Pattern: `depositor[tokenId] = msg.sender` without cross-checking against `nft.ownerOf(tokenId)` before the transfer.
- **FP:** Contract reads `address realOwner = nft.ownerOf(tokenId)` before accepting the transfer and records `depositor[tokenId] = realOwner`. Or requires `require(nft.ownerOf(tokenId) == msg.sender, "not owner")` so operators cannot stake on others' behalf.

**11. Integer Overflow / Underflow**

- **Detect:** Arithmetic inside `unchecked {}` blocks (Solidity ≥0.8) that could over/underflow: subtraction without a prior `require(amount <= balance)`, multiplication of two large values. Any arithmetic in Solidity <0.8 without SafeMath. (SWC-101)
- **FP:** Value range is provably bounded by earlier checks that appear in the same function before the unchecked block. `unchecked` used exclusively for loop counter increments of the form `++i` where `i < arr.length`, making overflow structurally impossible.

**12. Single-Function Reentrancy**

- **Detect:** External call (`call{value:}`, `transfer`, `send`, `safeTransfer`, `safeTransferFrom`) happens _before_ state update (balance set to 0, flag set, counter decremented). Classic: check-external-effect instead of check-effect-external.
- **FP:** State updated before the call (CEI followed). `nonReentrant` modifier present. Callee is a hardcoded immutable address of a contract whose receive/fallback is known to not re-enter.

**13. Immutable Variable Context Mismatch**

- **Detect:** Implementation contract uses `immutable` variables set in its constructor. These are embedded in bytecode, not storage -- so when a proxy `delegatecall`s, it gets the implementation's hardcoded values regardless of per-proxy configuration needs. If the implementation is shared across multiple proxies or chains, all proxies see the same immutable values. Pattern: `address public immutable WETH` in implementation constructor -- every proxy gets the same WETH address regardless of chain.
- **FP:** Immutable values are intentionally identical across all proxies (e.g. a protocol-wide constant). Per-proxy configuration uses storage variables set in `initialize()`. Implementation is purpose-deployed per proxy with correct constructor args.

**14. CREATE2 Address Reuse After selfdestruct**

- **Detect:** Protocol whitelists, approves, or trusts a contract at an address derived from CREATE2. Attacker controls the salt or factory. Pre-EIP-6780: attacker deploys a benign contract, earns trust (e.g., token approval, whitelist entry, governance power), calls `selfdestruct`, then redeploys a malicious contract to the identical address. The stored approval/whitelist entry now points to the malicious code. Pattern: `create2Factory.deploy(salt, initcode)` where `salt` is user-supplied or predictable, combined with no bytecode-hash verification at trust-grant time.
- **FP:** Post-Dencun (EIP-6780): `selfdestruct` no longer destroys code unless it occurs in the same transaction as contract creation, effectively eliminating the redeploy path on mainnet. Bytecode hash of the approved contract recorded at approval time and re-verified before each privileged call. No user-controlled CREATE2 salt accepted by the factory.

**15. ERC4626 Preview Rounding Direction Violation**

- **Detect:** `previewDeposit(a)` returns more shares than `deposit(a)` actually mints; `previewRedeem(s)` returns more assets than `redeem(s)` actually transfers; `previewMint(s)` returns fewer assets than `mint(s)` actually charges; `previewWithdraw(a)` returns fewer shares than `withdraw(a)` actually burns. EIP-4626 mandates that preview functions round in the vault's favor — they must never overstate what the user receives or understate what the user pays. Custom `_convertToShares`/`_convertToAssets` implementations that apply the wrong `Math.mulDiv` rounding direction (e.g., `Rounding.Ceil` when `Rounding.Floor` is required) violate this. Integrators that use preview return values for slippage checks will pass with an incorrect expectation and receive less than they planned for.
- **FP:** OpenZeppelin ERC4626 base used without overriding `_convertToShares`/`_convertToAssets`. Custom implementation explicitly passes `Math.Rounding.Floor` for share issuance (deposit/previewDeposit) and `Math.Rounding.Ceil` for share burning (withdraw/previewWithdraw).

**16. abi.encodePacked Hash Collision with Dynamic Types**

- **Detect:** `keccak256(abi.encodePacked(a, b, ...))` where two or more arguments are dynamic types (`string`, `bytes`, or dynamic arrays such as `uint[]`, `address[]`). `abi.encodePacked` concatenates raw bytes without length prefixes, so `("AB","CD")`, `("A","BCD")`, and `("ABC","D")` all produce the same byte sequence `0x41424344` and thus the same hash. If the hash is used for permit/signature verification, access control key derivation, or uniqueness enforcement (mapping keys, nullifiers), an attacker crafts an alternative input that collides with a legitimate hash and gains the same privileges.
- **FP:** `abi.encode()` used instead — each argument is ABI-padded and length-prefixed, eliminating ambiguity. Only one argument is a dynamic type (no two dynamic types to collide between). All arguments are fixed-size types (`uint256`, `address`, `bytes32`).

**17. ERC4626 Missing Allowance Check in withdraw() / redeem()**

- **Detect:** `withdraw(assets, receiver, owner)` or `redeem(shares, receiver, owner)` where `msg.sender != owner` but no allowance validation or decrement is performed before burning shares. EIP-4626 requires that if `caller != owner`, the caller must hold sufficient share approval; the allowance must be consumed atomically. Missing this check lets any address burn shares from an arbitrary owner and redirect the assets to any receiver — equivalent to an unchecked `transferFrom`.
- **FP:** `_spendAllowance(owner, caller, shares)` called unconditionally before the share burn when `caller != owner`. OpenZeppelin ERC4626 used without custom overrides of `withdraw`/`redeem`.

**18. Delegatecall to Untrusted / User-Supplied Callee**

- **Detect:** `address(target).delegatecall(data)` where `target` is user-provided or unconstrained. Callee executes in the caller's storage context - can overwrite owner, balances, call `selfdestruct`. (SWC-112)
- **FP:** `target` is a hardcoded immutable verified library address that cannot be changed after deployment.

**19. Front-Running Exact-Zero Balance Check with Dust Transfer**

- **Detect:** An `external` or `public` function contains `require(token.balanceOf(address(this)) == 0)`, `require(address(this).balance == 0)`, or any strict equality check against a zero balance that gates a state transition (e.g., starting an auction, initializing a pool, opening a deposit round). An attacker front-runs the legitimate caller's transaction by sending a dust amount of the token or ETH to the contract, making the balance non-zero and causing the victim's transaction to revert. The attack is repeatable at negligible cost, creating a permanent DoS on the guarded function. Distinct from Vector 39 (force-feeding ETH to break invariants) — this targets the zero-check gate itself as a griefing/DoS vector rather than inflating a balance used in financial math.
- **FP:** Check uses `<=` threshold instead of `== 0` (e.g., `require(balance <= DUST_THRESHOLD)`). Function is access-controlled so only a trusted caller can trigger it. Balance is tracked via an internal accounting variable that ignores direct transfers, not via `balanceOf` or `address(this).balance`.

---

**20. Non-Standard ERC20 Return Values (USDT-style)**

- **Detect:** `require(token.transfer(to, amount))` reverts on tokens that return nothing (USDT, BNB). Or return value ignored entirely (silent failure on failed transfer). (SWC-104)
- **FP:** OpenZeppelin `SafeERC20.safeTransfer()`/`safeTransferFrom()` used throughout.

**21. Zero-Amount Transfer Revert Breaking Distribution Logic**

- **Detect:** Contract calls `token.transfer(recipient, amount)` or `token.transferFrom(from, to, amount)` where `amount` can be zero — e.g., when fees round to 0, a user claims before any yield accrues, or a distribution loop pays out a zero share. Some non-standard ERC20 tokens (LEND, early BNB, certain stablecoins) include `require(amount > 0)` in their transfer logic and revert on zero-amount calls. Any fee distribution loop, reward claim, or conditional-payout path that omits a `if (amount > 0)` guard will permanently DoS on these tokens.
- **FP:** All transfer calls are preceded by `if (amount > 0)` or `require(amount > 0)`. Protocol enforces a minimum claim/distribution amount upstream. Supported token whitelist only includes tokens verified to accept zero-amount transfers (OZ ERC20 base allows them).

**22. Uninitialized Implementation Takeover**

- **Detect:** Implementation contract has an `initialize()` function but the constructor does not call `_disableInitializers()`. Anyone can call `initialize()` directly on the implementation (not the proxy), claim ownership, then call `upgradeTo()` to replace the implementation or `selfdestruct` via delegatecall. Pattern: UUPS/Transparent/Beacon implementation with `initializer` modifier but no `_disableInitializers()` in constructor. Real-world: Wormhole Bridge (2022), Parity Multisig Library (2017, ~$150M frozen).
- **FP:** Constructor calls `_disableInitializers()`. `initializer` modifier from OpenZeppelin `Initializable` is present and correctly gates the function. Implementation verifies it is being called through a proxy before executing any logic.

**23. ERC20 Non-Compliant: Return Values / Events**

- **Detect:** Custom `transfer()`/`transferFrom()` doesn't return `bool`, or always returns `true` on failure. `mint()` missing `Transfer(address(0), to, amount)` event. `burn()` missing `Transfer(from, address(0), amount)`. `approve()` missing `Approval` event. Breaks DEX and wallet composability.
- **FP:** OpenZeppelin `ERC20.sol` used as base with no custom overrides of the transfer/approve/event logic.

**24. Block Timestamp Dependence**

- **Detect:** `block.timestamp` used for game outcomes, randomness (`block.timestamp % N`), or auction timing where a 15-second manipulation changes the outcome. (SWC-116)
- **FP:** Timestamp used only for periods spanning hours or days, where 15-second validator manipulation has no meaningful impact on the outcome. Timestamp used only for event logging with no effect on state or logic.

**25. Deployment Transaction Front-Running (Ownership Hijack)**

- **Detect:** Deployment script broadcasts a contract creation transaction to the public mempool without using a private/protected transaction relay. An attacker sees the pending deployment, extracts the bytecode, and deploys an identical contract first with themselves as the owner — or front-runs the initialization with different parameters. For token contracts, the attacker can deploy to a predictable address and pre-seed liquidity pairs to manipulate trading. Pattern: deployment transactions sent via public RPC (`eth_sendRawTransaction`) without Flashbots Protect, MEV Blocker, or a private mempool relay. Constructor sets `owner = msg.sender` or `admin = tx.origin` without additional verification.
- **FP:** Deployment uses a private transaction relay (Flashbots Protect, MEV Blocker, private mempool). Owner address is passed as a constructor argument rather than derived from `msg.sender`. Deployment is on a chain without a public mempool (e.g., Arbitrum sequencer, private L2). Contract uses CREATE2 with a salt tied to the deployer's address.

**26. Merkle Proof Reuse — Leaf Not Bound to Caller**

- **Detect:** Merkle proof accepted without tying the leaf to `msg.sender`. Pattern: `require(MerkleProof.verify(proof, root, keccak256(abi.encodePacked(amount))))` or leaf contains only an address that is not checked against `msg.sender`. Anyone who observes the proof in the mempool can front-run and claim the same entitlement by submitting it from a different address.
- **FP:** Leaf explicitly encodes the caller: `keccak256(abi.encodePacked(msg.sender, amount))`. Function validates that the leaf's embedded address equals `msg.sender` before acting. Proof is single-use and recorded as consumed after the first successful call.

**27. Token Decimal Mismatch in Cross-Token Arithmetic**

- **Detect:** Protocol multiplies or divides token amounts using a hardcoded `1e18` denominator or assumes all tokens share the same decimals. USDC has 6 decimals, WETH has 18 — a formula like `price = usdcAmount * 1e18 / wethAmount` is off by 1e12. Pattern: collateral ratio, LTV, interest rate, or exchange rate calculations that combine two tokens' amounts with no per-token decimal normalization. `token.decimals()` is never called, or is called but its result is not used in scaling factors.
- **FP:** All amounts normalized to a canonical precision (WAD/RAY) immediately after transfer, using each token's actual `decimals()`. Explicit normalization factor `10 ** (18 - token.decimals())` applied per token before any cross-token arithmetic. Protocol only supports tokens with identical, verified decimals.

**28. Missing Nonce (Signature Replay)**

- **Detect:** Signed message has no per-user nonce, or nonce is present in the struct but never stored/incremented after use. Same valid signature can be submitted multiple times. (SWC-121)
- **FP:** Monotonic per-signer nonce included in signed payload, stored, checked for reuse, incremented atomically. `usedSignatures[hash]` mapping invalidates after first use.

**29. Upgrade Race Condition / Front-Running**

- **Detect:** Upgrade transaction submitted to a public mempool, creating a window for front-running (exploit old implementation before upgrade lands) or back-running (exploit assumptions the new implementation breaks). Multi-step upgrades are especially dangerous: `upgradeTo(V2)` lands in block N but `setNewParams(...)` is still pending -- attacker sandwiches between them. Pattern: `upgradeTo()` and post-upgrade configuration calls are separate transactions; no private mempool or bundling used; V2 is not safe with V1's state parameters.
- **FP:** Upgrade + initialization bundled into a single `upgradeToAndCall()` invocation. Flashbots Protect or private mempool used for upgrade transactions. V2 designed to be safe with V1's state from block 0. Timelock makes execution block predictable and protectable.

**30. ERC1155 uri() Missing {id} Substitution Causes Metadata Collapse**

- **Detect:** `uri(uint256 id)` returns a fully resolved URL (e.g., `"https://api.example.com/token/42"`) instead of a template containing the literal `{id}` placeholder as required by EIP-1155. Clients and marketplaces that follow the standard substitute the zero-padded 64-character hex token ID for `{id}` client-side — returning a fully resolved URL breaks this substitution, pointing all IDs to the same metadata endpoint or creating malformed double-substituted URLs. Additionally, if `uri(id)` returns an empty string or a hardcoded static value identical for all IDs, off-chain systems treat all tokens as identical, destroying per-token metadata and market value.
- **FP:** `uri(id)` returns a string containing the literal `{id}` substring per EIP-1155 spec, and clients substitute the hex-encoded token ID. Protocol overrides `uri(id)` to return a fully unique per-ID on-chain URI (e.g., full base64-encoded JSON) and explicitly documents deviation from the `{id}` substitution requirement.

**31. ERC721 / ERC1155 Type Confusion in Dual-Standard Marketplace**

- **Detect:** Marketplace or aggregator handles both ERC721 and ERC1155 in a shared `buy` or `fill` function using a type flag, but the `quantity` parameter required for ERC1155 amount is also accepted for ERC721 without validation that it equals 1. Price is computed as `price * quantity`. An attacker passes `quantity = 0` for an ERC721 listing — price calculation yields zero, NFT transfers successfully, payment is zero. Root cause of the TreasureDAO exploit (March 2022, $1.4M): `buyItem(listingId, 0)` for an ERC721 listing passed all checks and transferred the NFT for free.
- **FP:** ERC721 branch explicitly `require(quantity == 1)` before any price arithmetic. Separate code paths for ERC721 and ERC1155 with no shared quantity parameter. Price computed independently of quantity for ERC721 listings.

---

**32. CREATE2 Address Squatting (Counterfactual Front-Running)**

- **Detect:** A CREATE2-based deployment uses a salt that is not bound to the deployer's address (`msg.sender`). An attacker who knows the factory address, salt, and init code can precompute the deployment address and deploy there first (either via the same factory or a different one with matching parameters). For account abstraction wallets, this is especially dangerous: an attacker deploys a wallet to the user's counterfactual address with themselves as the owner, then receives funds intended for the legitimate user. Pattern: `CREATE2` salt is a user-supplied value, sequential counter, or derived from public data (e.g., `keccak256(username)`) without incorporating `msg.sender`. Factory's `deploy()` function is permissionless and does not bind salt to caller.
- **FP:** Salt incorporates `msg.sender`: `salt = keccak256(abi.encodePacked(msg.sender, userSalt))`. Factory restricts who can deploy: `require(msg.sender == authorizedDeployer)`. Init code includes owner address in constructor arguments, so different owners produce different init code hashes and thus different CREATE2 addresses.

**33. Signature Malleability**

- **Detect:** Raw `ecrecover(hash, v, r, s)` used without validating `s <= 0x7FFF...20A0`. Both `(v,r,s)` and `(v',r,s')` recover the same address. If signatures are used as unique identifiers (stored to prevent replay), a malleable variant bypasses the uniqueness check. (SWC-117)
- **FP:** OpenZeppelin `ECDSA.recover()` used (validates `s` range and `v`). Full message hash used as dedup key, not the signature bytes.

**34. ERC721/ERC1155 Callback Reentrancy**

- **Detect:** `safeTransferFrom` (ERC721) or `safeMint`/`safeTransferFrom` (ERC1155) called before state updates. These invoke `onERC721Received`/`onERC1155Received` on recipient contracts.
- **FP:** All state committed before the safe transfer. Function is `nonReentrant`.

**35. ERC721Enumerable Index Corruption on Burn or Transfer**

- **Detect:** Contract extends `ERC721Enumerable` and overrides `_beforeTokenTransfer` (OZ v4) or `_update` (OZ v5) without calling the corresponding `super` function. `ERC721Enumerable` maintains four interdependent index structures (`_ownedTokens`, `_ownedTokensIndex`, `_allTokens`, `_allTokensIndex`) that must be updated atomically on every mint, burn, and transfer. Skipping the super call leaves stale entries — `tokenOfOwnerByIndex` returns wrong token IDs, `ownerOf` for enumerable lookups resolves incorrectly, and `totalSupply` diverges from actual supply.
- **FP:** Override always calls `super._beforeTokenTransfer(from, to, tokenId, batchSize)` or `super._update(to, tokenId, auth)` as its first statement. Contract does not inherit `ERC721Enumerable` and tracks supply independently.

**36. Missing Chain ID Validation in Deployment Configuration**

- **Detect:** Deployment script reads RPC endpoint and chain parameters from environment variables or config files without validating that the connected chain matches the intended target. A misconfigured `RPC_URL` (e.g., mainnet URL in a staging config, or a compromised/rogue RPC endpoint) causes the script to deploy to the wrong chain with real funds, or to a chain where the deployment has different security assumptions. Pattern: script reads `$RPC_URL` from `.env` without calling `eth_chainId` and asserting it matches the expected value. Foundry script without `--chain-id` flag or `block.chainid` assertion. No dry-run or simulation step before broadcast.
- **FP:** Script asserts `require(block.chainid == expectedChainId)` at the start. Foundry `--verify` flag combined with explicit `--chain` parameter. CI/CD pipeline validates chain ID before executing deployment. Multi-chain deployment framework (e.g., Foundry multi-fork) with per-chain config validated against RPC responses.

**37. Paymaster Gas Penalty Undercalculation**

- **Detect:** Paymaster computes the prefund amount as `requiredPreFund + (refundPostopCost * maxFeePerGas)` without including the 10% penalty the EntryPoint applies to unused execution gas (`postOpUnusedGasPenalty`). When a UserOperation specifies a large `executionGasLimit` and uses little of it, the EntryPoint deducts a penalty the paymaster did not budget for, draining its deposit. Pattern: prefund formula lacks any reference to unused-gas penalty or `_getUnusedGasPenalty`.
- **FP:** Prefund calculation explicitly adds the unused-gas penalty: `requiredPreFund + penalty + (refundCost * price)`. Paymaster uses conservative overestimation that covers worst-case penalty.

**38. Off-By-One in Bounds or Range Checks**

- **Detect:** (1) Loop upper bound uses `<=` instead of `<` on an array index: `for (uint i = 0; i <= arr.length; i++)` — accesses `arr[arr.length]` on the final iteration, reverting or reading uninitialized memory. (2) `arr[arr.length - 1]` or `arr[index - 1]` without a preceding `require(arr.length > 0)` / `require(index > 0)` — in `unchecked` blocks the underflow silently wraps to a huge index. (3) Inclusive/exclusive boundary confusion in financial logic: `require(block.timestamp >= vestingEnd)` vs. `> vestingEnd`, or `require(amount <= MAX)` where MAX was intended as exclusive — one unit of difference causes early unlock or allows a boundary-exceeding deposit. (4) Cumulative distribution: allocating a total across N recipients using integer division, where rounding errors accumulate and the final recipient receives more or less than intended.
- **FP:** Loop uses `<` not `<=` and the upper bound is a fixed-length array or a compile-time constant — overflow into out-of-bounds is structurally impossible. Last-element access is always preceded by a `require(arr.length > 0)` or equivalent in the same scope. Financial boundary comparisons (`>=` vs `>`) are demonstrably correct for the invariant being enforced (e.g., `>= vestingEnd` for an inclusive deadline, `< MAX` for an exclusive cap).

**39. ERC4626 Mint/Redeem Asset-Cost Asymmetry**

- **Detect:** For the same share count `s`, `redeem(s)` returns more assets than `mint(s)` costs — so cycling redeem → remint yields a net profit on every loop. Equivalently, `mint(redeem(s).shares)` costs fewer assets than `redeem(s)` returned. Root cause: `_convertToAssets` rounds up in `redeem` (user receives more) and rounds down in `mint` (user pays less), the opposite of what EIP-4626 requires. The spec mandates that `redeem` rounds down (vault keeps the rounding error) and `mint` rounds up (user pays the rounding error). Pattern: `previewRedeem` and `redeem` call `_convertToAssets(shares, Rounding.Ceil)` while `previewMint` and `mint` call `_convertToAssets(shares, Rounding.Floor)`. The delta between the two is extractable per cycle. (Covers `prop_RT_mint_redeem` and `prop_RT_redeem_mint` from the a16z ERC4626 property test suite.)
- **FP:** `redeem`/`previewRedeem` call `_convertToAssets(shares, Math.Rounding.Floor)` and `mint`/`previewMint` call `_convertToAssets(shares, Math.Rounding.Ceil)`. OpenZeppelin ERC4626 used without custom conversion overrides.

---

**40. Blacklistable or Pausable Token in Critical Payment Path**

- **Detect:** Protocol hard-codes or accepts USDC, USDT, or another token with admin-controlled blacklisting or global pause, and routes payments through a push model: `token.transfer(recipient, amount)`. If `recipient` is blacklisted by the token issuer, or the token is globally paused, every push to that address reverts — permanently bricking withdrawals, liquidations, fee collection, or reward claims. Attacker can weaponize this by ensuring a critical address (vault, fee receiver, required counterparty) is blacklisted. Also relevant: protocol sends fee to a fixed `feeRecipient` inside a state-changing function — if `feeRecipient` is blacklisted, the entire function is permanently DOSed.
- **FP:** Pull-over-push: recipients withdraw their own funds; a blacklisted recipient only blocks themselves. Skip-on-failure logic (`try/catch`) used for fee or reward distribution. Supported token whitelist explicitly excludes blacklistable/pausable tokens.

**41. Nonce Gap from Reverted Transactions (CREATE Address Mismatch)**

- **Detect:** Deployment script uses `CREATE` (not CREATE2) and pre-computes expected contract addresses based on the deployer's nonce. If any transaction reverts or if an unrelated transaction is sent from the deployer EOA between script runs, the nonce advances but no contract is deployed. Subsequent deployments land at different addresses than expected, and contracts that were pre-configured to reference the expected addresses now point to empty addresses or wrong contracts. Pattern: script pre-computes addresses via `address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), deployer, nonce)))))` and hardcodes them into other contracts. Multiple scripts share the same deployer EOA without coordinated nonce management. Deployment script assumes a specific starting nonce.
- **FP:** `CREATE2` used with deterministic addressing (nonce-independent). Script reads current nonce from chain via `eth_getTransactionCount` before computing addresses. Addresses are captured from actual deployment receipts and passed forward, never pre-assumed. Dedicated deployer EOA used per deployment (fresh nonce = 0).

**42. Nested Mapping Inside Struct Not Cleared on `delete`**

- **Detect:** `delete myMapping[key]` or `delete myArray[i]` where the deleted item is a struct containing a `mapping` or a dynamic array. Solidity's `delete` zeroes primitive fields but does not recursively clear mappings — the nested mapping's entries persist in storage. If the same key is later reused (e.g., a re-deposited user, re-created proposal), old mapping values are unexpectedly visible. Pattern: struct with `mapping(address => uint256)` or `uint256[]` field; `delete` called on the struct without manually iterating and clearing the nested mapping.
- **FP:** Nested mapping manually cleared before `delete` (iterate and zero every entry). Struct key is never reused after deletion. Codebase explicitly accounts for residual mapping values in subsequent reads (always initialises before use).

**43. ERC1155 ID-Based Role Access Control With Publicly Mintable Role Tokens**

- **Detect:** Protocol implements access control by checking ERC1155 token balance: `require(balanceOf(msg.sender, ADMIN_ROLE_ID) > 0)` or `require(balanceOf(msg.sender, MINTER_ROLE_ID) >= 1)`. The role token IDs (`ADMIN_ROLE_ID`, `MINTER_ROLE_ID`) are public constants. If the ERC1155 `mint` function for those IDs is not separately access-controlled — e.g., it's callable by any holder of a lower-tier token, or via a public presale — any attacker can acquire the role token and gain elevated privileges. Role tokens are also transferable by default, creating a secondary market for protocol permissions.
- **FP:** Minting of all role-designated token IDs is gated behind a separate access control system (e.g., OZ `AccessControl` with `MINTER_ROLE` on the ERC1155 contract itself). Role tokens for privileged IDs are non-transferable: `_beforeTokenTransfer` reverts for those IDs when `from != address(0) && to != address(0)`. Protocol uses a dedicated non-token access control system rather than ERC1155 balances for privilege gating.

**44. Missing onERC1155BatchReceived Causes Token Lock on Batch Transfer**

- **Detect:** Receiving contract implements `IERC1155Receiver.onERC1155Received` (for single transfers) but not `IERC1155Receiver.onERC1155BatchReceived` (for batch transfers), or implements the latter returning a wrong selector. `safeBatchTransferFrom` to such a contract reverts on the callback check, permanently preventing batch delivery. Protocol that accepts individual deposits from users but attempts batch settlement or batch reward distribution internally will be permanently stuck if the recipient is one of these incomplete receivers. Pattern: `onERC1155BatchReceived` is absent, `returns (bytes4(0))`, or reverts unconditionally.
- **FP:** Contract implements both `onERC1155Received` and `onERC1155BatchReceived` returning the correct selectors, or inherits from OZ `ERC1155Holder` which provides both. Protocol's internal settlement exclusively uses single-item `safeTransferFrom` and is documented to never issue batch calls to contract recipients.
