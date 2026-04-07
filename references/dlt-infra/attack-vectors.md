# Blockchain Infrastructure Attack Vector Catalog

Master reference for all DLT/infrastructure attack vectors. Organized by attack surface.
Each vector has: ID, description, impact, detection strategy, and example code pattern.

---

## 1. CONSENSUS ATTACK VECTORS

### CON-001: BFT Quorum Manipulation
**D:** Exploit off-by-one or boundary conditions in quorum calculation to accept blocks with insufficient votes.
**Impact:** Invalid blocks finalized, double-spend possible.
**Detect:** Read quorum calculation. Check: is it `>= 2*f+1` or `> 2*f`? What is `f`? Is `n = 3f+1` enforced?
**FP:** Edge case at minimum validator set sizes (n=1,2,3,4).

### CON-002: Duplicate Vote Counting
**D:** Same validator's vote counted multiple times in quorum tally due to missing deduplication.
**Impact:** Quorum reached with fewer distinct validators than required.
**Detect:** Check vote set data structure. Is there a unique constraint on validator ID per round?

### CON-003: Cross-Round Vote Leakage
**D:** Votes from a previous consensus round accepted in the current round, inflating the vote count.
**Impact:** Premature quorum, invalid finalization.
**Detect:** Check vote message includes round number and is validated.

### CON-004: Proposer Grinding
**D:** Validator manipulates randomness seed to influence proposer selection in their favor.
**Impact:** Unfair block production, MEV extraction, censorship.
**Detect:** Check proposer selection algorithm. Is the seed derivation resistant to grinding (e.g., VRF)?

### CON-005: Time Manipulation
**D:** Byzantine validator sends votes with extreme timestamps that skew the median block time.
**Impact:** Time-dependent logic (unbonding, governance) can be manipulated. Chain halt if time goes backwards.
**Detect:** Check timestamp bounds validation on individual votes and blocks. Check MedianTime calculation.

### CON-006: Long-Range Attack
**D:** Attacker with historical validator keys creates a valid alternative chain starting from far in the past.
**Impact:** Chain rewrite, double-spend of historical transactions.
**Detect:** Check for weak subjectivity period enforcement, checkpoint system.

### CON-007: Nothing-at-Stake
**D:** In PoS without slashing, validators can vote on multiple forks without penalty.
**Impact:** Consensus failure, fork instability.
**Detect:** Check slashing conditions for equivocation (double voting).

### CON-008: Consensus Halt via Minority Veto
**D:** 1/3+ of validators can halt consensus by refusing to vote, and there's no timeout/round-skip mechanism.
**Impact:** Chain halt, liveness failure.
**Detect:** Check timeout handling. What happens when quorum isn't reached within timeout?

### CON-009: State Machine Replication Non-Determinism
**D:** Transaction execution produces different results on different validators due to non-deterministic code.
**Impact:** Consensus divergence, chain split.
**Detect:** Check for map iteration (Go), floating point, time.Now(), goroutines, external calls in execution.

### CON-010: Finality Reversion
**D:** Finalized blocks can be reverted through a chain reorg that shouldn't be possible.
**Impact:** Double-spend of "confirmed" transactions.
**Detect:** Check finality conditions. Can a reorg cross the finality boundary?

---

## 2. P2P / NETWORKING ATTACK VECTORS

### NET-001: Message Deserialization Panic
**D:** Malformed P2P message causes node crash via panic/unwrap on untrusted data.
**Impact:** Node crash, network DoS if all nodes are affected.
**Detect:** Find all message handlers. Check every deserialization for error handling. Check every array index for bounds check.

### NET-002: Amplification Attack
**D:** Small request triggers large response, or message re-broadcast without deduplication.
**Impact:** Network bandwidth exhaustion, node resource exhaustion.
**Detect:** Check message-to-response size ratio. Check gossip deduplication.

### NET-003: Eclipse Attack via Peer Table Poisoning
**D:** Attacker fills target's peer table with malicious peers, isolating it from the honest network.
**Impact:** Isolated node accepts attacker-controlled chain, double-spend.
**Detect:** Check peer discovery mechanism. Is there diversity enforcement? IP range limits?

### NET-004: Connection Exhaustion (Slowloris)
**D:** Attacker opens many connections and holds them without completing handshake or sending data.
**Impact:** Honest peers can't connect to the target node.
**Detect:** Check connection timeouts, max connection limits, handshake deadlines.

### NET-005: Gossip Message Injection
**D:** Invalid but expensive-to-verify message injected into gossip, wasting network resources.
**Impact:** CPU exhaustion across all nodes processing the invalid message.
**Detect:** Check gossip validation order. Are cheap checks (size, format) done before expensive checks (signature)?

### NET-006: Peer Scoring Manipulation
**D:** Attacker behaves well to build high peer score, then misbehaves while being retained due to high score.
**Impact:** Sustained misbehavior from high-scored malicious peers.
**Detect:** Check peer scoring decay and negative event impact. Can negative events override accumulated positive score?

### NET-007: DNS Seed Hijacking
**D:** Attacker compromises DNS seeds to direct new nodes to malicious peers.
**Impact:** New nodes eclipse attacked from bootstrap.
**Detect:** Check how DNS seeds are resolved. Are there multiple independent seeds? Is there fallback?

### NET-008: Bandwidth Exhaustion via Block Requests
**D:** Attacker repeatedly requests historical blocks/state, consuming target's upload bandwidth.
**Impact:** Target node can't serve honest peers, degrades network connectivity.
**Detect:** Check rate limiting on block/state serving. Check per-peer request limits.

---

## 3. STATE MACHINE ATTACK VECTORS

### STATE-001: Integer Overflow in Token Arithmetic
**D:** Unchecked arithmetic on token amounts wraps around, creating or destroying tokens.
**Impact:** Infinite minting or fund loss.
**Detect:** Check all arithmetic on balance/amount types. Are checked operations used?

### STATE-002: Missing Authorization Check
**D:** State-modifying operation doesn't verify the caller is authorized.
**Impact:** Unauthorized state changes, fund theft.
**Detect:** Check every message handler / extrinsic for signer/origin verification.

### STATE-003: Partial State Update (Atomicity Failure)
**D:** Multi-step state change fails midway, leaving state inconsistent.
**Impact:** Fund loss (debit without credit), state corruption.
**Detect:** Check multi-step operations. Are all changes committed atomically? What happens on error mid-way?

### STATE-004: State Bloat via Unbounded Storage
**D:** User can create unlimited state entries without proportional cost.
**Impact:** State tree growth, node storage exhaustion, slower processing.
**Detect:** Check storage writes. Is there a deposit/fee for state creation? Is there a size/count limit?

### STATE-005: Replay Attack
**D:** Valid transaction executed multiple times due to missing nonce/replay protection.
**Impact:** Double-spend, fund drain.
**Detect:** Check transaction signing (chain ID, nonce, domain separator). Check nonce validation.

### STATE-006: Front-Running / Sandwich
**D:** Proposer reorders transactions for profit.
**Impact:** User gets worse execution price, value extracted by proposer.
**Detect:** Check transaction ordering mechanism. Is there commit-reveal or fair ordering?

### STATE-007: Storage Key Collision
**D:** Two different state objects hash to the same storage key, overwriting each other.
**Impact:** State corruption, potential fund theft.
**Detect:** Check key derivation. Is the key prefix unique per module? Are all key components included?

### STATE-008: Gas / Weight Underpricing
**D:** Operation costs more resources than its gas/weight price reflects.
**Impact:** DoS by executing cheap-but-expensive operations.
**Detect:** Benchmark operations and compare to gas/weight cost. Look for O(n) operations with O(1) cost.

---

## 4. CRYPTOGRAPHIC ATTACK VECTORS

### CRYPTO-001: Signature Malleability
**D:** Multiple valid signatures exist for the same (message, key), enabling transaction ID manipulation.
**Impact:** Transaction replay, double-counting, exchange confusion.
**Detect:** Check signature normalization. secp256k1: low-S enforced? Ed25519: cofactor checked?

### CRYPTO-002: Merkle Tree Second Preimage
**D:** Leaf and internal node hash domains overlap, allowing a leaf to be confused with a subtree.
**Impact:** Fake Merkle proofs, state proof forgery.
**Detect:** Check leaf vs node hashing. Is there a domain separator (0x00 prefix for leaves, 0x01 for nodes)?

### CRYPTO-003: Missing Signature Verification
**D:** Code path where signature verification is skipped entirely.
**Impact:** Forged transactions/blocks accepted.
**Detect:** Trace every message type from receipt to processing. Is signature checked on all paths?

### CRYPTO-004: Weak Randomness
**D:** Random number generation uses predictable or manipulable seed.
**Impact:** Predictable leader election, exploitable lottery/auction.
**Detect:** Check RNG seeding. Is it based on block hash (manipulable by proposer)? Is it a VRF?

### CRYPTO-005: BLS Rogue Key Attack
**D:** Attacker crafts a BLS public key that cancels out honest keys in aggregate, allowing forgery.
**Impact:** Forged aggregate signatures, consensus bypass.
**Detect:** Check for proof-of-possession requirement on BLS key registration.

### CRYPTO-006: Hash Length Extension
**D:** SHA-256(secret || user_data) used as MAC, allowing attacker to append data without knowing secret.
**Impact:** Authentication bypass, message forgery.
**Detect:** Check MAC constructions. Are HMAC or SHA-3/Blake2 used instead of raw hash(secret || data)?

---

## 5. RPC / API ATTACK VECTORS

### RPC-001: Unauthenticated Admin Endpoint
**D:** Admin/debug RPC methods exposed on public interface without authentication.
**Impact:** Remote node control, data deletion, network manipulation.
**Detect:** Check RPC server config. Which namespaces are bound to which interfaces?

### RPC-002: Unbounded Query Response
**D:** Query endpoint returns all results without pagination, exhausting node memory.
**Impact:** Node OOM crash.
**Detect:** Check query endpoints for limit/pagination parameters. What's the maximum response size?

### RPC-003: Expensive Computation on Demand
**D:** RPC endpoint triggers expensive computation (trace replay, state proof) without resource limits.
**Impact:** CPU exhaustion, node unresponsive.
**Detect:** Check for timeout/gas limit on simulation endpoints (eth_call, debug_traceTransaction).

### RPC-004: WebSocket Subscription Flooding
**D:** Client opens unlimited subscriptions, each generating events the node must track and send.
**Impact:** Memory exhaustion, network bandwidth exhaustion.
**Detect:** Check subscription limits per connection, total subscription limits, event buffer sizes.

---

## 6. VALIDATOR / STAKING ATTACK VECTORS

### VAL-001: Reward Calculation Overflow
**D:** Reward computation overflows integer type, resulting in huge or zero rewards.
**Impact:** Infinite minting or reward theft.
**Detect:** Check reward calculation arithmetic. Are intermediate products bounded?

### VAL-002: Slashing Escape
**D:** Validator commits slashable offense but avoids slashing by unbonding before evidence is processed.
**Impact:** Unavoidable misbehavior, no accountability.
**Detect:** Check: does slashing apply to unbonding delegations? Is there an evidence age limit?

### VAL-003: Delegation Arithmetic Bug
**D:** Share/token conversion in delegation rounding creates or destroys value.
**Impact:** Rounding theft or first-depositor attack.
**Detect:** Check share price calculation. What happens with 0 shares, 1 share, MAX shares?

### VAL-004: Governance Parameter Bomb
**D:** Governance changes a critical parameter to a dangerous value (unbonding period = 0, slash fraction = 100%).
**Impact:** Immediate fund loss or security property violation.
**Detect:** Check parameter change bounds. Are there min/max limits on critical parameters?

### VAL-005: Validator Set Size Manipulation
**D:** Attacker manipulates validator set size to 0 (halt) or 1 (centralization) or MAX (performance degradation).
**Impact:** Chain halt, centralization, or DoS.
**Detect:** Check validator set size bounds. What's the min/max? Are they enforced at set update time?

---

## 7. CROSS-CHAIN / BRIDGE ATTACK VECTORS

### BRIDGE-001: Message Replay
**D:** Cross-chain message executed multiple times due to missing or bypassable replay protection.
**Impact:** Double-mint on destination, double-withdraw.
**Detect:** Check message nonce/ID tracking. Is execution status stored and checked?

### BRIDGE-002: Fake Message Injection
**D:** Attacker crafts a message that appears to come from the source chain but wasn't actually sent.
**Impact:** Arbitrary minting on destination chain.
**Detect:** Check message verification (signatures, proofs, relayer trust model).

### BRIDGE-003: Finality Assumption Mismatch
**D:** Bridge accepts message from source chain before finality, source chain reorgs, message becomes invalid.
**Impact:** Funds unlocked on destination for transaction that was reverted on source.
**Detect:** Check finality requirements. How many confirmations are required? Does it account for reorgs?

### BRIDGE-004: Token Mapping Confusion
**D:** Different tokens on source and destination mapped to the same bridge token, or vice versa.
**Impact:** Token theft through mapping confusion.
**Detect:** Check token registry. Is the mapping 1:1? Can tokens be registered that collide with existing tokens?

---

## Usage

When scanning a codebase, use these vectors as a checklist. For each vector:
1. Determine if the codebase has the relevant component (e.g., skip BRIDGE vectors if no bridge)
2. Locate the relevant code (use grep patterns)
3. Assess whether the protection exists
4. If protection is missing or insufficient, form a hypothesis and proceed through gates
