# Geth Fork / EVM L2 Vulnerability Patterns

Target chains: Scroll, Optimism, ZKsync, Berachain, Citrea, Rootstock, Whitechain, KUB Chain, Cronos EVM

## Architecture Context

```
Custom consensus / sequencer
    |
Modified Geth (go-ethereum fork)
    - Modified EVM (custom opcodes, precompiles)
    - Modified state management
    - Modified P2P (sequencer mode)
    - Modified transaction pool (L2 batch handling)
    |
Original Geth baseline
```

Key: Most L2s fork Geth and modify specific components. Bugs live at the boundaries between modified and unmodified code.

---

## GETH-001: Custom Precompile Vulnerabilities

**Impact:** Critical (arbitrary code execution, fund theft, chain halt)
**This is the #1 attack surface for Geth forks.**

L2s add custom precompiled contracts for L1<->L2 communication, special cryptographic operations, or performance.

**What to check:**
- **Input validation**: Does the precompile validate input length and format before processing?
- **Gas calculation**: Does `RequiredGas()` accurately reflect actual computation cost?
- **Out-of-bounds access**: Does the precompile index into input without bounds checking?
- **Panic handling**: Can the precompile panic? Is the panic recovered?
- **State modification**: Can a precompile modify state in ways that bypass EVM invariants?
- **Reentrancy**: Can a precompile call back into the EVM? Is this safe?

**Pattern:**
```go
// BUG: no bounds check on input
func (c *CustomPrecompile) Run(input []byte) ([]byte, error) {
    offset := binary.BigEndian.Uint32(input[0:4])
    length := binary.BigEndian.Uint32(input[4:8])
    data := input[offset:offset+length] // panic if offset+length > len(input)
    return process(data), nil
}
```

**Pattern: Gas underestimation**
```go
// BUG: RequiredGas returns constant but Run does O(n) work
func (c *CustomPrecompile) RequiredGas(input []byte) uint64 {
    return 1000 // should scale with input size
}
```

**Grep for:** `precompile`, `PrecompiledContract`, `RequiredGas`, `Run(input`

---

## GETH-002: Modified Opcode Behavior

**Impact:** Critical (consensus divergence, unexpected execution)

Some L2s modify EVM opcode behavior (e.g., SELFDESTRUCT, DIFFICULTY/PREVRANDAO, PUSH0).

**What to check:**
- Which opcodes are modified? Are the modifications correct?
- Do modified opcodes maintain backward compatibility where expected?
- Are gas costs correct for modified opcodes?
- Do modified opcodes interact correctly with other opcodes?
- SELFDESTRUCT changes: is the deprecated behavior handled correctly?
- PREVRANDAO: is the value set correctly in L2 context?

**Grep for:** `opcode`, `instruction`, `SELFDESTRUCT`, `PREVRANDAO`, `PUSH0`, `JumpTable`

---

## GETH-003: Sequencer / Block Production Bugs

**Impact:** High to Critical (censorship, invalid state, fund theft)

L2 sequencers replace Geth's consensus with centralized (or semi-centralized) block production.

**What to check:**
- **Single sequencer failure**: What happens if the sequencer goes down? Is there a fallback?
- **Forced inclusion**: Can users force-include transactions if the sequencer censors them?
- **Sequencer equivocation**: Can the sequencer produce two different blocks at the same height?
- **L1 derivation**: For optimistic rollups, is the L2 state correctly derived from L1 data?
- **Batch submission**: Are submitted batches validated? Can a malicious sequencer submit invalid batches?
- **Timestamp manipulation**: Does the sequencer control the L2 block timestamp? Within what bounds?

**Grep for:** `sequencer`, `batcher`, `proposer`, `derivation`, `ForceInclusion`, `L1Origin`

---

## GETH-004: L1 <-> L2 Bridge Bugs

**Impact:** Critical (cross-layer fund theft)

The bridge between L1 and L2 is often the highest-value target.

**What to check:**
- **Deposit processing**: Are L1 deposits correctly credited on L2?
- **Withdrawal processing**: Are L2 withdrawals correctly processed on L1?
- **Message replay**: Can the same L1->L2 or L2->L1 message be replayed?
- **Message forgery**: Can a message appear to come from L1 when it didn't?
- **Proof verification**: For optimistic rollups, is the fraud proof system correct? For ZK rollups, is the validity proof verification correct?
- **Finality**: When is a withdrawal considered final? Can it be reverted?

**Pattern: Deposit origin spoofing**
```go
// BUG: L2 contract checks msg.sender == bridge
// But attacker calls bridge.depositTransaction() with forged _to and _data
// The bridge relays the message, and on L2 it appears to come from a trusted address
```

**Grep for:** `deposit`, `withdrawal`, `bridge`, `CrossDomain`, `L1Block`, `portal`

---

## GETH-005: State Root Divergence

**Impact:** Critical (chain split, invalid fraud/validity proofs)

L2 execution must be exactly deterministic. Any divergence between sequencer and verifier causes issues.

**What to check:**
- **Modified state trie**: If the L2 modifies the Merkle Patricia Trie (e.g., different hash function), is it consistent?
- **Different execution environments**: Does the fraud prover / ZK prover execute identically to the sequencer?
- **Gas metering differences**: If gas costs were modified, are they modified identically everywhere?
- **Fee recipient handling**: Is the fee recipient (sequencer address) deterministic?
- **System transactions**: L2s often have system transactions at block boundaries. Are they deterministic?

---

## GETH-006: Modified Transaction Pool (Mempool)

**Impact:** Medium to High (DoS, censorship, ordering manipulation)

L2 mempools are often modified to handle L2-specific transaction types.

**What to check:**
- **L2 transaction types**: Deposit transactions, system transactions -- are they handled correctly?
- **Fee market**: Modified EIP-1559 (L1 data fee + L2 execution fee) -- are both calculated correctly?
- **Priority ordering**: How are transactions ordered? Can sequencer priority be manipulated?
- **Size limits**: Are L2-specific transaction types subject to the same size limits?

---

## GETH-007: EVM Gas Limit Edge Cases

**Impact:** Medium to High (DoS, economic exploits)

**What to check:**
- **Block gas limit**: Is it enforced correctly with L2 modifications?
- **Intrinsic gas**: Is intrinsic gas (base cost per transaction) calculated correctly for L2 transaction types?
- **Call depth limit**: Is the 1024 call depth limit enforced with custom precompiles?
- **Memory expansion gas**: Is memory gas calculated correctly with custom opcodes?
- **Refund cap**: Is the gas refund cap (max 1/5 of gas used since EIP-3529) applied correctly?

---

## GETH-008: RPC Divergence from Standard Geth

**Impact:** Medium (DoS, information leakage, application-level bugs)

L2s modify or add RPC endpoints.

**What to check:**
- **Custom RPC methods**: Are they properly authenticated/rate-limited?
- **Modified behavior**: If `eth_getBlockByNumber` returns L2-specific fields, is it handled safely?
- **L1 fee queries**: New endpoints for L1 data cost estimation -- can they be abused?
- **Debug endpoints**: Are debug/trace endpoints disabled in production?

---

## GETH-009: Upgrade / Hard Fork Transition Bugs

**Impact:** High to Critical (chain split, state corruption)

Geth forks need to track upstream Geth changes plus their own modifications.

**What to check:**
- **Upstream merge conflicts**: Did merging upstream changes break any custom modifications?
- **Activation block/time**: Are network upgrades activated at the correct L2 block?
- **Fork choice interaction**: Does the L2 fork choice correctly interact with L1 finality?
- **Pre/post-fork state**: Are state transitions across the fork boundary correct?

---

## GETH-010: Rollup-Specific Patterns

### Optimistic Rollups (Optimism, Base, etc.)
- **Fraud proof window**: Is the 7-day challenge window enforced?
- **Dispute game**: Can the dispute game be griefed or manipulated?
- **Output root**: Is the output root correctly computed and verifiable?

### ZK Rollups (Scroll, ZKsync, etc.)
- **Circuit soundness**: Does the ZK circuit correctly encode EVM execution?
- **Data availability**: Is all necessary data posted to L1?
- **Proof verification gas**: Is the on-chain proof verification correctly gas-costed?
- **Prover liveness**: What happens if the prover goes offline?

### Bitcoin Rollups (Citrea, Rootstock)
- **Bitcoin script verification**: Is the BitVM verification correct?
- **Peg mechanism**: Is the 2-way peg secure?
- **Bitcoin finality**: How many Bitcoin confirmations are required?

---

## Scan Priority

For Geth forks, prioritize in this order:
1. Custom precompiles (GETH-001) -- highest bug density
2. L1<->L2 bridge (GETH-004) -- highest financial impact
3. Sequencer logic (GETH-003) -- unique to L2
4. Modified opcodes (GETH-002) -- subtle but critical
5. State root computation (GETH-005) -- chain-breaking if wrong
6. Everything else
