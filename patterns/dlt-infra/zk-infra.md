# ZK (Zero-Knowledge Proof) Infrastructure Vulnerability Patterns

Target chains/systems: ZKsync Era/Lite/OS, StarkEx, Starknet, RISC Zero, zkVerify, ADI Foundation, Citrea (ZK aspects)

## Architecture Context

```
Application / Smart Contracts (Solidity, Cairo, Noir, Circom, etc.)
    |
ZK Virtual Machine / Execution Environment
    - zkEVM (ZKsync Era, Scroll, Polygon zkEVM) -- proves EVM execution
    - Cairo VM (StarkEx, Starknet) -- proves Cairo program execution
    - RISC-V zkVM (RISC Zero) -- proves RISC-V program execution
    |
Arithmetization Layer
    - Converts computation into polynomial constraints
    - R1CS (Groth16), PLONKish (PLONK, halo2), AIR (STARKs)
    |
Proof System
    - Prover: generates proof from witness + circuit (off-chain, heavy computation)
    - Verifier: checks proof on-chain or off-chain (cheap, constant/log time)
    |
Commitment Scheme
    - KZG / Kate commitments (trusted setup required)
    - FRI (Fast Reed-Solomon IOP) (no trusted setup, used by STARKs)
    - IPA / Bulletproofs (no trusted setup, logarithmic verification)
    |
L1 Settlement / Data Availability
    - On-chain verifier contract (Solidity)
    - Calldata or blob for data availability
    - State diff or full transaction data posted
```

Key concepts:
- **Soundness**: A malicious prover cannot convince the verifier of a false statement. Soundness breaks are critical -- they allow theft of all funds in a rollup.
- **Completeness**: An honest prover can always convince the verifier. Completeness breaks cause liveness failures (prover cannot produce valid proofs).
- **Zero-knowledge**: The proof reveals nothing beyond the truth of the statement. ZK breaks leak private data (relevant for privacy applications, less so for rollups).
- **Witness**: Private inputs to the circuit that the prover knows but the verifier does not see.
- **Circuit / Constraints**: The algebraic representation of the computation being proved. Every valid computation must satisfy all constraints, and ideally no invalid computation should.

Rollup-specific flow:
```
1. Sequencer orders transactions and produces L2 blocks
2. Prover takes the block and generates a ZK proof that the state transition is valid
3. Proof + state commitment (+ data availability) posted to L1
4. L1 verifier contract checks the proof
5. If valid, the new state root is accepted on L1
6. Users can withdraw funds against the new state root
```

---

## ZK-001: Circuit Constraint Under-Specification

**Impact:** Critical (soundness break -- prover can prove false statements, steal all rollup funds)
**Frequency:** The most common and most dangerous class of ZK bugs

A ZK circuit encodes a computation as a system of polynomial constraints. If the constraints are insufficient -- meaning they do not fully constrain all witness variables -- then a malicious prover can assign arbitrary values to under-constrained variables and produce a valid proof for a false statement.

**What to check:**
- **Unconstrained witness variables**: Every witness variable allocated in the circuit must appear in at least one constraint. A variable that appears nowhere in the constraint system can take any value.
- **Missing range checks**: Field elements can be very large (e.g., 254 bits for BN254). If a value is supposed to be a boolean (0 or 1), an 8-bit byte, or a 32-bit integer, there must be explicit range constraints. Without them, the prover can assign values outside the intended range.
- **Missing equality constraints**: If two sub-circuits should operate on the same value, the wire connecting them must be explicitly constrained to be equal. Copy constraints in PLONK-based systems or explicit equality constraints in R1CS must be present.
- **Missing output constraints**: If the circuit computes a result but never constrains the output to match the public input, the proof proves nothing useful.
- **Conditional logic flaws**: When a circuit branches (e.g., `if condition then A else B`), both branches are typically evaluated, and a selector chooses which result to use. If the selector is not properly constrained, the prover can mix results from both branches.
- **Bit decomposition errors**: When decomposing a field element into bits, verify that (a) each bit is constrained to be 0 or 1, (b) the recomposition equals the original value, and (c) the number of bits is sufficient for the field.

**Pattern (Circom -- R1CS):**
```circom
// BUG: signal 'intermediate' is assigned but never constrained
template BadMultiply() {
    signal input a;
    signal input b;
    signal output c;
    signal intermediate;

    intermediate <-- a * b;  // assignment only, no constraint!
    c <== a + b;             // this constrains c = a + b, but 'intermediate' is free

    // FIX: use <== which both assigns AND constrains
    // intermediate <== a * b;
    // or equivalently:
    // intermediate <-- a * b;
    // intermediate === a * b;
}
```

**Pattern (halo2 / PLONKish):**
```rust
// BUG: witness cell allocated but no gate constrains it
fn assign_region(&self, region: &mut Region<F>) -> Result<(), Error> {
    let val = region.assign_advice(
        || "unconstrained value",
        self.config.advice_col,
        0,
        || Value::known(F::from(42)),
    )?;
    // Missing: no constraint gate references this cell
    // The prover can put ANY value here and the proof still verifies
    Ok(())
}
```

**Pattern (Cairo / StarkNet):**
```cairo
// BUG: assert is used for hints but the constraint is missing
func compute_sqrt{range_check_ptr}(value: felt) -> (result: felt) {
    let result = sqrt_hint(value);  // hint provides the value, not a constraint
    // Missing: assert result * result = value;
    // Without the assertion, 'result' can be anything
    return (result=result);
}
```

**Grep for:** `<--` (Circom assignment without constraint), `assign_advice` / `assign_fixed` without corresponding `create_gate` (halo2), `witness` / `hint` without `assert` or `constrain` (general), `alloc` / `alloc_input` without `enforce` (bellman), `_unchecked`, `unsafe`

---

## ZK-002: Fiat-Shamir Transcript Manipulation ("Frozen Heart")

**Impact:** Critical (soundness break -- attacker can forge proofs)
**Frequency:** Has affected multiple production proof systems (Plonky2, Bulletproofs, bellman, etc.)

The Fiat-Shamir heuristic transforms an interactive proof into a non-interactive one by replacing the verifier's random challenges with hash outputs. The hash (transcript) must include ALL relevant public inputs, prover messages, and protocol parameters. If any are omitted, an attacker can manipulate the challenge values by choosing inputs that produce favorable hashes.

**What to check:**
- **Missing public inputs in transcript**: All public inputs must be absorbed into the transcript before deriving challenges. If a public input is omitted, the prover can change it freely without affecting the challenges.
- **Missing prover commitments**: All commitments sent by the prover in earlier rounds must be included in the transcript before subsequent challenge computation.
- **Missing domain separators**: Different protocols or different instances of the same protocol should use domain separators in their transcripts. Without them, a proof from one context may be valid in another.
- **Missing circuit/verification key**: The verification key or circuit description must be part of the transcript. Otherwise, a proof generated for one circuit may verify under a different circuit.
- **Weak hash function**: The hash function must behave as a random oracle. Using a non-cryptographic hash or a hash with known weaknesses breaks the model.
- **Transcript ordering**: The order in which elements are absorbed matters. Swapping two elements can lead to different (potentially exploitable) challenge values.
- **Proof system library version**: Check if the proof system library has known Fiat-Shamir bugs. Many have been patched in recent versions.

**Pattern (generic transcript):**
```rust
// BUG: public input not included in transcript
fn compute_challenge(transcript: &mut Transcript, commitment: &G1) -> Fr {
    transcript.append_point(b"commitment", commitment);
    // Missing: transcript.append_scalar(b"public_input", &public_input);
    // Attacker can change public_input without affecting the challenge
    transcript.challenge_scalar(b"challenge")
}
```

**Pattern (multi-round protocol):**
```rust
// BUG: round-1 commitment not included before round-2 challenge
fn prove(circuit: &Circuit, witness: &Witness) -> Proof {
    let commit_round1 = commit(witness);
    let challenge_1 = hash(/* should include commit_round1 but doesn't */);
    let commit_round2 = compute_round2(witness, challenge_1);
    let challenge_2 = hash(commit_round1, commit_round2); // too late for challenge_1
    // ...
}
```

**Real-world reference:** The "Frozen Heart" vulnerability class (Trail of Bits, 2022) affected Plonky2, Bulletproofs implementations, and others. In each case, insufficient transcript inputs allowed proof forgery.

**Grep for:** `Transcript`, `transcript`, `fiat_shamir`, `challenge`, `squeeze`, `absorb`, `append_message`, `domain_separator`, `hash_to_field`

---

## ZK-003: Field Arithmetic Edge Cases

**Impact:** High to Critical (soundness break, unexpected behavior, potential fund theft)
**Frequency:** Common in hand-written circuits and custom field implementations

ZK proofs operate over finite fields (e.g., BN254 scalar field, Goldilocks, BabyBear). Field arithmetic has properties that differ from normal integer arithmetic, and edge cases can lead to soundness bugs.

**What to check:**

- **Overflow / wrap-around**: Field elements wrap around at the field modulus `p`. If a circuit assumes that `a + b > a` (as in normal integers), this fails when `a + b >= p`. For example, in the BN254 scalar field, adding 1 to `p-1` gives 0.
  - This is critical for range checks, balance calculations, and comparisons.

- **Division by zero**: In a finite field, division by zero is undefined, but some implementations may silently return 0 or a garbage value instead of failing. A circuit that divides without checking the divisor can have unpredictable behavior.
  ```
  // BUG: if divisor == 0, field_div may not fail as expected
  let result = field_div(numerator, divisor);
  ```

- **Non-canonical representations**: A field element should be in the range `[0, p-1]`. If the implementation accepts values >= p, then the same logical value can have multiple representations, breaking uniqueness assumptions.
  ```rust
  // BUG: accepting raw bytes without checking < p
  fn deserialize_field_element(bytes: &[u8; 32]) -> Fp {
      Fp::from_raw_bytes(bytes) // may not reduce mod p
  }
  ```

- **Multiplicative inverse of zero**: `0` has no multiplicative inverse. Circuits that compute inverses must handle zero explicitly. If `is_zero(x)` is implemented as `x * x_inv == 1` (checking if inverse exists), it must be paired with a constraint that `x * x_inv == 0 || x * x_inv == 1`.

- **Quadratic residue assumptions**: Not every field element has a square root. If a circuit assumes `sqrt(x)` always exists, a prover can exploit cases where it does not.

- **Extension field bugs**: Some proof systems use extension fields (e.g., `Fp2`, `Fp12` for pairing-based systems). Arithmetic in extension fields is more complex, and bugs in multiplication or inversion of extension field elements can break soundness.

- **Negative number representation**: Fields do not have "negative" numbers, but signed values are often encoded as either `x` (for non-negative) or `p - x` (for negative). If the encoding/decoding is inconsistent, comparisons and range checks fail.

**Pattern (Circom):**
```circom
// BUG: comparison in field arithmetic does not work like integer comparison
// In a prime field, (a - b) can wrap around, making "a > b" checks unreliable
template UnsafeComparison() {
    signal input a;
    signal input b;
    signal output isGreater;

    // This does NOT correctly compute a > b in a prime field
    isGreater <== a - b;  // wraps around if a < b, producing a large field element
}
```

**Grep for:** `field_div`, `inv()`, `inverse()`, `from_raw`, `from_bytes_unchecked`, `mod_inverse`, `sqrt`, `is_zero`, `Fp2`, `Fp6`, `Fp12`, `non_canonical`, `reduce`, `montgomery`

---

## ZK-004: Proof Serialization / Deserialization Bugs

**Impact:** High to Critical (verifier crash, accepting invalid proofs, DoS)
**Frequency:** Common in on-chain verifiers and cross-system proof passing

Proofs are serialized for transmission and storage, then deserialized for verification. Bugs in this process can cause verifier crashes, acceptance of invalid proofs, or denial of service.

**What to check:**

- **Invalid curve point acceptance**: Proof elements are elliptic curve points. A deserialized point must be checked to be (a) on the curve, (b) in the correct subgroup, and (c) not the point at infinity (unless explicitly allowed). Missing subgroup checks are especially dangerous -- points in the wrong subgroup can lead to soundness breaks.
  ```solidity
  // BUG: no subgroup check on deserialized proof points
  function verifyProof(uint256[8] calldata proof) external {
      // Directly uses proof points without checking they're in G1/G2 subgroup
      // Attacker can submit points on the curve but in a different subgroup
  }
  ```

- **Malformed proof crashing verifier**: If the verifier does not validate proof length and format before processing, a malformed proof can cause out-of-bounds reads, division by zero, or other crashes. In on-chain verifiers (Solidity), this can cause the transaction to revert, wasting gas. In off-chain verifiers, this can crash the node.

- **Proof malleability**: Some proof systems allow multiple valid serializations of the same proof. If proof identity is used for deduplication or replay protection, malleability can bypass these checks.
  - Groth16 proofs can be negated (negate one G1 point and swap pairing arguments) to produce a different valid proof for the same statement.
  - BLS signatures have similar malleability.

- **Field element out of range**: Serialized field elements must be < the field modulus. If the verifier does not check this, it may accept elements that are not valid field members.

- **Endianness mismatch**: Different systems may use big-endian or little-endian serialization. A mismatch causes the verifier to interpret a completely different value.

- **Compressed vs uncompressed point confusion**: Elliptic curve points can be serialized in compressed (x + sign bit) or uncompressed (x, y) form. If the deserializer expects one format but receives the other, it will misinterpret the data.

**Pattern (Solidity on-chain verifier):**
```solidity
// BUG: no validation that proof points are on the curve or in the subgroup
function verifyProof(
    uint256[2] memory a,
    uint256[2][2] memory b,
    uint256[2] memory c,
    uint256[] memory input
) public view returns (bool) {
    // Missing: check that a, b, c are valid curve points
    // Missing: check that input elements are < field modulus
    // Missing: check that points are in the correct subgroup (for BN254, this is
    //          automatic for G1 but NOT for G2 in some implementations)
    return Pairing.pairingCheck(/* ... */);
}
```

**Pattern (Rust proof deserialization):**
```rust
// BUG: deserialize_uncompressed does not check subgroup membership
fn verify_proof(proof_bytes: &[u8]) -> bool {
    let a = G1Affine::deserialize_uncompressed_unchecked(&proof_bytes[0..64]).unwrap();
    let b = G2Affine::deserialize_uncompressed_unchecked(&proof_bytes[64..192]).unwrap();
    // _unchecked variants skip subgroup and curve checks for performance
    // Attacker can submit points not in the subgroup
    verify(a, b, public_inputs)
}
```

**Grep for:** `deserialize_uncompressed_unchecked`, `from_uncompressed_unchecked`, `subgroup_check`, `is_on_curve`, `is_in_correct_subgroup`, `abi.decode`, `ecAdd`, `ecMul`, `ecPairing`, `PRECOMPILE`, `0x06`, `0x07`, `0x08` (EVM precompile addresses for EC operations), `proof_malleability`, `serialize`, `deserialize`

---

## ZK-005: Data Availability Gaps

**Impact:** Critical (users cannot prove their balances, funds potentially locked forever)
**Frequency:** Common in rollup designs, especially during cost optimization

A ZK rollup posts a validity proof to L1 confirming the state transition is correct. But the proof alone is not enough -- users need the underlying data (transactions or state diffs) to reconstruct the L2 state and prove their balances. If this data is unavailable, users cannot generate withdrawal proofs even though the state is "valid."

**What to check:**

- **State diffs vs full transaction data**: Some rollups post only state diffs (which accounts changed and to what values) rather than full transactions. This is cheaper but means users cannot reconstruct intermediate states. If a state diff is missing or incomplete, users may be unable to prove their current balance.

- **Calldata vs blob (EIP-4844) availability**: Calldata is permanently available; blobs are pruned after ~18 days (4096 epochs). If the rollup relies on blob data and does not archive it separately, historical state reconstruction becomes impossible after pruning.
  ```
  // RISK: rollup posts data as blobs but has no archive solution
  // After 18 days, blob data is pruned from L1 consensus nodes
  // Users who haven't synced cannot reconstruct state
  ```

- **Off-chain DA (validium mode)**: Some systems (StarkEx, ZKsync with validium mode) store data off-chain with a Data Availability Committee (DAC). If the DAC colludes or goes offline, data is unavailable.
  - Check: How many DAC members are required? What is the trust assumption?
  - Check: Can the system fall back to on-chain DA if the DAC fails?

- **Compressed data correctness**: Rollups compress data before posting to L1. If the compression/decompression is buggy, the "available" data cannot actually be used to reconstruct state.

- **Data-proof binding**: The validity proof must commit to the data being posted. If the proof and the data are not cryptographically linked, a sequencer could post a valid proof with incorrect/incomplete data.
  - Check: Does the circuit/STARK include the data hash as a public input?
  - Check: Does the L1 verifier contract check that the posted data matches the commitment in the proof?

- **Escape hatch dependency on DA**: If the escape hatch (forced withdrawal mechanism) requires users to provide a Merkle proof of their balance, and the data needed to compute that proof is unavailable, the escape hatch is useless.

**Pattern (L1 verifier contract):**
```solidity
// BUG: proof verified but posted data not checked against proof commitment
function commitBlock(
    bytes calldata pubdata,
    uint256[8] calldata proof,
    bytes32 newStateRoot
) external {
    require(verifier.verify(proof, newStateRoot), "invalid proof");
    // Missing: require(keccak256(pubdata) == extractDataCommitment(proof));
    // Sequencer can post garbage pubdata while submitting a valid proof
    // Users cannot reconstruct state from the garbage data
    emit BlockCommitted(newStateRoot, pubdata);
}
```

**Grep for:** `pubdata`, `calldata`, `blob`, `data_availability`, `DAC`, `DataAvailability`, `commitBlock`, `blobhash`, `BLOBBASEFEE`, `point_evaluation_precompile`, `4844`, `state_diff`, `compressed`, `validium`

---

## ZK-006: Prover-Verifier State Mismatch

**Impact:** Critical (soundness break or liveness failure)
**Frequency:** Moderate -- often emerges during upgrades or multi-component deployments

The prover generates a proof based on a specific circuit and state. The verifier checks the proof against its own understanding of the circuit and expected state commitments. If these diverge, either the prover cannot produce accepted proofs (liveness failure) or the verifier accepts proofs for wrong states (soundness failure).

**What to check:**

- **Verification key mismatch**: The verifier uses a verification key that must correspond exactly to the circuit the prover uses. If the prover's circuit is updated but the verification key on L1 is not, or vice versa, proofs will fail or (worse) an old verification key might accept proofs from a simpler circuit.
  ```solidity
  // RISK: verification key is hardcoded and not updated with circuit changes
  contract Verifier {
      bytes32 constant VK_HASH = 0xabc...;  // must match prover's circuit exactly
      // If the prover circuit changes, this constant must be updated atomically
  }
  ```

- **State root computation divergence**: The prover and verifier must agree on how the state root is computed (hash function, tree structure, leaf encoding). A difference in any of these causes the verifier to reject valid proofs or accept proofs for a different state.

- **Public input encoding**: The prover and verifier must encode public inputs identically (same field, same serialization, same ordering). A mismatch means the verifier checks a different statement than what the prover proved.

- **Protocol version skew**: During rollup upgrades, the prover, sequencer, and verifier may run different software versions temporarily. If the proof protocol changed between versions, this window is dangerous.

- **Genesis state disagreement**: If the prover and verifier disagree on the initial state (genesis block), all subsequent state transitions will produce different state roots.

- **Circuit feature flags**: Some circuits have configurable features (e.g., which opcodes are supported). If the prover enables a feature the verifier does not expect, the constraint system differs and proofs are incompatible.

**Pattern (system upgrade):**
```python
# BUG: prover updated to v2 circuit, but L1 verifier still has v1 verification key
# Scenario 1 (liveness): v2 proofs fail verification with v1 key -> rollup halts
# Scenario 2 (soundness): if v1 key somehow accepts v2 proofs but checks fewer
#   constraints, a malicious prover can exploit the missing constraints

# Correct upgrade sequence:
# 1. Deploy new verifier contract with v2 key
# 2. Governance approves switch to new verifier
# 3. Switch prover to v2 circuit
# 4. All three happen atomically or with careful coordination
```

**Grep for:** `verification_key`, `vk_hash`, `VK_COMMITMENT`, `verifier_address`, `setVerifier`, `upgradeVerifier`, `protocol_version`, `genesis`, `PublicInput`, `encode_public_inputs`

---

## ZK-007: Recursive Proof Composition Bugs

**Impact:** Critical (soundness break in the recursive layer can invalidate entire proof chains)
**Frequency:** Increasing as recursive proofs become standard (ZKsync, Starknet, RISC Zero, Plonky2/3)

Recursive proof composition allows a proof to verify another proof inside it, enabling proof aggregation and incrementally verifiable computation. Bugs in recursion can undermine the soundness of the entire proof chain.

**What to check:**

- **Wrong verification key in inner verifier**: The recursive circuit contains a verifier sub-circuit that checks inner proofs. If this inner verifier uses the wrong verification key (or the verification key is not constrained as a public input), a proof generated for a different circuit can pass verification.
  ```rust
  // BUG: inner verification key is a private witness, not a public input
  // Prover can substitute any verification key and prove any inner statement
  fn recursive_verify(
      inner_proof: Proof,
      inner_vk: VerificationKey,  // should be constrained to a known value
      inner_public_inputs: Vec<Fr>,
  ) -> Result<()> {
      // If inner_vk is unconstrained, attacker chooses a trivial circuit's VK
      verify_in_circuit(inner_proof, inner_vk, inner_public_inputs)?;
      Ok(())
  }
  ```

- **Recursion depth exploit**: If there is no limit on recursion depth, an attacker might construct deeply nested proofs that consume excessive verifier resources (memory, stack) or trigger overflow.

- **Accumulation scheme bugs**: Some recursive systems (e.g., Nova, IVC) use an accumulation scheme instead of full verification at each step. The accumulation must be done correctly -- the running instance must be properly updated. If the accumulator is not checked at the final verification step, intermediate errors propagate silently.

- **Cycle of curves issues**: Recursive proofs over the same curve require expensive non-native field arithmetic. Systems that use a cycle of curves (e.g., Pasta curves: Pallas/Vesta) must handle the field mismatch correctly. Bugs can occur in the non-native field arithmetic circuit.

- **Proof aggregation ordering**: When aggregating multiple proofs, the order in which they are combined may matter. If proofs are reorderable and the aggregator does not commit to the order, this can be exploited.

- **Base case validation**: Recursive proofs need a base case (the first proof in the chain that does not verify a previous proof). If the base case is not handled correctly, the recursion has no valid foundation.

**Grep for:** `recursive`, `recursion`, `inner_proof`, `inner_verifier`, `accumulator`, `IVC`, `folding`, `aggregate`, `batch_verify`, `cycle_of_curves`, `Pallas`, `Vesta`, `base_case`, `RecursiveCircuit`

---

## ZK-008: Trusted Setup Ceremony Vulnerabilities

**Impact:** Critical (compromise of the setup allows forging any proof -- total soundness break)
**Frequency:** Applies to KZG/Groth16-based systems; does not apply to STARKs or transparent setups

Some proof systems (notably Groth16 and KZG-based systems like PLONK with KZG commitments) require a structured reference string (SRS) generated through a trusted setup ceremony. If the "toxic waste" (secret randomness used during setup) is known to any party, they can forge proofs for false statements.

**What to check:**

- **Toxic waste retention**: The ceremony generates secret values (tau, alpha, beta in Groth16) that must be destroyed. If any single participant retains their contribution's secret, and they are the only participant, they can forge proofs. The security assumption is that at least one participant destroys their secret.
  - Check: How many participants were in the ceremony?
  - Check: Is the list of participants public and verifiable?
  - Check: Were transcripts published for verification?

- **Insufficient participants**: A ceremony with very few participants has a higher probability that all are compromised (colluding or individually compromised). Production systems should have hundreds or thousands of participants.

- **Ceremony replay / manipulation**: If an attacker can replay or modify a participant's contribution, they can control the output.
  - Check: Is each contribution chained (each participant builds on the previous one)?
  - Check: Are contributions verified before being included?
  - Check: Is there a hash chain or similar mechanism to prevent tampering?

- **SRS verification**: After the ceremony, the SRS must be verified for internal consistency (e.g., the powers of tau form a valid geometric sequence on the curve). If the SRS is not verified, a malicious coordinator could substitute a compromised SRS.
  ```rust
  // Verification checks for powers of tau:
  // e(g1^(tau^i), g2) == e(g1^(tau^(i-1)), g2^tau) for all i
  // If this check is skipped, the SRS may be malformed
  ```

- **Universal vs circuit-specific setup**: Universal setups (like the Ethereum KZG ceremony for EIP-4844, or Aztec's Ignition) can be reused across circuits. Circuit-specific setups (Groth16) require a new ceremony for each circuit. If a circuit-specific setup is reused for a different circuit, the security guarantee does not hold.

- **SRS size limits**: The SRS has a maximum degree. If the circuit requires more constraints than the SRS supports, the setup must be redone. Using an undersized SRS can lead to undefined behavior.

- **STARK/FRI systems (no trusted setup)**: For STARK-based systems (StarkEx, Starknet, RISC Zero), there is no trusted setup. However, verify that the system is not accidentally using a component that requires a trusted setup (e.g., a KZG-based polynomial commitment mixed into a STARK pipeline).

**Grep for:** `trusted_setup`, `ceremony`, `powers_of_tau`, `ptau`, `SRS`, `CRS`, `toxic_waste`, `tau`, `setup_verification`, `Ignition`, `perpetual_powers_of_tau`, `KZG`, `kate_commitment`

---

## ZK-009: Gas / Fee Miscalculation in ZK L2

**Impact:** High (economic exploits, DoS, sequencer insolvency)
**Frequency:** Common -- L2 fee models are complex and often miscalibrated

ZK L2s have a multi-component cost structure: L2 execution gas, L1 calldata/blob cost for data availability, and proof generation cost. Miscalculating any component creates economic exploits.

**What to check:**

- **Proof verification cost on L1**: Verifying a ZK proof on L1 costs significant gas (e.g., ~300K gas for Groth16 via BN254 precompiles, ~2-5M for STARK/FRI proofs via calldata). If the L2 fee model does not account for this cost and amortize it across transactions in the batch, the sequencer/prover loses money on every batch.
  ```
  // L1 verification cost per batch: ~300,000 gas * gas_price
  // If batch has N transactions, each transaction should pay at least:
  //   (300,000 * gas_price) / N in L1 fees
  // BUG: if N is very small (e.g., 1 transaction), the fee may not cover verification cost
  ```

- **L1 calldata cost estimation**: The L2 must estimate how much L1 calldata each transaction will require. If this estimate is too low, the sequencer pays more for L1 posting than it collects in fees.
  - Check: Is calldata cost estimated before or after compression?
  - Check: Does the estimate account for EIP-4844 blob pricing?
  - Check: Can a user craft a transaction that compresses poorly, making it more expensive than estimated?

- **Proof generation cost**: Proof generation is computationally expensive (minutes to hours of CPU/GPU time). If transaction fees do not cover the cost of proving, the prover operates at a loss.
  - Check: Is there a minimum fee that covers the marginal proving cost per transaction?

- **L2 gas metering divergence from EVM**: ZK L2s often have different gas costs than mainnet because some operations are more expensive to prove (e.g., KECCAK256 is expensive in ZK circuits). If the gas schedule does not reflect proving cost, users can DoS the prover with cheap-to-execute-but-expensive-to-prove transactions.
  ```solidity
  // Example: KECCAK256 costs 30 + 6*words in EVM gas
  // But proving KECCAK256 in a ZK circuit may require millions of constraints
  // If the ZK L2 uses standard EVM gas pricing, users can submit
  // transactions that are cheap in gas but extremely expensive to prove
  ```

- **Dynamic fee adjustment**: If the L2 adjusts fees based on demand (like EIP-1559), check that the adjustment mechanism cannot be manipulated (e.g., by spamming cheap transactions to lower the base fee, then submitting expensive ones).

- **Batch economics**: The sequencer batches transactions and posts them together. Check the economics of small batches, empty batches, and maximally large batches. Edge cases in batch size can create unprofitable conditions.

**Pattern (ZKsync Era fee model):**
```solidity
// ZKsync Era uses "ergs" (zkEVM gas units) that differ from EVM gas
// The mapping between EVM gas and ergs must be correct for all opcodes
// If SLOAD costs 100 ergs but its ZK proving cost is equivalent to 10,000 ergs,
// users can spam SLOADs cheaply while making proving expensive
```

**Grep for:** `gasPrice`, `l1GasPrice`, `baseFee`, `blobBaseFee`, `ergs`, `proving_cost`, `batch_overhead`, `L1_GAS_PER_PUBDATA`, `fair_l2_gas_price`, `feeModel`, `getMinimalL2GasPrice`, `overhead`, `amortize`, `REQUIRED_L1_TO_L2_GAS_PER_PUBDATA`

---

## ZK-010: Escape Hatch / Forced Exit Bugs

**Impact:** Critical (users permanently unable to withdraw funds if prover/sequencer fails)
**Frequency:** Under-tested in most ZK rollups -- rarely exercised in practice

The escape hatch is the mechanism that allows users to withdraw funds directly from the L1 contract when the ZK rollup prover or sequencer becomes unavailable. This is a critical safety mechanism -- without it, a rollup failure means permanent loss of all user funds.

**What to check:**

- **Escape hatch existence**: Does the rollup have an escape hatch at all? Some early designs did not include one. The L1 contract must have a mechanism for users to prove their L2 balance and withdraw directly.

- **Merkle proof requirements**: To use the escape hatch, users typically need to provide a Merkle proof of their account balance in the last verified L2 state. Check:
  - Can users actually construct this proof? Do they have access to the full state tree?
  - What happens if the last verified state is very old? (user may have received funds after that state)
  - Is the Merkle proof verification implemented correctly on L1?

- **Timelock / delay**: There is usually a timelock before the escape hatch activates (to prevent abuse while the system is functioning). Check:
  - How long is the delay? (too long = users wait months; too short = can be triggered unnecessarily)
  - Can the delay be extended by the operator? (operator could indefinitely delay escape)
  - Is there a clear trigger condition? (e.g., "no valid proof posted for X days")

- **Censorship during escape**: During the escape period, the sequencer might still be partially functional and could try to front-run or censor escape transactions on L1.
  - Check: Can the sequencer submit a batch that changes user balances after the escape hatch opens but before users exit?
  - Check: Is there a freeze on state updates during the escape period?

- **Priority queue / forced transaction mechanism**: Before full escape, rollups often have a "forced transaction" mechanism where users submit L2 transactions via L1 that the sequencer must include. Check:
  - Is there a deadline for the sequencer to include forced transactions?
  - What happens if the deadline passes? Does the escape hatch activate?
  - Can the forced transaction be front-run by the sequencer?

- **ERC-20 and NFT handling**: The escape hatch must handle all asset types, not just ETH. Check:
  - Can users exit with ERC-20 tokens?
  - Can users exit with NFTs?
  - What about LP tokens or other DeFi positions that exist only on L2?

- **Partial withdrawal**: Can users withdraw a partial amount, or must they withdraw everything?

- **Reentrancy in escape hatch**: The L1 escape hatch contract interacts with various token contracts during withdrawal. Check for reentrancy vulnerabilities.

**Pattern (L1 rollup contract):**
```solidity
// BUG: escape hatch delay can be extended by operator indefinitely
contract ZKRollup {
    uint256 public escapeDelay = 7 days;

    function setEscapeDelay(uint256 newDelay) external onlyOperator {
        // No upper bound! Operator can set delay to type(uint256).max
        escapeDelay = newDelay;
    }

    function activateEscapeHatch() external {
        require(
            block.timestamp > lastProofTimestamp + escapeDelay,
            "too early"
        );
        // If operator sets escapeDelay to max, this can never be called
        escapeMode = true;
    }
}
```

**Pattern (incomplete escape hatch):**
```solidity
// BUG: escape hatch only handles ETH, not ERC-20 tokens
function emergencyWithdraw(
    bytes32[] calldata merkleProof,
    uint256 amount
) external {
    require(escapeMode, "not in escape mode");
    require(verifyMerkleProof(merkleProof, msg.sender, amount), "invalid proof");
    // Only sends ETH -- ERC-20 balances are permanently locked
    payable(msg.sender).transfer(amount);
}
```

**Pattern (state update during escape):**
```solidity
// BUG: sequencer can submit state updates even after escape hatch opens
function commitBlock(bytes calldata data, uint256[8] calldata proof) external {
    // Missing: require(!escapeMode, "escape mode active");
    // Sequencer can change state root, invalidating users' Merkle proofs
    stateRoot = newRoot;
}
```

**Grep for:** `escape`, `exodus`, `emergencyWithdraw`, `forcedExit`, `forcedWithdraw`, `emergencyMode`, `freezeMode`, `priorityQueue`, `forcedTransaction`, `escapeHatch`, `PRIORITY_EXPIRATION`, `activateExodus`, `performExodus`, `cancelOutstandingDeposits`

---

## Scan Priority

For ZK infrastructure audits, prioritize in this order:

1. **ZK-001: Circuit constraint under-specification** -- highest frequency and severity; a single missing constraint can drain the entire rollup. Start by examining all witness variable allocations and verifying each is constrained. In halo2-based circuits, cross-reference `assign_advice` calls with `create_gate` constraints. In Circom, look for `<--` without corresponding `===`.

2. **ZK-002: Fiat-Shamir transcript manipulation** -- systemic soundness break affecting all proofs. Verify that the transcript includes all public inputs, all prover messages, domain separators, and the verification key. Cross-reference with known "Frozen Heart" vulnerabilities in the proof system version.

3. **ZK-010: Escape hatch / forced exit bugs** -- critical for user fund safety during system failure. This is often the least-tested code path because it is rarely exercised in production. Verify the complete flow: trigger condition, timelock, Merkle proof verification, multi-asset support, and immunity to operator manipulation.

4. **ZK-005: Data availability gaps** -- without DA, even correct proofs cannot help users recover funds. Verify the binding between proof commitments and posted data. Check blob expiry handling and validium/DAC trust assumptions.

5. **ZK-004: Proof serialization/deserialization bugs** -- especially critical for on-chain verifiers. Check curve point validation, subgroup checks, and field element range validation. Focus on Solidity verifier contracts and any `_unchecked` deserialization in Rust.

6. **ZK-006: Prover-verifier state mismatch** -- especially dangerous during upgrades. Check verification key management, upgrade coordination, and public input encoding consistency.

7. **ZK-003: Field arithmetic edge cases** -- subtle but exploitable. Focus on range checks, division by zero handling, and non-canonical representations. Especially relevant in hand-written circuits.

8. **ZK-007: Recursive proof composition bugs** -- increasingly important as recursive proofs become standard. Verify inner verification key constraints and accumulation correctness.

9. **ZK-009: Gas/fee miscalculation** -- economically exploitable. Focus on the mismatch between EVM gas costs and ZK proving costs, especially for hash-heavy operations (KECCAK256, SHA256).

10. **ZK-008: Trusted setup ceremony** -- binary risk (either compromised or not). Verify ceremony parameters and SRS consistency. Primarily relevant for Groth16 and KZG-based systems. Not applicable to STARK-based systems (StarkEx, Starknet, RISC Zero).
