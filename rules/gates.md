# HarryAgent Gate System

Every finding must pass through 6 sequential gates before inclusion in the final report. A failure at any gate terminates the finding -- it moves to REJECTED with the specific gate and reason recorded.

## Gate 1: Hypothesis Formation

**Requirement:** The finding must be expressed as a falsifiable hypothesis.

**Format:**
```
IF [specific action by attacker]
THEN [specific violation that occurs]
BECAUSE [specific mechanism in code at file:line]
```

**Rejection criteria:**
- Vague language: "could potentially", "might be possible", "seems like"
- No code reference: hypothesis must cite specific file and function
- Non-falsifiable: if you can't describe what would disprove it, it's not a hypothesis
- Informational only: "this function lacks comments" is not a security finding

**Example PASS:**
```
IF a malicious validator sends a prevote for height H with a timestamp T < last_block_time
THEN the chain halts because CometBFT's MedianTime calculation produces a non-monotonic block time
BECAUSE consensus/state.go:createProposalBlock() does not validate individual vote timestamps before computing the median
```

**Example FAIL:**
```
The consensus mechanism could potentially be vulnerable to timing attacks.
```

## Gate 2: Reachability Proof

**Requirement:** The vulnerable code path must be reachable from an external entry point by an attacker.

**Verify:**
1. Trace backwards from the vulnerable code to an external entry point (RPC endpoint, P2P message handler, transaction type, CLI command)
2. Identify every conditional branch on the path -- can the attacker satisfy all conditions?
3. Check for guards: does middleware, authentication, or rate limiting block the path?

**Rejection criteria:**
- Code is dead/unreachable (no caller, behind feature flag, deprecated)
- Path requires admin/root privileges that an attacker wouldn't have
- Path is blocked by validation that correctly rejects malicious input
- Code only runs in test/debug mode

**Required output:**
```
ENTRY POINT: [endpoint/handler]
CALL CHAIN: entry() -> middleware() -> handler() -> vulnerable_func()
CONDITIONS: [list every branch condition and how attacker satisfies it]
GUARDS: [list every guard on the path and why it doesn't block]
```

## Gate 3: Controllability Proof

**Requirement:** The attacker must be able to control the inputs that trigger the vulnerability.

**Verify:**
1. Which parameters does the attacker control? (direct input, indirect via prior state manipulation)
2. What values must those parameters take to trigger the bug?
3. Are those values within the valid range accepted by upstream validation?
4. Does the attacker need to be in a specific role (validator, peer, user)? Is that role obtainable?

**Rejection criteria:**
- Attacker cannot influence the relevant state
- Required input values are rejected by validation before reaching vulnerable code
- Requires collusion of multiple trusted parties (unless that's in-scope per bug bounty rules)
- Timing window is too narrow to be practically exploitable (<1 block)

**Required output:**
```
CONTROLLED INPUTS: [list with source]
REQUIRED VALUES: [specific values or ranges]
ATTACKER ROLE: [peer/validator/user/unauthenticated]
ROLE OBTAINABILITY: [how attacker gets this role]
```

## Gate 4: Impact Quantification

**Requirement:** The impact must be concrete, not theoretical.

**Assess:**
1. What specifically happens when the vulnerability is triggered?
2. How much money is at risk? (if financial impact)
3. How many nodes/validators/users are affected?
4. Is the impact permanent or temporary? Recoverable or not?
5. Does it require a hard fork to fix?

**Severity matrix:**

| Impact | Severity |
|--------|----------|
| Direct theft of staked/locked funds | Critical |
| Infinite minting / supply manipulation | Critical |
| Permanent chain split (no automatic resolution) | Critical |
| Consensus bypass allowing double-spend | Critical |
| Network halt requiring coordinated restart | High |
| Permanent fund lock (no recovery path) | High |
| State corruption requiring hard fork | High |
| Validator set manipulation (force join/evict) | High |
| Temporary DoS >10 minutes per trigger | Medium |
| Mempool manipulation with measurable economic impact | Medium |
| Node crash (single node, auto-restartable) | Medium |
| Information disclosure of private state | Medium |
| Minor temporary DoS (<10 min) | Low |
| Non-critical log pollution / resource waste | Low |

**Rejection criteria:**
- Impact is purely theoretical with no concrete scenario
- Self-harm only (attacker hurts themselves, not the network)
- Requires >$1M capital to execute for <$1K gain
- Impact is mitigated by existing monitoring/alerting in production

**Required output:**
```
IMPACT: [specific outcome]
SCOPE: [number of affected nodes/validators/users]
FINANCIAL RISK: [dollar amount or "N/A"]
PERMANENCE: [permanent/temporary, recoverable/irrecoverable]
SEVERITY: [Critical/High/Medium/Low]
```

## Gate 5: Proof of Concept

**Requirement:** Every Medium+ finding must have a PoC or detailed step-by-step code trace.

**Acceptable PoC types (in order of strength):**

1. **Executable test** (strongest): A test file that compiles, runs, and demonstrates the vulnerability
   - Go: `*_test.go` file using the project's test framework
   - Rust: `#[test]` function using the project's test harness
   - Must include assertions that verify the vulnerable behavior

2. **Detailed code trace** (acceptable): Step-by-step walkthrough with exact function calls, parameters, and state changes
   - Must follow the actual code path, not a theoretical one
   - Must include concrete values at each step
   - Must show the exact point where the invariant breaks

3. **Network-level scenario** (acceptable for P2P/consensus): Sequence of messages/blocks with exact payloads
   - Must specify message types, fields, and values
   - Must describe the expected vs actual behavior at each step

**Rejection criteria:**
- "A PoC could be constructed by..." -- no, construct it or trace it
- PoC references functions that don't exist in the codebase
- PoC skips steps or uses handwaving ("...and then the state becomes corrupted...")
- PoC assumes incorrect function behavior (verify what the function actually does)

**Required output:**
```
POC TYPE: [executable_test / code_trace / network_scenario]
STEPS:
  1. [exact action with exact parameters]
  2. [exact action with exact parameters]
  ...
EXPECTED BEHAVIOR: [what should happen]
ACTUAL BEHAVIOR: [what does happen]
INVARIANT BROKEN: [which security property is violated]
```

## Gate 6: Clean Report

**Requirement:** Only verified findings appear in the final report.

**Status classification:**
- **CONFIRMED**: Executable test passed demonstrating the vulnerability
- **VERIFIED**: Detailed code trace completed, all steps validated against actual code
- **LEAD**: Promising but incomplete -- missing PoC or unverified step in trace (goes to appendix, not main report)
- **REJECTED**: Failed at Gate 1-5 (goes to rejected appendix with reason)

**Final checks before report inclusion:**
1. Re-read every code reference in the finding -- does the file exist? Does the function exist? Is the line number correct?
2. Re-check the fix recommendation -- does it actually address the root cause?
3. Check for duplicates -- is this the same root cause as another finding?
4. Check against project's known issues -- is this already reported or documented as accepted risk?

## Gate Bypass: ZERO Tolerance

No finding bypasses any gate. No severity level is exempt. A Critical finding with a wrong code reference is worse than no finding at all -- it destroys credibility with the bug bounty program.

The only exception: if a finding is so obviously critical (e.g., hardcoded private key, obvious infinite loop in block validation) that Gates 2-4 are trivially satisfied, you may document them briefly rather than formally. Gate 5 (PoC) is NEVER skipped.
