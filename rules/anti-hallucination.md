# Anti-Hallucination Protocol

The #1 failure mode of AI security auditing is **false positives** -- fabricated vulnerabilities that waste the operator's time and destroy credibility with bug bounty programs. Every mechanism in HarryAgent is designed to minimize this.

## Core Principle

**If you cannot prove it from the code, it does not exist.**

Not "it might exist." Not "it could exist in certain conditions." It either exists in the code you've read, or it doesn't. Uncertainty is fine -- mark it as a LEAD and move on. Fabrication is unacceptable.

## Mandatory Verification Behaviors

### 1. Verify Every Code Reference

Before including ANY code reference in a finding:
- `grep` for the function name -- does it exist?
- `read` the file at the cited line -- does it do what you claim?
- Check the function signature -- do the parameters match your description?

**NEVER cite a function, variable, or file you haven't read in this session.**

### 2. Verify Assumptions About Language Behavior

Common hallucination patterns:
- Claiming Go integer overflow wraps (it does for unsigned, panics for signed in some contexts -- CHECK)
- Claiming Rust unwrap() panics silently (it doesn't -- it panics with a stack trace and crashes the node)
- Assuming a function returns an error when it actually panics (or vice versa)
- Assuming a mutex is not held when it is (read the caller chain)
- Assuming a channel is unbuffered when it's buffered (read the make() call)

**Rule: If your finding depends on language-specific behavior, verify it. Don't assume.**

### 3. Check for Guards You Might Have Missed

Before finalizing any finding, actively search for:
- Input validation in middleware/handlers upstream of the vulnerable code
- Type system constraints that prevent invalid values (especially in Rust)
- Rate limiting or size limits that prevent resource exhaustion
- Error handling that catches the condition before it causes harm
- Recovery mechanisms (defer/recover in Go, catch_unwind in Rust)

**Rule: Spend as much time trying to disprove your finding as you spent finding it.**

### 4. Devil's Advocate Requirement

For every finding above Low severity, answer these questions BEFORE including it:
1. "What guard or check would prevent this?" -- then search for that guard
2. "Has the developer likely considered this?" -- check for comments, related tests, past commits
3. "What would the developer say to dismiss this?" -- preemptively address their likely response
4. "If I'm wrong, what did I misread?" -- re-read the critical code path one more time

### 5. Cross-Reference Existing Tests

Before reporting a vulnerability:
- Search for test files that exercise the vulnerable code path
- If a test exists that specifically covers this scenario, the behavior might be intentional
- If no test exists for a critical path, that's a signal (but not proof) of a gap

## Confidence Scoring

Every hypothesis gets a confidence score from 0.0 to 1.0:

```
confidence = (evidence * 0.30) + (reachability * 0.25) + (controllability * 0.25) + (impact_clarity * 0.20)
```

| Component | 0.0 | 0.5 | 1.0 |
|-----------|-----|-----|-----|
| Evidence | Theoretical only | Code suggests it | Code proves it |
| Reachability | Haven't traced path | Partial trace with gaps | Full trace from entry to vuln |
| Controllability | Unknown if attacker controls input | Attacker controls some inputs | Attacker fully controls trigger |
| Impact Clarity | Vague impact | Estimated impact | Quantified impact with numbers |

**Thresholds:**
- >= 0.7: Proceed to PoC construction
- 0.4 - 0.7: Flag for depth analysis, may proceed if promising
- < 0.4: REJECT -- insufficient evidence to justify further investigation

## Evidence Hierarchy

Not all evidence is equal:

1. **[CODE-VERIFIED]**: You read the actual source code and the behavior is explicit
2. **[CODE-INFERRED]**: Behavior is implied by code structure but not explicit (e.g., missing check implies no validation)
3. **[DOCS-STATED]**: Documentation says X but you haven't verified the code matches
4. **[PATTERN-MATCHED]**: Matches a known vulnerability pattern but specific instance not verified
5. **[THEORETICAL]**: Logically possible but no code evidence yet

**Rules:**
- Only [CODE-VERIFIED] and [CODE-INFERRED] evidence can support a CONFIRMED finding
- [PATTERN-MATCHED] evidence alone = LEAD status maximum
- [THEORETICAL] evidence alone = REJECTED
- [DOCS-STATED] must be verified against code before use in findings -- docs lie

## Known Hallucination Traps

### Trap 1: "Missing check" that exists elsewhere
The check exists in a middleware, wrapper, or caller -- you just didn't trace far enough up the call stack.
**Mitigation:** Trace the full call chain from entry point, not just the immediate caller.

### Trap 2: "Overflow" in safe math
The language or library already handles overflow (Rust's checked_*, Go's math/big, SafeMath in Solidity).
**Mitigation:** Check the actual types and operations used, not just the arithmetic.

### Trap 3: "Unbounded" that is bounded by protocol rules
A loop or allocation looks unbounded but is constrained by consensus rules (max block size, max transactions, max validators).
**Mitigation:** Check protocol parameters and constants before reporting unbounded resource usage.

### Trap 4: "Race condition" with proper locking
A concurrent access pattern looks racy but is protected by a mutex, channel, or atomic operation you didn't see.
**Mitigation:** Search for lock/unlock, mutex, RwLock, sync.Map, atomic.* in the surrounding code.

### Trap 5: "Panic" that is caught
A Rust unwrap() or Go panic that is caught by a recover() or catch_unwind() upstream.
**Mitigation:** Check for defer/recover in Go callers, catch_unwind in Rust callers.

### Trap 6: "Unvalidated input" that is validated by the type system
Rust's type system often prevents invalid values from being constructed. A function taking `ValidatorId` not `String` means the ID was already validated at construction.
**Mitigation:** Check newtype patterns and constructor validation.

## When In Doubt

- Mark as LEAD, not CONFIRMED
- Include your uncertainty explicitly: "Unable to verify whether X guard exists in the call chain"
- Let the operator (the human auditor) make the judgment call
- A false negative (missed real bug) is better than a false positive (fabricated bug) -- false positives waste time AND erode trust with bug bounty programs
