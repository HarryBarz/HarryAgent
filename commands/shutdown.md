# /shutdown Command — Hunt Network Shutdown Bugs

## Usage
```
/shutdown [target_path] [--stack <cosmos|geth|substrate|rust-l1|go-l1|zk|move>]
```

## Description
Targeted hunt for bugs that can **halt the entire network** — the highest-severity class of blockchain infrastructure vulnerability. Uses all 148 battle-tested patterns from the real-exploit datasets to systematically search for known bug classes.

## What It Finds
Network shutdown = **all validators crash or stall simultaneously**, preventing new blocks/transactions.

Kill classes (ordered by likelihood):
1. **Panic/unwrap on untrusted input** — single malformed message crashes every node that processes it
2. **Infinite loop / event loop block** — node alive but completely unresponsive
3. **Unbounded memory allocation** — OOM kill on every node
4. **Consensus-path arithmetic crash** — overflow/div-by-zero in BeginBlock/EndBlock kills all validators
5. **Non-determinism in consensus** — chain split, then halt
6. **Decompression bomb** — small payload expands to GB, OOM before validation
7. **Unrecoverable block failure** — bad block can't be skipped, chain stuck forever

---

## Execution Flow

### Step 0: Detect Stack and Scope
1. If no target_path, use current working directory
2. Auto-detect tech stack from build files (go.mod, Cargo.toml, Move.toml, package.json)
3. Load the matching pattern file from `patterns/dlt-infra/`
4. Load ALL three real-exploit datasets:
   - `patterns/dlt-infra/real-exploits/node-crash.md`
   - `patterns/dlt-infra/real-exploits/p2p.md`
   - `patterns/dlt-infra/real-exploits/rpc-crash.md`

### Step 1: Language-Specific Panic Surface Scan
Launch 1 agent focused purely on crash primitives in the target language.

**For Rust codebases:**
```
Search the codebase for network-shutdown primitives:

1. grep for .unwrap() and .expect( in ALL files under: 
   - P2P message handlers
   - RPC handlers  
   - consensus/block processing (BeginBlock, EndBlock, on_initialize, on_finalize, FinalizeBlock)
   - transaction validation/execution
   - deserialization functions

2. grep for panic! and unreachable! in non-test code

3. grep for: vec![0; and Vec::with_capacity( where size comes from network input

4. grep for: .iter().sum() and checked_add/checked_mul ABSENCE on arithmetic in consensus paths

5. grep for: zstd::decode_all, snap::decompress, flate2 on untrusted input without size limit

6. grep for: as usize, as u64, as u32 type casts without bounds checking

For each match: note the file:line, trace back to see if the input comes from 
network/P2P/RPC (untrusted) or internal (trusted). Only flag untrusted paths.
```

**For Go codebases:**
```
Search the codebase for network-shutdown primitives:

1. grep for: panic( in non-test code — any panic in a handler reachable from P2P or RPC

2. grep for: recover() — check if P2P/RPC handlers have panic recovery

3. grep for: make([]byte, and make([]T, where size comes from network input without cap

4. grep for: [index] direct array/slice indexing on network-derived data without bounds check

5. grep for: go func() — goroutine spawns in message handlers without bounded pools

6. grep for: .Quo(, .Div(, / where divisor could be zero in consensus paths

7. grep for: .Mul(, .Add( without overflow checking in BeginBlocker/EndBlocker

8. grep for: time.Now(), math/rand, map iteration in FinalizeBlock/DeliverTx (non-determinism)

For each match: trace to entry point. Flag if reachable from P2P message or RPC request.
```

**For JavaScript/TypeScript codebases:**
```
Search for network-shutdown primitives:

1. grep for: parseInt(, Number( followed by use in for loops — JS precision loss infinite loop

2. grep for: __proto__, prototype in input validation (ABSENCE = prototype pollution risk)

3. grep for: .length in for loops on network input — object-with-length trick

4. grep for: Uint8Array.from(, Buffer.from( with network-controlled size

5. grep for: JSON.parse without try-catch on network input

6. grep for: req.body, req.query, req.params followed by property access without null check

7. grep for: axios(, fetch(, http.get( outbound calls without maxContentLength/timeout/redirect limits
```

### Step 2: Pattern Matching Against Real Exploits
Launch 3 agents in parallel, one per dataset:

**Agent 1 — Node Crash Patterns (NC-001 through NC-030):**
```
Read patterns/dlt-infra/real-exploits/node-crash.md.
For each of the 30 patterns, run its Detection Strategy against [target_path].
Tech stack: [detected_stack]

Priority order:
- NC-003 (unwrap/panic on untrusted input) — #1 most common, check FIRST
- NC-004 (unbounded allocation from size field) — check P2P listeners, RPC handlers
- NC-010 (arithmetic overflow in consensus) — check BeginBlock/EndBlock
- NC-011 (division by zero in consensus) — check all division in block processing
- NC-017 (non-determinism in FinalizeBlock) — check for RPC/network calls, map iteration
- NC-023 (DA namespace poisoning) — if chain uses external DA
- NC-024 (decompression bomb) — check all decompression on untrusted input
- NC-026 (unrecoverable block failure) — check error handling in block execution loop

Output format for each match:
PATTERN: NC-XXX
LOCATION: file:line
EVIDENCE: [code snippet showing the vulnerable pattern]
UNTRUSTED INPUT PATH: [how attacker data reaches this code]
CONFIDENCE: [0.0-1.0]
```

**Agent 2 — P2P Shutdown Patterns (from p2p.md, shutdown-relevant only):**
```
Read patterns/dlt-infra/real-exploits/p2p.md.
Focus ONLY on patterns that cause full network shutdown (not just single-node issues):

- P2P-004 (stream multiplexer flooding) — check libp2p resource manager config
- P2P-009 (CometBFT block parts mismatch) — if Cosmos chain
- P2P-031 (block replay via small dedup cache) — if L2/rollup
- P2P-033 (TCP string overflow panic) — if Rust+JS bridge
- P2P-035 (Firedancer shred memory corruption) — if Solana
- P2P-038 (infinite loop via type confusion) — if JavaScript
- P2P-049 (gossip defrag panic) — if Solana
- P2P-050 (vote censorship) — if custom vote storage
- P2P-051 (shred dedup crash → forwarding loop) — if block chunk propagation
- P2P-052 (BFT time manipulation) — if CometBFT
- P2P-062 (NEAR ping of death) — if multi-algorithm crypto
- P2P-063 (Rab13s) — if Bitcoin-fork UTXO chain
- P2P-068 (HamsterWheel infinite verifier loop) — if Move VM

Run detection strategies for applicable patterns against [target_path].
```

**Agent 3 — RPC Shutdown Patterns (from rpc-crash.md, shutdown-relevant only):**
```
Read patterns/dlt-infra/real-exploits/rpc-crash.md.
Focus on patterns where RPC crash kills the entire node process (not just rpcdaemon):

- RPC-001 (eth_call EIP-2929 overflow) — if EVM chain with block overrides
- RPC-007 (DoERS zero-cost eth_call) — if public eth_call endpoint
- RPC-019 (Sui BTreeMap panic) — if Move VM
- RPC-034 (ModExp OOM → consensus split) — if EVM chain with Nethermind
- RPC-036 (Reth eth_call OOM) — if Reth-based
- RPC-037 (Sui tx simulation panic) — if transaction simulation RPC
- RPC-041 (Monad assert overflow) — if state override in eth_call
- RPC-044 (HTTP response DoS cascade) — if outbound HTTP without size limits
- RPC-048 (WASM gas mispricing) — if WASM VM

Run detection strategies for applicable patterns against [target_path].
```

### Step 3: Consensus Path Deep Dive
Launch 1 agent for the most critical code paths:

```
Read agents/dlt-infra/consensus-hunter.md and agents/dlt-infra/state-machine-hunter.md.

Focus EXCLUSIVELY on code that runs during block production/validation — 
this is the only code where a bug crashes ALL validators simultaneously.

Trace these paths in [target_path]:
1. Block proposal → validation → execution → commit
2. BeginBlock / EndBlock / on_initialize / on_finalize
3. Vote/attestation processing
4. Epoch transitions
5. Upgrade/migration handlers

For each path, check:
- Can any arithmetic overflow/underflow?
- Can any division have a zero divisor from on-chain state?
- Are there any unwrap/expect/panic/assert on values derived from transactions?
- Are there any non-deterministic operations (RPC calls, time.Now, map iteration, goroutines)?
- Are there any unbounded loops over on-chain data?
- Can any error cause the block to fail in a way that can't be skipped?

This is the HIGHEST PRIORITY scan — a single bug here = instant network halt.
```

### Step 4: Compile Results
Merge all findings. Deduplicate by root cause. Sort by severity:

```
CRITICAL (Network Shutdown):
  - Bugs where a single message/request crashes all validators
  - Bugs where block processing enters an unrecoverable state
  - Bugs where consensus diverges across implementations

HIGH (Targeted Node Kill):
  - Bugs where specific nodes can be crashed
  - Bugs where node recovery requires manual intervention

Output: SHUTDOWN_REPORT.md with:
1. Executive summary (number of shutdown-class bugs found)
2. Each finding: pattern ID matched, location, PoC concept, recommended fix
3. Appendix: rejected hypotheses (patterns checked but no match found)
```

---

## Quick Reference: What to grep for (by language)

### Rust — Shutdown Primitives
```bash
# Panics on untrusted input
rg '\.unwrap\(\)' --type rust -g '!*test*' -g '!*mock*'
rg '\.expect\(' --type rust -g '!*test*' -g '!*mock*'
rg 'panic!' --type rust -g '!*test*' -g '!*mock*'

# Unbounded allocation
rg 'vec!\[0;' --type rust
rg 'Vec::with_capacity\(' --type rust

# Unchecked arithmetic in consensus
rg '\.iter\(\)\.sum\(\)' --type rust
rg 'as usize' --type rust

# Decompression without limit
rg 'decode_all|decompress' --type rust
```

### Go — Shutdown Primitives
```bash
# Panics
rg 'panic\(' --type go -g '!*test*'

# Unbounded allocation  
rg 'make\(\[\]' --type go

# Integer overflow in consensus
rg '\.Quo\(|\.Div\(|\.Mul\(' --type go

# Non-determinism
rg 'time\.Now\(\)|rand\.' --type go

# Missing error checks
rg 'if err != nil' --type go  # compare against total error returns
```

### JavaScript/TypeScript — Shutdown Primitives
```bash
# Infinite loop via precision loss
rg 'parseInt\(' --type js --type ts
rg 'for.*\.length' --type js --type ts

# Prototype pollution
rg '\[.*\]\s*=' --type js --type ts  # bracket notation assignment

# Missing null checks
rg 'req\.body|req\.query|req\.params' --type js --type ts
```
