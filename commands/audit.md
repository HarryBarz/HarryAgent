# /audit Command

## Usage
```
/audit [target_path] [--scope <files_or_dirs>] [--stack <cosmos|geth|substrate|rust-l1|go-l1|zk|move>] [--focus <surface>] [--skip-phase <phase_number>]
```

## Description
Runs the full 6-phase HarryAgent audit pipeline against the target blockchain infrastructure codebase.

## Execution Flow

### Step 0: Pre-flight

1. **Validate target exists:**
   ```
   ls [target_path]
   ```
   If no target_path provided, use current working directory.

2. **Check for prior audits:**
   - Look for existing `AUDIT_REPORT.md`, `RECON_REPORT.md` in the target
   - Look for `security/`, `audit/`, `audits/` directories
   - Look for `SECURITY.md`, `SECURITY_POLICY.md`
   - If found, read them to avoid duplicate findings

3. **Detect tech stack** (if --stack not provided):
   - `go.mod` + cosmos-sdk import -> Cosmos SDK
   - `go.mod` + go-ethereum import -> Geth fork
   - `Cargo.toml` + substrate/frame import -> Substrate
   - `Cargo.toml` + solana-sdk import -> Solana ecosystem
   - `Move.toml` -> Move chain
   - `go.mod` without specific framework -> Custom Go L1
   - `Cargo.toml` without specific framework -> Custom Rust L1
   - ZK-specific: look for `circuit`, `prover`, `verifier`, `snark`, `stark` in directory names

4. **Load tech-stack patterns:**
   Read the appropriate pattern file from `patterns/dlt-infra/`

5. **Determine scope:**
   - If --scope provided, use it
   - Otherwise, identify in-scope directories:
     - INCLUDE: `consensus/`, `p2p/`, `node/`, `core/`, `state/`, `mempool/`, `txpool/`, `crypto/`, `rpc/`, `api/`, `validator/`, `staking/`, `runtime/`, `pallets/`, `x/` (cosmos modules), `crates/`
     - EXCLUDE: `test/`, `tests/`, `mock/`, `mocks/`, `testutil/`, `scripts/`, `docs/`, `examples/`, `vendor/`, `third_party/`, `proto/` (generated code)

### Step 1: Reconnaissance (Phase 1)

Launch 2 agents in parallel using the Agent tool:

**Agent 1 - Structure Recon:**
```
Prompt: Read agents/shared/recon.md. Execute the STRUCTURE reconnaissance on [target_path].
Map the full directory structure, identify all source files in scope, count lines of code,
identify the build system, list all dependencies, and find all entry points (main functions,
CLI commands, RPC handlers, P2P message handlers).
Output a structured inventory.
Tech stack: [detected_stack]
```

**Agent 2 - Protocol Recon:**
```
Prompt: Read agents/shared/recon.md. Execute the PROTOCOL reconnaissance on [target_path].
Identify the consensus mechanism, networking protocol, state model, transaction types,
cryptographic primitives used, and key invariants the protocol must maintain.
Read the README, architecture docs, and protocol specs if available.
Tech stack: [detected_stack]
```

Combine outputs into `RECON_REPORT.md`.

### Step 2: Flow Mapping (Phase 2)

Launch 1 agent:

```
Prompt: Read agents/shared/flow-mapper.md. Using the RECON_REPORT.md, trace the critical
fund/value flows and state transition paths in [target_path].
Focus on: transaction lifecycle, block lifecycle, fund flows, validator lifecycle.
Tech stack: [detected_stack]
```

Output: Flow maps appended to `RECON_REPORT.md`.

### Step 3: Breadth Sweep (Phase 3)

Launch 7 agents in parallel using the Agent tool:

```
For each agent in [consensus, p2p-network, state-machine, crypto, rpc-surface, mempool, validator-ops]:
  Prompt: Read agents/dlt-infra/{agent}-hunter.md and rules/gates.md.
  You are the {agent} hunter. Scan [target_path] for vulnerabilities in your domain.
  Tech stack: [detected_stack]
  Recon report: [paste relevant section from RECON_REPORT.md]
  
  For each potential finding, form a hypothesis:
  IF [action] THEN [violation] BECAUSE [mechanism at file:line]
  
  Score each hypothesis using the confidence formula.
  Apply Gate 1 (hypothesis formation) before including.
  
  Output: List of hypotheses with confidence scores.
```

Collect all hypotheses. Deduplicate by root cause (different agents may flag the same code from different angles -- keep the strongest formulation).

### Step 4: Depth Analysis (Phase 4)

For each hypothesis with confidence >= 0.4, ordered by confidence descending:

```
Prompt: Read rules/gates.md. Apply Gates 2-4 to this hypothesis:

HYPOTHESIS: [hypothesis text]
CONFIDENCE: [score]
SOURCE AGENT: [agent name]

Verify:
- Gate 2: Is the code path reachable? Trace from entry point to vulnerable code.
- Gate 3: Can the attacker control the inputs? What values are needed?
- Gate 4: What is the concrete impact? Quantify it.

If any gate fails, output REJECTED with the gate number and reason.
If all gates pass, output CONFIRMED with the full gate documentation.
```

### Step 5: Verification (Phase 5)

For each CONFIRMED hypothesis at Medium+ severity:

```
Prompt: Read agents/shared/verifier.md. Construct a PoC for this finding:

FINDING: [finding details]
TECH STACK: [detected_stack]
LANGUAGE: [Go/Rust/C++]

Construct the strongest possible PoC:
1. Prefer executable test if the project has a test framework
2. Otherwise, write a detailed step-by-step code trace with concrete values
3. For P2P/consensus issues, write a network-level scenario with exact message payloads

Apply Gate 5. If PoC construction fails, downgrade to LEAD.
```

### Step 6: Report Generation (Phase 6)

```
Prompt: Read agents/shared/report-writer.md. Generate the final AUDIT_REPORT.md.

Include:
- Executive summary
- Scope and methodology
- All CONFIRMED and VERIFIED findings (main body)
- All LEAD findings (appendix -- promising but unverified)
- All REJECTED hypotheses (appendix -- for transparency)

Apply Gate 6 before finalizing: re-verify every code reference, check for duplicates,
check against known issues.
```

Output: `AUDIT_REPORT.md` in the working directory.

### Post-Audit

1. Print summary to console:
   ```
   HarryAgent Audit Complete
   Target: [target_path]
   Tech Stack: [detected_stack]
   Findings: X Critical, Y High, Z Medium, W Low
   Leads: N (unverified, review manually)
   Rejected: M hypotheses
   Report: AUDIT_REPORT.md
   ```

2. If any Critical or High findings exist, highlight them prominently.

## Quick Variants

### /scan
Runs Phase 1 (Recon) + Phase 3 (Breadth Sweep) only. Skips flow mapping, depth analysis, and PoC. Useful for initial triage of a new codebase.

### /hunt [surface]
Runs Phase 1 (Recon) + single agent from Phase 3 for the specified surface + Phase 4 (Depth) + Phase 5 (PoC). Deep dive into one attack surface.

Valid surfaces: `consensus`, `p2p`, `state`, `crypto`, `rpc`, `mempool`, `validator`
