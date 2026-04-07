# HarryAgent

Autonomous blockchain infrastructure security auditor for [Claude Code](https://claude.ai/code). Hunts for network shutdown bugs, node crashes, P2P exploits, and RPC vulnerabilities across Go, Rust, C++, and JavaScript blockchain codebases.

**148 battle-tested exploit patterns** extracted from real paid bug bounties (Immunefi, Sherlock, Code4rena, Ethereum Bug Bounty, HackerOne Cosmos, Spearbit, Cantina, Trail of Bits, Halborn).

## Install

```bash
git clone https://github.com/YOUR_USERNAME/HarryAgent.git
cd HarryAgent
./install.sh
```

That's it. HarryAgent is now active in every Claude Code session.

## Usage

```bash
# cd into any blockchain codebase
cd /path/to/target-chain

# Start Claude Code
claude

# Hunt for network shutdown bugs (highest value — $100K-$2M bounties)
/shutdown

# Full 6-phase security audit
/audit

# Deep dive into a specific attack surface
/hunt p2p
/hunt rpc
/hunt consensus
/hunt mempool
/hunt crypto
/hunt state
/hunt validator

# Quick breadth sweep (no PoC generation)
/scan
```

## What It Finds

| Severity | Bug Class | Typical Bounty |
|----------|-----------|----------------|
| **Critical** | Network shutdown, infinite minting, consensus bypass, double-spend | $100K - $2M |
| **High** | Chain halt, permanent fund lock, state corruption requiring hard fork | $25K - $500K |
| **Medium** | Temporary DoS, mempool manipulation, RPC crash | $5K - $50K |

## Supported Tech Stacks

| Stack | Language | Examples |
|-------|----------|----------|
| Cosmos SDK / CometBFT | Go | Sei, Celestia, Cronos, ZetaChain |
| Geth Forks / EVM L2 | Go | Scroll, Optimism, ZKsync, Berachain |
| Substrate / Polkadot | Rust | Astar, Hydration, Moonbeam, Acala |
| Custom Rust L1 | Rust | Solana, Firedancer, NEAR, Stellar |
| Custom Go L1 | Go | Flow, VeChainThor, gno.land |
| ZK Infrastructure | Rust/Go | ZKsync, Scroll, Starknet, RISC Zero |
| Move Chains | Move/Rust | Sui, Aptos |

## Real-Exploit Pattern Database

HarryAgent includes **148 vulnerability patterns** extracted from real, paid-out bug bounty reports:

| Dataset | Patterns | Source |
|---------|----------|--------|
| Node Crash (`node-crash.md`) | 30 | Shardeum, Firedancer, SEDA, Movement, Optimism, Story Protocol |
| P2P Network (`p2p.md`) | 69 | Geth, Bitcoin Core, libp2p, CometBFT, Solana, NEAR, Polkadot, Avalanche |
| RPC Surface (`rpc-crash.md`) | 49 | Geth, Nethermind, Besu, Erigon, Reth, Sui, Aptos, Monad |

Every pattern includes:
- The exact bug class and root cause
- Which chains were affected
- Real code patterns showing the vulnerability
- Detection strategy (what to grep for)
- CVE/advisory IDs where available

## Architecture

```
HarryAgent/
├── CLAUDE.md                          # System prompt (identity + pipeline)
├── install.sh                         # Installs to ~/.claude/
├── commands/
│   ├── audit.md                       # /audit — full 6-phase pipeline
│   └── shutdown.md                    # /shutdown — network shutdown hunt
├── agents/
│   ├── dlt-infra/                     # 7 specialized hunter agents
│   │   ├── consensus-hunter.md
│   │   ├── p2p-network-hunter.md
│   │   ├── state-machine-hunter.md
│   │   ├── crypto-hunter.md
│   │   ├── rpc-surface-hunter.md
│   │   ├── mempool-hunter.md
│   │   └── validator-ops-hunter.md
│   └── shared/                        # Support agents
│       ├── recon.md
│       ├── flow-mapper.md
│       ├── verifier.md
│       └── report-writer.md
├── patterns/
│   └── dlt-infra/
│       ├── cosmos-sdk.md              # Cosmos-specific patterns
│       ├── geth-forks.md              # Geth fork patterns
│       ├── substrate.md               # Substrate/Polkadot patterns
│       ├── rust-l1s.md                # Rust L1 patterns
│       ├── go-l1s.md                  # Go L1 patterns
│       ├── move-chains.md             # Move chain patterns
│       ├── zk-infra.md                # ZK infrastructure patterns
│       └── real-exploits/
│           ├── node-crash.md          # 30 real node crash patterns
│           ├── p2p.md                 # 69 real P2P exploit patterns
│           └── rpc-crash.md           # 49 real RPC crash patterns
├── rules/
│   ├── gates.md                       # 6-gate quality system
│   └── anti-hallucination.md          # Zero false positive protocol
└── references/
    └── dlt-infra/
        ├── attack-vectors.md          # Master attack vector catalog
        └── bounty-targets.md          # Bug bounty program analysis
```

## How It Works

### /shutdown (Network Shutdown Hunt)

1. **Detects tech stack** from build files (go.mod, Cargo.toml, Move.toml)
2. **Language-specific panic scan** — greps for `.unwrap()`, `panic!`, nil derefs, unbounded allocations
3. **Pattern matching** — runs 148 real-exploit detection strategies against the codebase
4. **Consensus path deep dive** — traces BeginBlock/EndBlock/FinalizeBlock for crashes
5. **Outputs** `SHUTDOWN_REPORT.md` with findings, PoC concepts, and fix recommendations

### /audit (Full Pipeline)

6 phases: Recon → Flow Mapping → Breadth Sweep (7 parallel hunters) → Depth Analysis → PoC Verification → Report

### Quality Gates

Every finding passes through 6 gates before inclusion:
1. **Hypothesis** — clearly stated IF/THEN/BECAUSE
2. **Reachability** — code path traced from entry point
3. **Controllability** — attacker can control the inputs
4. **Impact** — concrete, quantified damage
5. **PoC** — executable test or detailed code trace
6. **Clean report** — no fabricated references, no hedging

## Uninstall

```bash
./uninstall.sh
```

## Credits

Patterns extracted from public bug bounty reports, CVEs, security advisories, and academic research. All sources credited in the pattern files.

Built for the bug bounty grind.
