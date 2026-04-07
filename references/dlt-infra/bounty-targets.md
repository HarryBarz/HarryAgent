# Bug Bounty Target Analysis & Prioritization

Analysis of active blockchain infrastructure bug bounty programs for HarryAgent targeting.

## Prioritization Matrix

Prioritize targets by: (Bounty Size) x (Attack Surface Breadth) x (Code Accessibility) / (Competition Level)

## Tier 1: High Bounty + Broad Attack Surface

### Optimism ($2M max)
- **Stack:** Geth fork (Go), custom sequencer, fraud proof system
- **Repos:** op-geth, op-node, optimism monorepo
- **Key surfaces:** L1<->L2 bridge, sequencer, dispute game, custom precompiles
- **Patterns:** GETH-001 through GETH-010
- **Note:** Large scope, mature program, active triaging

### ZKsync Era ($1.1M max) / ZKsync Lite ($2.3M max)
- **Stack:** Custom ZK rollup (Rust/Solidity), modified Geth
- **Repos:** zksync-era, era-zk_toolbox
- **Key surfaces:** ZK circuits, L1 verifier contracts, custom compiler (zksolc), bootloader
- **Patterns:** ZK-001 through ZK-010, GETH-001
- **Note:** ZK circuit bugs are highest value. Compiler bugs also in scope.

### Wormhole ($1M max)
- **Stack:** Multi-chain bridge (Rust/Go/TypeScript)
- **Repos:** wormhole, wormhole-connect
- **Key surfaces:** Guardian network, VAA verification, relayer, cross-chain message passing
- **Patterns:** BRIDGE-001 through BRIDGE-004, CRYPTO-003
- **Note:** Guardian set changes are high-value target

### Sui Protocol ($1M max - HackenProof)
- **Stack:** Custom L1 (Rust/Move)
- **Repos:** sui
- **Key surfaces:** Narwhal/Bullshark consensus, object model, Move VM, Sui framework
- **Patterns:** MOVE-001 through MOVE-008, RUST-001 through RUST-005
- **Note:** Object ownership model is unique attack surface

### NEAR Protocol ($1M max - HackenProof)
- **Stack:** Custom L1 (Rust)
- **Repos:** nearcore
- **Key surfaces:** Nightshade sharding, chunk production, state sync, contract runtime
- **Patterns:** RUST-001 through RUST-010, RUST-007 (NEAR-specific)
- **Note:** Sharding adds complexity to consensus and state management

### Aptos ($1M max - HackenProof)
- **Stack:** Custom L1 (Rust/Move)
- **Repos:** aptos-core
- **Key surfaces:** AptosBFT consensus, Move VM, parallel execution (Block-STM), object model
- **Patterns:** MOVE-001 through MOVE-008, RUST-001 through RUST-005
- **Note:** Parallel execution engine (Block-STM) is unique attack surface

### OKX ($1M max - HackenProof)
- **Stack:** Custom chain infrastructure
- **Key surfaces:** Exchange infrastructure, blockchain nodes
- **Note:** Very broad scope, competitive

### Polygon ($250K max, $7.1M total paid)
- **Stack:** Multiple chains (Go/Rust) - PoS, zkEVM
- **Key surfaces:** Heimdall (Cosmos SDK fork), Bor (Geth fork), zkEVM circuits
- **Patterns:** COS-001 through COS-012, GETH-001 through GETH-010, ZK-001 through ZK-010

## Tier 2: Medium Bounty + Good Attack Surface

### Firedancer ($500K max)
- **Stack:** Solana validator client reimplementation (C)
- **Key surfaces:** Consensus, networking, transaction processing - entirely new implementation
- **Patterns:** RUST-001 (adapted for C), NET-001 through NET-008
- **Note:** New implementation of complex protocol = high bug density expected. C code = memory safety bugs.

### Sei ($500K max)
- **Stack:** Cosmos SDK (Go) with parallel EVM
- **Key surfaces:** Parallel EVM execution, order matching, Cosmos modules
- **Patterns:** COS-001 through COS-012, GETH-001 (EVM integration)
- **Note:** Parallel EVM is novel attack surface

### Babylon Labs ($500K max)
- **Stack:** Cosmos SDK (Go) with Bitcoin integration
- **Key surfaces:** Bitcoin staking protocol, BTC timestamping, Cosmos modules
- **Patterns:** COS-001 through COS-012
- **Note:** Bitcoin interop is unique, less competition

### Celestia ($375K max - HackenProof)
- **Stack:** Cosmos SDK (Go), CometBFT, data availability layer
- **Key surfaces:** Data availability sampling, blob processing, namespace Merkle trees
- **Patterns:** COS-001 through COS-012, CRYPTO-002
- **Note:** DA-specific primitives (NMT) are unique attack surface

### Hydration ($500K max)
- **Stack:** Substrate (Rust)
- **Key surfaces:** Omnipool DEX, cross-chain via XCM
- **Patterns:** SUB-001 through SUB-010
- **Note:** DeFi logic on Substrate - blend of DeFi and infra bugs

### Starknet ($350K max)
- **Stack:** Custom L2 (Rust/Cairo)
- **Key surfaces:** STARK prover/verifier, Cairo VM, Sequencer, L1 contracts
- **Patterns:** ZK-001 through ZK-010
- **Note:** Cairo-specific bugs in addition to ZK-generic bugs

### Scroll ($250K max)
- **Stack:** Geth fork + ZK rollup (Go/Rust)
- **Key surfaces:** zkEVM circuits, modified Geth, bridge, sequencer
- **Patterns:** GETH-001 through GETH-010, ZK-001 through ZK-010

### Stacks ($250K max)
- **Stack:** Custom L1 connected to Bitcoin (Rust)
- **Key surfaces:** Proof of Transfer consensus, Clarity VM, Bitcoin anchoring
- **Patterns:** RUST-001 through RUST-010

### Citrea ($250K max - HackenProof)
- **Stack:** Bitcoin ZK rollup (Rust)
- **Key surfaces:** BitVM verification, ZK proof generation, Bitcoin peg
- **Patterns:** ZK-001 through ZK-010, BRIDGE-001 through BRIDGE-004

### Stellar ($250K max)
- **Stack:** Custom L1 (Rust - stellar-core previously C++)
- **Key surfaces:** Stellar Consensus Protocol (SCP), asset issuance, path payments
- **Patterns:** RUST-001 through RUST-010, CON-001 through CON-010

### NEAR Intents: Smart Contracts ($300K max - HackenProof)
- **Stack:** NEAR smart contracts (Rust)
- **Key surfaces:** Atomic P2P transactions, intent execution, cross-chain messaging
- **Patterns:** RUST-007

## Tier 3: Smaller Bounty / Niche Targets

### Scallop Protocol ($300K - HackenProof)
- **Stack:** Sui Move smart contracts
- **Patterns:** MOVE-001 through MOVE-008

### Berachain ($250K max)
- **Stack:** Cosmos SDK + Geth fork (Proof of Liquidity)
- **Patterns:** COS-001 through COS-012, GETH-001

### Axelar Network ($500K max)
- **Stack:** Cosmos SDK cross-chain messaging
- **Patterns:** COS-001 through COS-012, BRIDGE-001 through BRIDGE-004

### Flow Protocol ($100K - HackenProof)
- **Stack:** Custom Go L1
- **Patterns:** GOL1-001 through GOL1-008, GOL1-005 (Cadence VM)

### gno.land ($5K - HackenProof)
- **Stack:** Custom Go L1 with GnoVM
- **Patterns:** GOL1-001 through GOL1-008, GOL1-005 (GnoVM)
- **Note:** Low bounty but novel VM = good for learning/reputation

### ZetaChain ($200K - HackenProof)
- **Stack:** Cosmos SDK + EVM (cross-chain)
- **Patterns:** COS-001 through COS-012, BRIDGE-001 through BRIDGE-004

### RISC Zero ($150K - HackenProof)
- **Stack:** ZK VM (Rust)
- **Patterns:** ZK-001 through ZK-010

---

## Strategy Recommendations

### Quick Wins (High probability of finding something)
1. **New implementations**: Firedancer, Citrea, Babylon -- new code = more bugs
2. **Custom precompiles**: Any Geth fork that adds precompiles (Scroll, Optimism, Berachain)
3. **Parallel execution**: Sei, Aptos -- novel execution model = unexplored edge cases
4. **Bridge logic**: Any cross-chain component (Wormhole, Axelar, ZetaChain, NEAR Intents)

### Deep Dives (Lower probability but massive payouts)
1. **ZK circuits**: ZKsync, Scroll, Starknet -- soundness bugs = maximum bounty
2. **Consensus bugs**: NEAR (sharding), Celestia (DA), Sui (Narwhal/Bullshark)
3. **Core protocol**: Sui, NEAR, Aptos -- fundamental protocol bugs in validator code

### Avoided (Too competitive or too low bounty)
- Low-bounty programs with high competition (gno.land $5K, Moonbeam $5K)
- Programs with "private" scope reviews that have zero payouts (may indicate unresponsive triaging)
