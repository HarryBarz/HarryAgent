# Go L1 Blockchain Vulnerability Patterns (Flow, VeChainThor, gno.land, Kaia)

## Architecture Context

### Flow
- **Multi-role architecture**: Splits consensus, verification, execution, and collection across different node types.
- **Cadence smart contract language**: Resource-oriented language executed in the Cadence VM; distinct from Move but shares lineage.
- **Spork upgrades**: Network-wide coordinated upgrades that reset state roots.
- **Written in Go**: Core node software, networking, execution engine all in Go.

### VeChainThor
- **Proof of Authority (PoA)**: Authority masternodes produce blocks; economic incentives via VET/VTHO dual-token model.
- **Multi-party payment protocol (MPP)**: Enables sponsored transactions where gas is paid by a third party.
- **Built on Go**: Forked and heavily modified Ethereum-like architecture.

### gno.land
- **GnoVM**: Interpreted Go (Gno) as a smart contract language. Contracts are written in a Go subset.
- **Tendermint consensus**: Uses Tendermint BFT for consensus.
- **Realms and packages**: Stateful smart contracts (realms) and reusable libraries (packages).
- **Written in Go**: VM interpreter, node, and all infrastructure.

### Kaia (formerly Klaytn)
- **Istanbul BFT consensus**: Modified PBFT with committee-based block production.
- **EVM compatible**: Supports Solidity smart contracts but with Go-based node implementation.
- **Service chains**: Layer 2 anchoring for enterprise use cases.
- **Written in Go**: Core node based on modified go-ethereum.

---

## Scan Priority

| Pattern  | Severity | Scan Priority |
|----------|----------|---------------|
| GOL1-001 | Critical | P0 - Always scan |
| GOL1-002 | Critical | P0 - Always scan |
| GOL1-003 | Critical | P0 - Always scan |
| GOL1-004 | High     | P0 - Always scan |
| GOL1-005 | Critical | P1 - Scan if custom VM present |
| GOL1-006 | High     | P1 - Scan in consensus/execution paths |
| GOL1-007 | High     | P1 - Scan in state management |
| GOL1-008 | Medium   | P2 - Scan if CGo dependencies present |

---

## GOL1-001: Map Iteration Non-Determinism

**Severity**: Critical
**Chains**: All Go L1s (Flow, VeChainThor, gno.land, Kaia)
**Category**: Consensus / Determinism

### Description

Go maps have intentionally randomized iteration order. If map iteration is used in any code path that affects state computation, transaction ordering, or block production, different nodes will compute different results, causing consensus failures, chain splits, or inconsistent state roots.

This is one of the most common and dangerous bugs in Go-based blockchain implementations.

### Vulnerable Pattern

```go
// BAD: Map iteration order affects validator selection
func selectValidators(candidates map[string]*Validator) []string {
    var selected []string
    for addr, v := range candidates {
        if v.Stake >= minStake {
            selected = append(selected, addr)
        }
    }
    // selected order is non-deterministic across nodes!
    return selected[:numValidators]
}

// BAD: Map iteration determines transaction execution order
func executePendingTxs(pending map[common.Hash]*Transaction) []*Receipt {
    var receipts []*Receipt
    for _, tx := range pending {
        receipt := executeTx(tx)
        receipts = append(receipts, receipt)
        // Each execution may modify state, so order matters
    }
    return receipts
}

// BAD: Map iteration used to compute state hash
func computeStateRoot(accounts map[common.Address]*Account) common.Hash {
    hasher := sha3.NewLegacyKeccak256()
    for addr, acct := range accounts {
        hasher.Write(addr.Bytes())
        hasher.Write(acct.Serialize())
        // Hash depends on iteration order - non-deterministic!
    }
    return common.BytesToHash(hasher.Sum(nil))
}
```

### Secure Pattern

```go
// GOOD: Sort keys before iterating
func selectValidators(candidates map[string]*Validator) []string {
    // Collect and sort keys for deterministic ordering
    addrs := make([]string, 0, len(candidates))
    for addr := range candidates {
        addrs = append(addrs, addr)
    }
    sort.Strings(addrs)

    var selected []string
    for _, addr := range addrs {
        if candidates[addr].Stake >= minStake {
            selected = append(selected, addr)
        }
    }
    return selected[:numValidators]
}

// GOOD: Use a sorted data structure instead of a map
// Use a BTree, sorted slice, or the blockchain's own ordered storage
type OrderedAccountStore struct {
    accounts []AccountEntry // kept sorted by address
}
```

### What to Scan For

- `range` over `map[...]` in any code path that: computes state roots/hashes, determines transaction ordering, selects validators/committees, produces block content, or generates any output that must be identical across nodes.
- Maps used to accumulate results that are later serialized or hashed.
- Maps used in reward distribution calculations.
- Test code that passes because of lucky iteration order but will fail intermittently.

---

## GOL1-002: Goroutine Leaks and Race Conditions

**Severity**: Critical
**Chains**: All Go L1s
**Category**: Concurrency / Consensus

### Description

Go's concurrency primitives (goroutines, channels, mutexes) are powerful but error-prone. In blockchain node software, concurrency bugs can cause:
- **Race conditions** in shared state leading to non-deterministic behavior and consensus divergence.
- **Goroutine leaks** from unbuffered channels or missing context cancellation, leading to memory exhaustion and node crashes.
- **Deadlocks** from inconsistent lock ordering, causing nodes to freeze.

### Vulnerable Pattern

```go
// BAD: Race condition on shared state in consensus
type ConsensusEngine struct {
    currentHeight uint64  // accessed by multiple goroutines without sync
    currentRound  uint32
}

func (ce *ConsensusEngine) handleProposal(proposal *Proposal) {
    if proposal.Height == ce.currentHeight { // unsynchronized read
        ce.currentRound++                    // unsynchronized write
        ce.processProposal(proposal)
    }
}

// BAD: Goroutine leak from unbuffered channel
func (n *Node) broadcastBlock(block *Block) {
    for _, peer := range n.peers {
        go func(p *Peer) {
            p.sendCh <- block // blocks forever if peer is slow/disconnected
            // goroutine never returns, leaking memory
        }(peer)
    }
}

// BAD: Deadlock from inconsistent lock ordering
func (s *StateDB) Transfer(from, to common.Address, amount *big.Int) {
    s.locks[from].Lock()   // Lock A then B
    s.locks[to].Lock()
    // Another goroutine may lock B then A -> deadlock
    defer s.locks[from].Unlock()
    defer s.locks[to].Unlock()
    // ...
}
```

### Secure Pattern

```go
// GOOD: Proper synchronization
type ConsensusEngine struct {
    mu            sync.RWMutex
    currentHeight uint64
    currentRound  uint32
}

func (ce *ConsensusEngine) handleProposal(proposal *Proposal) {
    ce.mu.Lock()
    defer ce.mu.Unlock()
    if proposal.Height == ce.currentHeight {
        ce.currentRound++
        ce.processProposal(proposal)
    }
}

// GOOD: Goroutine with timeout and context
func (n *Node) broadcastBlock(ctx context.Context, block *Block) {
    for _, peer := range n.peers {
        go func(p *Peer) {
            select {
            case p.sendCh <- block:
                // sent successfully
            case <-time.After(5 * time.Second):
                log.Warn("peer send timeout", "peer", p.ID)
            case <-ctx.Done():
                return
            }
        }(peer)
    }
}

// GOOD: Consistent lock ordering by sorting addresses
func (s *StateDB) Transfer(from, to common.Address, amount *big.Int) {
    first, second := orderAddresses(from, to)
    s.locks[first].Lock()
    s.locks[second].Lock()
    defer s.locks[second].Unlock()
    defer s.locks[first].Unlock()
    // ...
}
```

### What to Scan For

- Shared variables accessed without `sync.Mutex`, `sync.RWMutex`, or `atomic` operations.
- Channel sends without `select` timeout or context cancellation.
- Goroutines spawned in loops without completion tracking (`sync.WaitGroup`).
- Inconsistent mutex lock ordering across different code paths.
- Run `go vet -race` and check for known race detector findings.

---

## GOL1-003: Custom Serialization Bugs

**Severity**: Critical
**Chains**: All Go L1s
**Category**: Consensus / Data Integrity

### Description

Go L1 blockchains often implement custom serialization formats (RLP variants, Protobuf extensions, custom binary encodings). Bugs in serialization cause consensus divergence because nodes disagree on the canonical byte representation of blocks, transactions, or state.

### Vulnerable Pattern

```go
// BAD: Struct field ordering not guaranteed across Go versions
type BlockHeader struct {
    Height    uint64
    Timestamp int64
    // Adding a field here in an upgrade may change serialization
    // if using reflection-based encoding
    ParentHash common.Hash
}

// BAD: Floating point in serialization (non-deterministic across platforms)
type RewardCalc struct {
    Rate float64 `json:"rate"`
}

func (r *RewardCalc) Serialize() []byte {
    data, _ := json.Marshal(r) // float64 JSON repr varies across implementations
    return data
}

// BAD: Optional/nil fields serialized inconsistently
func encodeTransaction(tx *Transaction) []byte {
    buf := new(bytes.Buffer)
    buf.Write(encodeUint64(tx.Nonce))
    if tx.Data != nil {
        buf.Write(tx.Data) // missing length prefix
    }
    // When Data is nil vs empty slice, output may differ
    // Decoder cannot distinguish between "no data" and "empty data"
    return buf.Bytes()
}
```

### Secure Pattern

```go
// GOOD: Explicit field ordering with tagged encoding
type BlockHeader struct {
    Height     uint64      `rlp:"0"`
    Timestamp  int64       `rlp:"1"`
    ParentHash common.Hash `rlp:"2"`
}

// GOOD: Fixed-point arithmetic instead of floating point
type RewardCalc struct {
    RateBasisPoints uint64 // 10000 = 100%, deterministic integer math
}

// GOOD: Explicit length-prefixed encoding with nil handling
func encodeTransaction(tx *Transaction) []byte {
    buf := new(bytes.Buffer)
    buf.Write(encodeUint64(tx.Nonce))
    if tx.Data == nil {
        buf.Write(encodeUint32(0)) // explicit zero length
    } else {
        buf.Write(encodeUint32(uint32(len(tx.Data))))
        buf.Write(tx.Data)
    }
    return buf.Bytes()
}
```

### What to Scan For

- Custom `Encode`/`Decode`, `Marshal`/`Unmarshal` functions, especially using reflection.
- `float32`/`float64` used in any consensus-critical data structure.
- `nil` vs empty slice ambiguity in encoding (`[]byte(nil)` vs `[]byte{}`).
- Struct fields added or reordered without serialization version bumps.
- Missing round-trip tests (`encode(decode(x)) == x` and `decode(encode(x)) == x`).

---

## GOL1-004: Error Handling Gaps

**Severity**: High
**Chains**: All Go L1s
**Category**: Reliability / Correctness

### Description

Go uses explicit error returns rather than exceptions. Unchecked errors in critical paths can lead to:
- Silent data corruption when a failed database write is not detected.
- Consensus divergence when nodes handle errors differently.
- Denial of service when error conditions cause panics in production.

### Vulnerable Pattern

```go
// BAD: Ignored error on state write
func (s *StateDB) CommitBlock(block *Block) {
    for _, tx := range block.Transactions {
        receipt, err := s.ApplyTransaction(tx)
        // err is silently ignored - state may be partially applied
        s.receipts = append(s.receipts, receipt)
    }
    s.db.Commit() // also ignoring error return
}

// BAD: Error converted to log instead of propagation
func (v *Validator) VerifyBlock(block *Block) bool {
    sig, err := crypto.VerifySignature(block.Header.Signature, block.Hash())
    if err != nil {
        log.Error("signature verification failed", "err", err)
        // Returns default zero value of sig (false? or uninitialized?)
        // Should return error explicitly
    }
    return sig
}

// BAD: Panic on error in production code
func MustLoadConfig(path string) *Config {
    data, err := os.ReadFile(path)
    if err != nil {
        panic(err) // crashes the node
    }
    var config Config
    json.Unmarshal(data, &config) // error ignored
    return &config
}
```

### Secure Pattern

```go
// GOOD: All errors checked and propagated
func (s *StateDB) CommitBlock(block *Block) error {
    for _, tx := range block.Transactions {
        receipt, err := s.ApplyTransaction(tx)
        if err != nil {
            return fmt.Errorf("apply tx %s: %w", tx.Hash(), err)
        }
        s.receipts = append(s.receipts, receipt)
    }
    if err := s.db.Commit(); err != nil {
        return fmt.Errorf("commit state db: %w", err)
    }
    return nil
}

// GOOD: Error returned explicitly
func (v *Validator) VerifyBlock(block *Block) (bool, error) {
    valid, err := crypto.VerifySignature(block.Header.Signature, block.Hash())
    if err != nil {
        return false, fmt.Errorf("verify block %d signature: %w", block.Height, err)
    }
    return valid, nil
}
```

### What to Scan For

- Variables named `err` that are assigned but never checked (`_ , err = ...` followed by no `if err`).
- Functions with error return values called without capturing the error.
- `log.Error`/`log.Warn` used as a substitute for returning an error in critical paths.
- `panic()` calls in non-initialization code (consensus, execution, networking).
- Linter: run `errcheck` and `staticcheck` on the codebase.

---

## GOL1-005: Custom VM Vulnerabilities

**Severity**: Critical
**Chains**: Flow (Cadence VM), gno.land (GnoVM)
**Category**: Execution / VM Safety

### Description

Custom VMs are complex interpreters that must enforce gas metering, memory limits, and deterministic execution. Common vulnerabilities:
- **Gas metering bypass**: Operations that consume real resources (CPU, memory) but are not charged gas, enabling DoS.
- **Interpreter bugs**: Incorrect evaluation of expressions, edge cases in control flow, or type system unsoundness.
- **Host function escape**: Calling into Go host functions from the VM with unexpected parameters.
- **Non-deterministic behavior**: VM producing different results on different platforms or Go versions.

### Vulnerable Pattern

```go
// BAD: Gas not charged for recursive data structure operations (GnoVM example)
func (vm *GnoVM) evalStringConcat(a, b string) string {
    // No gas charge for string concatenation
    // Attacker can create exponentially growing strings
    return a + b
}

// BAD: Host function trusts VM-provided length without validation
func (vm *VM) hostReadMemory(offset, length uint64) []byte {
    // Missing bounds check - VM can read arbitrary host memory
    return vm.memory[offset : offset+length]
}

// BAD: Non-deterministic math in VM (Cadence example)
func (interp *Interpreter) evalDivision(a, b *big.Int) *big.Int {
    result := new(big.Int)
    result.Div(a, b) // Division by zero not handled
    return result
}
```

### Secure Pattern

```go
// GOOD: Gas charged for all operations proportional to cost
func (vm *GnoVM) evalStringConcat(a, b string) (string, error) {
    cost := uint64(len(a) + len(b))
    if err := vm.chargeGas(cost * gasCostPerByte); err != nil {
        return "", ErrOutOfGas
    }
    if len(a)+len(b) > maxStringLength {
        return "", ErrStringTooLong
    }
    return a + b, nil
}

// GOOD: Host function validates all parameters
func (vm *VM) hostReadMemory(offset, length uint64) ([]byte, error) {
    if offset+length > uint64(len(vm.memory)) || offset+length < offset {
        return nil, ErrMemoryOutOfBounds
    }
    result := make([]byte, length) // copy, don't slice
    copy(result, vm.memory[offset:offset+length])
    return result, nil
}
```

### What to Scan For

- Operations in VM interpreter loops that do not call `chargeGas` or equivalent.
- Host/native functions callable from smart contracts without parameter validation.
- `math/big` operations without zero-divisor checks.
- String/array operations without length limits.
- Use of `reflect`, `unsafe`, or platform-dependent operations inside the VM.
- Missing fuel/gas checks on loops, recursion, and memory allocation.

---

## GOL1-006: Interface Type Assertion Panics

**Severity**: High
**Chains**: All Go L1s
**Category**: Reliability / DoS

### Description

Go type assertions on interface values panic at runtime if the assertion fails and the comma-ok pattern is not used. In blockchain nodes, a panic in consensus or block processing crashes the node, potentially causing network-wide outages if the same input triggers the panic on all nodes.

### Vulnerable Pattern

```go
// BAD: Type assertion without comma-ok
func processMessage(msg Message) {
    switch msg.Type() {
    case MsgProposal:
        proposal := msg.(ProposalMessage) // panics if msg is wrong type
        handleProposal(proposal)
    case MsgVote:
        vote := msg.(VoteMessage) // panics if msg is wrong type
        handleVote(vote)
    }
}

// BAD: Type assertion on deserialized data from network
func handlePeerMessage(data interface{}) {
    block := data.(*Block) // panics if peer sends unexpected type
    processBlock(block)
}

// BAD: Nested type assertion chain
func getBalance(state interface{}) uint64 {
    account := state.(map[string]interface{})["account"].(map[string]interface{})
    balance := account["balance"].(uint64) // any of these can panic
    return balance
}
```

### Secure Pattern

```go
// GOOD: Comma-ok pattern
func processMessage(msg Message) error {
    switch msg.Type() {
    case MsgProposal:
        proposal, ok := msg.(ProposalMessage)
        if !ok {
            return fmt.Errorf("expected ProposalMessage, got %T", msg)
        }
        return handleProposal(proposal)
    case MsgVote:
        vote, ok := msg.(VoteMessage)
        if !ok {
            return fmt.Errorf("expected VoteMessage, got %T", msg)
        }
        return handleVote(vote)
    default:
        return fmt.Errorf("unknown message type: %d", msg.Type())
    }
}

// GOOD: Type switch for safe exhaustive matching
func handlePeerMessage(data interface{}) error {
    switch v := data.(type) {
    case *Block:
        return processBlock(v)
    case *Transaction:
        return processTx(v)
    default:
        return fmt.Errorf("unexpected message type from peer: %T", data)
    }
}
```

### What to Scan For

- `x.(Type)` without the `, ok` pattern, especially on values from: network deserialization, database reads, plugin/module interfaces, or RPC handler parameters.
- Nested type assertions (multiple assertions in one expression).
- Type assertions in consensus, block processing, or transaction execution paths.
- `interface{}` used as a parameter type in core APIs (increases assertion risk).

---

## GOL1-007: Slice/Pointer Aliasing Bugs

**Severity**: High
**Chains**: All Go L1s
**Category**: Memory Safety / Determinism

### Description

Go slices are reference types that share underlying arrays. Appending to a slice may or may not create a new backing array depending on capacity. This leads to subtle aliasing bugs where mutations through one slice unexpectedly affect another, causing state corruption or non-deterministic behavior.

### Vulnerable Pattern

```go
// BAD: Slice aliasing through sub-slicing
func (bp *BlockProducer) selectTransactions(pool []Transaction) []Transaction {
    selected := pool[:0] // shares same backing array as pool!
    for _, tx := range pool {
        if tx.GasPrice >= minGas {
            selected = append(selected, tx) // overwrites pool entries
        }
    }
    return selected
    // pool is now corrupted - some entries overwritten
}

// BAD: Returning slice of internal state
func (s *StateDB) GetValidators() []Validator {
    return s.validators // caller can modify internal state
}

// BAD: Append may or may not alias
func addPeer(peers []Peer, newPeer Peer) []Peer {
    result := append(peers, newPeer)
    // If len(peers) < cap(peers), result shares backing array with peers
    // If len(peers) == cap(peers), result has a new backing array
    // Behavior depends on runtime capacity - non-deterministic from caller's perspective
    return result
}
```

### Secure Pattern

```go
// GOOD: Explicit copy to avoid aliasing
func (bp *BlockProducer) selectTransactions(pool []Transaction) []Transaction {
    selected := make([]Transaction, 0, len(pool))
    for _, tx := range pool {
        if tx.GasPrice >= minGas {
            selected = append(selected, tx)
        }
    }
    return selected // independent backing array
}

// GOOD: Return a copy of internal state
func (s *StateDB) GetValidators() []Validator {
    result := make([]Validator, len(s.validators))
    copy(result, s.validators)
    return result
}

// GOOD: Explicit pre-allocation
func addPeer(peers []Peer, newPeer Peer) []Peer {
    result := make([]Peer, len(peers)+1)
    copy(result, peers)
    result[len(peers)] = newPeer
    return result
}
```

### What to Scan For

- `slice[:0]` re-slicing that reuses the same backing array.
- Functions returning slices of internal struct fields without copying.
- `append()` to sub-slices where the original may still be referenced.
- Pointer fields in slice elements (mutating the pointed-to value affects all slices sharing that element).
- Concurrent access to slices without synchronization (slices are not goroutine-safe).

---

## GOL1-008: CGo Boundary Bugs

**Severity**: Medium
**Chains**: VeChainThor (crypto libs), Kaia (leveldb/rocksdb), any L1 using C dependencies
**Category**: Memory Safety / Interop

### Description

CGo allows Go code to call C functions, but the boundary between Go's garbage-collected memory and C's manually managed memory is a source of bugs:
- Go pointers passed to C can be garbage collected if not pinned.
- C memory returned to Go must be explicitly freed.
- Null pointers from C are not automatically checked in Go.
- CGo calls are expensive and block OS threads, causing goroutine scheduling issues.

### Vulnerable Pattern

```go
// BAD: Go memory passed to C without pinning
func hashData(data []byte) []byte {
    result := make([]byte, 32)
    // data may be moved by GC while C is reading it
    C.compute_hash(
        (*C.char)(unsafe.Pointer(&data[0])),
        C.int(len(data)),
        (*C.char)(unsafe.Pointer(&result[0])),
    )
    return result
}

// BAD: C-allocated memory never freed
func loadDatabase(path string) *Database {
    cpath := C.CString(path) // allocates C memory
    // Missing: defer C.free(unsafe.Pointer(cpath))
    db := C.open_database(cpath)
    return &Database{handle: db}
}

// BAD: Null pointer from C not checked
func getRecord(db *C.Database, key string) []byte {
    ckey := C.CString(key)
    defer C.free(unsafe.Pointer(ckey))
    result := C.db_get(db, ckey) // may return NULL
    // Dereferencing NULL result will crash
    return C.GoBytes(unsafe.Pointer(result.data), result.length)
}
```

### Secure Pattern

```go
// GOOD: Use runtime.Pinner (Go 1.21+) or copy data for C
func hashData(data []byte) []byte {
    // Copy to C-allocated memory
    cdata := C.CBytes(data)
    defer C.free(cdata)

    var result [32]byte
    cresult := (*C.char)(unsafe.Pointer(&result[0]))

    // Pin the Go memory if using direct pointers
    pinner := runtime.Pinner{}
    pinner.Pin(&result[0])
    defer pinner.Unpin()

    C.compute_hash((*C.char)(cdata), C.int(len(data)), cresult)
    return result[:]
}

// GOOD: C memory properly freed
func loadDatabase(path string) *Database {
    cpath := C.CString(path)
    defer C.free(unsafe.Pointer(cpath))
    db := C.open_database(cpath)
    if db == nil {
        return nil // handle error
    }
    runtime.SetFinalizer(&Database{handle: db}, func(d *Database) {
        C.close_database(d.handle)
    })
    return &Database{handle: db}
}

// GOOD: Null check on C return value
func getRecord(db *C.Database, key string) ([]byte, error) {
    ckey := C.CString(key)
    defer C.free(unsafe.Pointer(ckey))
    result := C.db_get(db, ckey)
    if result.data == nil {
        return nil, fmt.Errorf("key not found: %s", key)
    }
    defer C.free(unsafe.Pointer(result.data))
    return C.GoBytes(unsafe.Pointer(result.data), result.length), nil
}
```

### What to Scan For

- `C.CString()` calls without corresponding `C.free()`.
- `unsafe.Pointer` conversions of Go slice/string data passed to C functions.
- Missing null checks on return values from C functions.
- CGo calls in hot paths (each CGo call has ~100ns overhead and blocks an OS thread).
- `C.GoBytes` or `C.GoString` without first checking for null.
- Missing `runtime.Pinner` or `runtime.KeepAlive` when passing Go pointers to long-running C functions.
