# Rust L1 Blockchain Vulnerability Patterns

Target chains: Solana, Firedancer (Solana validator in C/Rust FFI), NEAR, Stellar, Aleo

## Architecture Context (for agent reference)

```
Solana:
  Client RPC / JSON-RPC
      |
  Transaction Pipeline (sigverify -> banking stage -> PoH -> replay)
      |
  Solana Runtime (BPF/SBF programs, native programs, sysvars)
      |
  Validator (Turbine, Gossip, Repair, Snapshot)

NEAR:
  Client RPC
      |
  Runtime (VMLogic, near-vm / wasmer)
      |
  Chain Layer (chunks, block production, epoch management)
      |
  Network Layer (peer manager, routing, state sync)

Stellar:
  Horizon API
      |
  stellar-core (SCP consensus, overlay, herder, ledger)
      |
  Rust SDK / Soroban VM (smart contracts on Stellar)

Aleo:
  Client RPC
      |
  snarkVM (proof generation/verification, Aleo instructions)
      |
  snarkOS (consensus, peer-to-peer, block production)

Firedancer:
  Solana-compatible validator written in C with Rust FFI bindings
  Primary risk surface: C<->Rust boundary, reimplemented Solana logic
```

Key: Rust's safety guarantees are nullified inside `unsafe` blocks, at FFI boundaries, and in release-mode integer arithmetic. All five chains rely on performance-sensitive hot paths where these guarantees are routinely bypassed.

---

## RUST-001: Unsafe Blocks and Raw Pointer Dereference

**Impact:** Memory corruption, arbitrary code execution, node takeover (Critical)
**Severity:** Critical
**Frequency:** Common in validator hot paths (networking, serialization, memory-mapped accounts)

Blockchain node software in Rust uses `unsafe` extensively for performance. Every `unsafe` block is a potential memory safety violation -- buffer overflows, use-after-free, double-free, and dangling pointer dereference.

**What to check:**
- Every `unsafe` block in the codebase -- is the safety invariant documented and actually upheld?
- Raw pointer arithmetic: does it respect allocation bounds?
- `std::mem::transmute` usage -- are source and target types actually compatible in layout?
- `slice::from_raw_parts` -- is the length validated? Does the pointer actually point to valid, initialized memory of the correct type?
- `std::ptr::read` / `std::ptr::write` on unaligned or uninitialized memory
- Memory-mapped I/O (`mmap`) used for account storage (Solana's `AppendVec`) -- can a crafted snapshot produce a mapping that causes out-of-bounds reads?
- Manual `Drop` implementations that free resources -- can double-free occur if the value is also dropped automatically?
- `Pin` misuse -- is the pointer actually pinned for its entire required lifetime?

**Pattern:**
```rust
// BUG: no bounds check -- attacker-controlled offset can read/write arbitrary memory
unsafe fn read_account(mmap: &[u8], offset: usize) -> &AccountInfo {
    let ptr = mmap.as_ptr().add(offset); // offset from untrusted snapshot
    &*(ptr as *const AccountInfo)        // no alignment or bounds check
}

// BUG: transmute between incompatible types
unsafe fn parse_header(data: &[u8; 64]) -> MessageHeader {
    std::mem::transmute(*data) // assumes MessageHeader is exactly 64 bytes
                                // and has no padding/alignment requirements
}

// BUG: slice::from_raw_parts with unchecked length
unsafe fn decode_entries(ptr: *const Entry, count: u64) -> &[Entry] {
    // count comes from network message -- attacker can set to u64::MAX
    std::slice::from_raw_parts(ptr, count as usize)
}
```

**Grep for:** `unsafe`, `as *const`, `as *mut`, `transmute`, `from_raw_parts`, `ptr::read`, `ptr::write`, `ptr::copy`, `.as_ptr()`, `MaybeUninit`, `Pin::new_unchecked`

---

## RUST-002: Panic/Unwrap on Untrusted Input

**Impact:** Node crash, network-wide denial of service if triggerable by any peer (High)
**Severity:** High
**Frequency:** Very common -- especially in early-stage or rapidly-developed chains

In Rust, `.unwrap()`, `.expect()`, array indexing (`data[i]`), and explicit `panic!()` all abort the current thread. In a blockchain node, if any of these are reachable from network input (P2P messages, RPC requests, transaction data, gossip), a malicious actor can crash validators.

**What to check:**
- `.unwrap()` and `.expect()` on any `Result` or `Option` derived from external input
- Direct array/slice indexing (`data[i]`) where `i` comes from untrusted data -- use `.get(i)` instead
- `panic!()` or `unreachable!()` in code paths reachable from network handlers
- Integer casts with `as` that can truncate or sign-extend unexpectedly (e.g., `u64 as usize` on 32-bit)
- String parsing with `.parse::<T>().unwrap()` on user-supplied strings
- Solana: can a crafted transaction cause the runtime to panic before deducting fees? (free crash attack)
- NEAR: can a crafted chunk cause chunk validation to panic and halt the node?

**Pattern:**
```rust
// BUG: unwrap on network data -- peer can crash this node
fn handle_message(data: &[u8]) {
    let msg: NetworkMessage = bincode::deserialize(data).unwrap(); // CRASH
    let sender = msg.header.sender_id.unwrap(); // CRASH if None
    let value = msg.payload[msg.offset]; // CRASH if offset >= payload.len()
}

// BUG: RPC handler panics on bad input
fn rpc_get_block(params: &JsonValue) -> Result<Block, RpcError> {
    let slot: u64 = params["slot"].as_u64().unwrap(); // panics if "slot" missing
    let block = self.blockstore.get_block(slot).unwrap(); // panics if slot not found
    Ok(block)
}

// BUG: integer truncation on 32-bit targets
fn allocate_buffer(size: u64) -> Vec<u8> {
    vec![0u8; size as usize] // on 32-bit: 5GB becomes small number -> later OOB
}
```

**Grep for:** `.unwrap()`, `.expect(`, `panic!`, `unreachable!`, `todo!`, `unimplemented!`, `\[.*\]` indexing in network/rpc/transaction handlers, `as usize`, `as u32`, `as i32`

---

## RUST-003: Integer Overflow in Release Mode

**Impact:** Accounting errors, inflation bugs, consensus divergence (Critical)
**Severity:** Critical
**Frequency:** Common -- Rust's release mode silently wraps on overflow

In debug builds, Rust panics on integer overflow. In release builds (how all validators run in production), integer overflow wraps silently via two's complement. This means `u64::MAX + 1 == 0` and `0u64 - 1 == u64::MAX` in production.

**What to check:**
- All arithmetic on token amounts, balances, fees, rewards, stake calculations
- Multiplication before division (can intermediate product overflow)
- Subtraction that could underflow (balance - amount where amount > balance)
- Addition of user-controlled values to accumulators
- Slot/epoch/height arithmetic near u64::MAX
- Solana: lamport arithmetic in native programs
- NEAR: yoctoNEAR (10^24 per NEAR) arithmetic -- multiplications overflow easily
- Aleo: credit arithmetic in snarkVM
- Stellar: stroop arithmetic (10^7 per XLM)

**Pattern:**
```rust
// BUG: wrapping overflow in release mode
fn calculate_reward(stake: u64, rate: u64, epochs: u64) -> u64 {
    stake * rate * epochs / 1_000_000 // if stake * rate * epochs > u64::MAX, wraps to small number
}

// BUG: underflow wraps to u64::MAX in release
fn transfer(from: &mut u64, to: &mut u64, amount: u64) {
    *from -= amount; // if amount > *from, wraps to ~u64::MAX -- infinite money
    *to += amount;
}

// BUG: checked in debug, wraps in release
fn total_supply(accounts: &[Account]) -> u64 {
    accounts.iter().map(|a| a.balance).sum() // .sum() uses Add which wraps in release
}
```

**Safe alternatives:**
```rust
// Use checked arithmetic
let reward = stake.checked_mul(rate)
    .and_then(|v| v.checked_mul(epochs))
    .and_then(|v| v.checked_div(1_000_000))
    .ok_or(OverflowError)?;

// Or use saturating arithmetic where appropriate
let new_balance = balance.saturating_sub(amount);
```

**Grep for:** `+`, `-`, `*`, `/` on u64/u128/i64 (focus on financial calculations), `.sum()`, `.product()`, `wrapping_add`, `wrapping_sub`, `wrapping_mul`, absence of `checked_add`, `checked_sub`, `checked_mul`, `saturating_add`, `saturating_sub`

---

## RUST-004: Serialization/Deserialization Bugs

**Impact:** Node crash, memory exhaustion, state corruption, consensus split (High to Critical)
**Severity:** High
**Frequency:** Common -- serialization is the primary interface between untrusted data and node logic

Rust blockchain nodes use borsh (NEAR, Solana), bincode (Solana), serde_json (RPC), and custom formats. Malformed serialized data from peers, snapshots, or transactions can cause crashes, unbounded allocations, or logic bugs.

**What to check:**
- Does deserialization limit allocation size? A crafted `Vec<T>` length prefix can cause multi-GB allocation -> OOM kill
- Are `enum` discriminants validated? An invalid discriminant in borsh causes panic
- Does the deserializer consume all bytes? Trailing bytes may indicate a confused parser or version mismatch
- Can different serialization of the same logical value produce different hashes? (non-canonical encoding -> consensus split)
- Are there forward/backward compatibility issues between node versions?
- Solana: bincode deserialization of transaction data -- max size checks?
- NEAR: borsh deserialization of actions, state, and receipts
- Aleo: custom serialization of proofs and records

**Pattern:**
```rust
// BUG: unbounded Vec allocation from network data
#[derive(BorshDeserialize)]
struct ChunkBody {
    transactions: Vec<Transaction>, // borsh reads length prefix then allocates
                                     // attacker sends length = 2^32 -> OOM
}

// BUG: non-canonical encoding accepted
fn verify_state_root(data: &[u8]) -> bool {
    let state: State = borsh::from_slice(data).unwrap();
    let reencoded = borsh::to_vec(&state).unwrap();
    // data != reencoded if borsh accepts non-canonical encoding
    // but hash was computed over `data`, not `reencoded`
    hash(data) == expected_hash
}

// BUG: bincode default config has no size limit
fn parse_message(data: &[u8]) -> Result<Message, Error> {
    bincode::deserialize(data) // default config: max_size = unlimited
}
```

**Safe alternative:**
```rust
// bincode with size limit
let config = bincode::config::standard()
    .with_limit::<MAX_MESSAGE_SIZE>();
let msg: Message = bincode::decode_from_slice(data, config)?.0;
```

**Grep for:** `BorshDeserialize`, `bincode::deserialize`, `serde_json::from_`, `from_slice`, `from_reader`, `Deserialize`, `#[derive(`, check for max size limits on deserialized containers

---

## RUST-005: Concurrency Bugs

**Impact:** Data corruption, deadlocks causing node hang, consensus divergence (High to Critical)
**Severity:** High
**Frequency:** Moderate -- Rust prevents data races at compile time but not logical races or deadlocks

Rust's ownership model prevents data races on `&mut T`, but `Arc<Mutex<T>>`, `RwLock`, `AtomicU64`, and channel-based patterns can still have logical races, deadlocks, and TOCTOU bugs.

**What to check:**
- Lock ordering: are multiple mutexes always acquired in the same order? Different ordering -> deadlock
- `RwLock` starvation: can a flood of readers starve writers? (or vice versa, depending on implementation)
- `Arc<Mutex<T>>` held across `.await` points -- this blocks the async runtime thread
- `Condvar` without proper predicate check (spurious wakeups)
- Atomic operations: is the memory ordering (`Relaxed`, `Acquire`, `Release`, `SeqCst`) correct?
- TOCTOU bugs: check-then-act on shared state without holding the lock for both
- Solana: banking stage parallelism -- can two threads process conflicting transactions simultaneously?
- NEAR: chunk production vs chunk processing races

**Pattern:**
```rust
// BUG: deadlock -- locks acquired in different order
fn process_a(state: &AppState) {
    let _accounts = state.accounts.lock().unwrap();
    let _ledger = state.ledger.lock().unwrap(); // order: accounts -> ledger
}
fn process_b(state: &AppState) {
    let _ledger = state.ledger.lock().unwrap();
    let _accounts = state.accounts.lock().unwrap(); // order: ledger -> accounts -- DEADLOCK
}

// BUG: Mutex held across await -- blocks entire tokio worker thread
async fn update_state(state: Arc<Mutex<State>>) {
    let mut guard = state.lock().unwrap();
    let result = fetch_from_network().await; // holding lock across await!
    guard.apply(result);
}

// BUG: TOCTOU -- balance can change between check and update
fn safe_transfer(accounts: &Arc<Mutex<HashMap<Pubkey, u64>>>, from: Pubkey, amount: u64) {
    let balance = accounts.lock().unwrap().get(&from).copied().unwrap_or(0);
    if balance >= amount { // check
        // another thread modifies balance here!
        accounts.lock().unwrap().entry(from).and_modify(|b| *b -= amount); // act
    }
}
```

**Grep for:** `Mutex::new`, `RwLock::new`, `Arc::new`, `.lock()`, `.read()`, `.write()`, `Atomic`, `Condvar`, `crossbeam`, `tokio::sync::Mutex`, `.await` near `.lock()`

---

## RUST-006: Solana-Specific Vulnerabilities

**Impact:** Fund theft, privilege escalation, program logic bypass (Critical)
**Severity:** Critical
**Frequency:** Very common in Solana programs (on-chain) and validator code (off-chain)

Solana's programming model has unique attack surfaces: account model, CPIs, PDAs, sysvars, and the BPF/SBF runtime.

**What to check:**

### Missing Signer Checks
- Does the program verify `account.is_signer` for accounts that authorize an action?
- Can an attacker pass any account as the "authority" if signer is not checked?

### Missing Owner Checks
- Does the program verify `account.owner == expected_program_id`?
- Can an attacker create a fake account with the same data layout but different owner?

### PDA Collisions and Validation
- Are PDA seeds unique enough to prevent collision across different logical entities?
- Is `bump` validated (canonical bump vs arbitrary bump)?
- Can different seed combinations produce the same PDA?

### CPI Privilege Escalation
- When program A invokes program B via CPI, does program B properly validate the calling program?
- Can a malicious program invoke a CPI with accounts it shouldn't be able to sign for?
- Are there re-entrancy risks through CPI chains? (A -> B -> A)

### Account Data Validation
- Is account data length checked before deserialization?
- Are discriminators checked to prevent type confusion between different account types?
- Is the account marked as writable only when it should be?

**Pattern:**
```rust
// BUG: missing signer check -- anyone can drain the vault
fn withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let vault = &accounts[0];
    let authority = &accounts[1]; // NOT checked for is_signer!
    let destination = &accounts[2];

    // should have: if !authority.is_signer { return Err(ProgramError::MissingRequiredSignature); }

    **vault.try_borrow_mut_lamports()? -= amount;
    **destination.try_borrow_mut_lamports()? += amount;
    Ok(())
}

// BUG: missing owner check -- attacker provides fake account
fn read_config(config_account: &AccountInfo) -> Result<Config, ProgramError> {
    // should check: config_account.owner == program_id
    let config: Config = Config::try_from_slice(&config_account.data.borrow())?;
    Ok(config)
}

// BUG: PDA with insufficient seeds -- collision between users
fn derive_user_vault(program_id: &Pubkey, user: &Pubkey) -> Pubkey {
    // Missing a unique seed component -- different program logic paths
    // might derive the same PDA
    Pubkey::find_program_address(&[b"vault", user.as_ref()], program_id).0
}

// BUG: CPI to arbitrary program -- attacker substitutes token program
fn transfer_tokens(accounts: &[AccountInfo]) -> ProgramResult {
    let token_program = &accounts[3];
    // should check: token_program.key == &spl_token::id()
    invoke(
        &spl_token::instruction::transfer(
            token_program.key,
            source.key, destination.key, authority.key,
            &[], amount,
        )?,
        &[source.clone(), destination.clone(), authority.clone(), token_program.clone()],
    )
}
```

**Grep for:** `is_signer`, `owner`, `find_program_address`, `create_program_address`, `invoke`, `invoke_signed`, `CpiContext`, `AccountInfo`, `try_borrow_mut_lamports`, `#[account(`, `Signer`, `has_one`, `constraint`

---

## RUST-007: NEAR-Specific Vulnerabilities

**Impact:** Fund theft, storage exhaustion, stuck contracts (High to Critical)
**Severity:** High to Critical
**Frequency:** Common in NEAR smart contracts and runtime

NEAR's sharded architecture, storage staking model, async cross-contract calls, and gas model introduce unique vulnerability classes.

**What to check:**

### Storage Staking Manipulation
- NEAR requires contracts to stake NEAR proportional to their storage use
- Can an attacker force a contract to use excessive storage, locking up its NEAR?
- Can storage be freed to release staked NEAR in ways the contract didn't intend?
- Does the contract account for storage deposit/refund correctly in every code path?

### Cross-Contract Call Promise Resolution Bugs
- NEAR uses promises for async cross-contract calls -- the callback may succeed even if the promise failed
- Does the callback check `env::promise_result(0)` for `PromiseResult::Failed`?
- Can an attacker cause the called contract to fail, then exploit the caller's callback assuming success?
- Are token transfers refunded if the callback indicates failure?

### Gas Prepaid Overflow
- Gas is prepaid in NEAR -- contracts attach gas to cross-contract calls
- Can a contract be tricked into attaching more gas than intended, exhausting the transaction's gas?
- Can gas calculations overflow, resulting in near-zero gas being attached?
- Is there a minimum gas reserve kept for the callback?

### Shard-Related Issues
- Can state be manipulated in one shard to affect processing in another shard?
- Are cross-shard receipts validated properly?
- Can delayed receipts cause unexpected behavior?

**Pattern:**
```rust
// BUG: callback doesn't check if promise succeeded -- attacker gets tokens even if transfer failed
#[private]
pub fn on_transfer_complete(&mut self, sender: AccountId, amount: U128) {
    // Missing: match env::promise_result(0) { PromiseResult::Successful(_) => ..., _ => refund }
    self.balances.insert(&sender, &(self.balances.get(&sender).unwrap_or(0) - amount.0));
    // balance decremented even if the actual transfer failed!
}

// BUG: storage staking -- attacker bloats contract storage
pub fn store_data(&mut self, key: String, value: String) {
    // no limit on key/value size, no storage deposit required
    self.data.insert(&key, &value); // attacker stores huge data, contract's NEAR gets locked
}

// BUG: gas overflow -- prepaid gas for CPI can wrap
pub fn multi_call(&self, targets: Vec<AccountId>) {
    let gas_per_call = env::prepaid_gas() / targets.len() as u64; // if targets is empty -> div by zero
    // if targets.len() is very large, gas_per_call rounds to 0 -> calls fail silently
    for target in targets {
        Promise::new(target).function_call("action".into(), vec![], 0, gas_per_call);
    }
}
```

**Grep for:** `env::promise_result`, `Promise::new`, `promise_then`, `function_call`, `env::storage_write`, `env::storage_read`, `env::prepaid_gas`, `env::used_gas`, `#[callback]`, `#[private]`, `near_bindgen`, `BorshSerialize`, `BorshDeserialize`, `storage_deposit`, `storage_balance_of`

---

## RUST-008: Memory Safety in FFI Boundaries

**Impact:** Memory corruption, remote code execution, node compromise (Critical)
**Severity:** Critical
**Frequency:** Common in Firedancer, Stellar (C++ core), and any chain using C libraries for crypto

When Rust calls C/C++ code (or vice versa), all of Rust's safety guarantees disappear. FFI boundaries are the most dangerous code in a Rust blockchain node.

**What to check:**
- Is every C function call wrapped in `unsafe` with documented safety invariants?
- Are buffer sizes passed correctly across the FFI boundary? (C doesn't have Rust slices)
- Are null pointers checked before dereferencing on the C side?
- Are strings properly null-terminated when passing to C? (`CString` vs `&str`)
- Is memory allocated on one side and freed on the same side? (mixing allocators -> corruption)
- Are C callbacks safe? Can they be called after the Rust side has dropped the data?
- Firedancer-specific: Rust<->C boundary for transaction processing, signature verification, PoH
- Stellar: Rust Soroban VM calling into C++ stellar-core infrastructure
- Aleo: FFI to C libraries for GPU-accelerated proof generation

**Pattern:**
```rust
// BUG: buffer size mismatch across FFI
extern "C" {
    fn c_hash_block(data: *const u8, len: u32, output: *mut u8);
}

fn hash_block(data: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    unsafe {
        // BUG: data.len() is usize (64-bit) but len is u32 -- truncation for large data
        c_hash_block(data.as_ptr(), data.len() as u32, output.as_mut_ptr());
    }
    output
}

// BUG: use-after-free via FFI callback
extern "C" {
    fn register_callback(cb: extern "C" fn(*const State));
}

fn setup(state: Box<State>) {
    let ptr = Box::into_raw(state);
    unsafe {
        register_callback(my_callback); // callback uses ptr
    }
    // BUG: if state is dropped elsewhere, callback dereferences dangling pointer
}

// BUG: string not null-terminated
fn call_c_log(msg: &str) {
    unsafe {
        // &str is NOT null-terminated -- C function reads past end of string
        c_log(msg.as_ptr() as *const libc::c_char);
    }
    // Fix: use CString::new(msg).unwrap().as_ptr()
}
```

**Grep for:** `extern "C"`, `#[no_mangle]`, `#[link(`, `libc::`, `std::ffi::CString`, `CStr`, `*const`, `*mut`, `Box::into_raw`, `Box::from_raw`, `ManuallyDrop`, `as u32` near FFI calls, `bindgen`, `cbindgen`

---

## RUST-009: Cryptographic Implementation Bugs

**Impact:** Signature forgery, key leakage, consensus bypass, privacy break (Critical)
**Severity:** Critical
**Frequency:** Moderate -- crypto crates have had real vulnerabilities (ed25519-dalek double-public-key, curve25519 timing)

Rust blockchain nodes rely heavily on crypto crates. Bugs in these crates or their usage can break the entire security model.

**What to check:**

### Signature Verification
- Is the signature verified against the correct message? (hash of what, exactly?)
- Is the public key validated (on the curve, not identity point)?
- ed25519-dalek: is batch verification used? (batch verification has different acceptance criteria than single verification -- can cause consensus split if some validators batch and others don't)
- Are malleable signatures accepted? (same message, different valid signature -> replay or confusion)
- ed25519-dalek v1.x had a vulnerability (RUSTSEC-2022-0093) in `PublicKey::verify_strict` -- check version

### Key Management
- Are private keys zeroized after use? (`zeroize` crate)
- Are keys stored in memory that can be swapped to disk?
- Is `rand::thread_rng()` used or a deterministic/weak RNG?

### Hash Function Usage
- Is the hash function collision-resistant for the use case?
- Are domain separators used to prevent cross-protocol attacks?
- Is hash truncation safe for the security level needed?

### Zero-Knowledge Proofs (Aleo)
- Are proof verification inputs properly validated?
- Can a malicious prover craft a proof that verifies but proves a false statement?
- Are trusted setup parameters validated?

**Pattern:**
```rust
// BUG: signature verified against wrong message
fn verify_transaction(tx: &Transaction) -> bool {
    let sig = &tx.signature;
    let pubkey = &tx.sender;
    // BUG: verifying signature over serialized tx which INCLUDES the signature field
    // should verify over tx data WITHOUT the signature
    pubkey.verify(&bincode::serialize(tx).unwrap(), sig).is_ok()
}

// BUG: private key not zeroized
fn sign_message(seed: &[u8; 32], msg: &[u8]) -> Signature {
    let keypair = Keypair::from_seed(seed);
    let sig = keypair.sign(msg);
    sig
    // keypair dropped here but private key material remains in memory
    // Fix: use zeroize::Zeroizing<Keypair> or manual zeroization
}

// BUG: weak RNG for key generation
fn generate_keypair() -> Keypair {
    let mut rng = rand::rngs::SmallRng::from_entropy(); // SmallRng is NOT cryptographically secure
    Keypair::generate(&mut rng)
    // Fix: use rand::rngs::OsRng or rand::thread_rng()
}

// BUG: missing domain separator -- same hash used in two contexts
fn compute_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    // no domain separator -- if this hash is used for both
    // "account state" and "transaction id", cross-protocol attacks possible
    hasher.update(data);
    hasher.finalize().into()
}
```

**Grep for:** `ed25519_dalek`, `curve25519`, `x25519`, `Keypair`, `SecretKey`, `verify`, `sign`, `Sha256`, `Sha512`, `Blake2`, `blake3`, `Hasher`, `Digest`, `zeroize`, `Zeroizing`, `OsRng`, `SmallRng`, `StdRng`, `thread_rng`, `from_seed`, `bellman`, `ark_`, `snark`, `proof`, `groth16`

---

## RUST-010: Async Runtime Bugs

**Impact:** Node hang, memory exhaustion, degraded performance, missed blocks (High)
**Severity:** High
**Frequency:** Common -- async Rust has subtle pitfalls that are easy to introduce

All target chains use async runtimes (tokio, async-std, or custom) for networking, RPC, and internal task management. Async runtime bugs can cause silent performance degradation or complete node failure.

**What to check:**

### Task Starvation
- Are CPU-intensive operations running on the async runtime's thread pool? (should use `spawn_blocking`)
- Is a single task monopolizing a runtime thread with long synchronous computation?
- Solana: PoH generation is CPU-intensive -- is it isolated from async networking?

### Unbounded Channel Growth
- Are `mpsc::unbounded_channel()` or `crossbeam::unbounded()` used?
- Can a fast producer overwhelm a slow consumer -> unbounded memory growth -> OOM?
- Is there backpressure from consumers to producers?

### Future Cancellation Safety
- When a future is dropped (e.g., timeout, select!), is the partial work cleaned up?
- Are resources (locks, file handles, network connections) leaked on cancellation?
- Does `tokio::select!` cancel the losing branch -- is that branch cancellation-safe?

### Runtime Misconfiguration
- Is the tokio runtime configured with enough worker threads?
- Are blocking operations using `block_on` inside async context? (-> deadlock on single-threaded runtime)
- Is there a risk of nested runtime creation? (`block_on` inside `block_on` -> panic)

**Pattern:**
```rust
// BUG: CPU-heavy work on async runtime -- starves other tasks
async fn process_block(block: Block) {
    // This runs on a tokio worker thread -- blocks all other tasks on this thread
    let result = verify_all_signatures(&block); // CPU-intensive, should be spawn_blocking
    broadcast(result).await;
}

// BUG: unbounded channel -- OOM under load
fn start_gossip(network: Arc<Network>) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    // producers send gossip messages faster than consumer processes them
    // during network spam, channel grows without bound
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            process_gossip(msg).await;
        }
    });
}

// BUG: resource leak on cancellation via select!
async fn fetch_with_timeout(peer: Peer) -> Result<Data, Error> {
    tokio::select! {
        result = peer.fetch_data() => result, // if timeout wins, fetch_data is cancelled
        _ = tokio::time::sleep(Duration::from_secs(5)) => {
            Err(Error::Timeout)
            // BUG: peer.fetch_data() may have partially written to a shared buffer
            // or opened a connection that is now leaked
        }
    }
}

// BUG: block_on inside async context -> panic or deadlock
async fn handle_request(req: Request) -> Response {
    // WRONG: calling block_on inside async context
    let result = tokio::runtime::Handle::current().block_on(async {
        some_async_operation().await
    }); // panics: "Cannot block the current thread from within a runtime"
    Response::new(result)
}
```

**Grep for:** `tokio::spawn`, `spawn_blocking`, `#[tokio::main]`, `Runtime::new`, `block_on`, `unbounded_channel`, `mpsc::channel`, `select!`, `tokio::select!`, `tokio::time::timeout`, `async fn`, `.await`, `Future`, `Pin<Box<dyn Future`, `async-std`, `smol`

---

## Scan Priority

### Phase 1 -- Immediate (highest risk, most exploitable)
1. **RUST-006** (Solana-specific) -- Missing signer/owner checks are the #1 exploited vulnerability class in Solana
2. **RUST-001** (Unsafe blocks) -- Any `unsafe` in network-facing code is critical
3. **RUST-003** (Integer overflow) -- Silent in release mode, directly causes fund theft
4. **RUST-008** (FFI boundaries) -- Especially critical for Firedancer and any chain calling C crypto libs
5. **RUST-009** (Crypto bugs) -- Check crate versions against RUSTSEC advisories immediately

### Phase 2 -- High Priority
6. **RUST-002** (Panic/unwrap) -- Grep all `.unwrap()` in network and transaction processing paths
7. **RUST-004** (Serialization) -- Unbounded deserialization from any external source
8. **RUST-007** (NEAR-specific) -- Promise resolution and storage staking issues

### Phase 3 -- Systematic Review
9. **RUST-005** (Concurrency) -- Requires understanding lock ordering and data flow
10. **RUST-010** (Async runtime) -- Performance and availability issues, harder to exploit for fund theft

### Version-Specific Checks
Before starting any audit, check `Cargo.toml` and `Cargo.lock` for:
- `ed25519-dalek` < 2.0 (RUSTSEC-2022-0093: strict verification bypass)
- `borsh` version compatibility (breaking changes between 0.x and 1.x)
- `solana-program` version (known bugs per version)
- `near-sdk` version
- `tokio` < 1.0 (old API, different cancellation semantics)
- Run `cargo audit` output through the agent for known vulnerabilities in all dependencies
