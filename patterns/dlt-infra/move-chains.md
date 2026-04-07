# Move-Based Chains Vulnerability Patterns (Sui, Aptos)

## Architecture Context

### Sui
- **Object-centric model**: State is organized around objects (owned, shared, immutable) rather than accounts.
- **Programmable Transaction Blocks (PTBs)**: Multiple operations composed atomically in a single transaction.
- **Narwhal/Bullshark consensus**: DAG-based mempool (Narwhal) with Bullshark ordering for shared-object transactions. Owned-object transactions bypass consensus via fast path.
- **Move on Sui**: Extended Move with object model, `TxContext`, and dynamic fields.

### Aptos
- **Account/resource model**: Closer to original Diem Move. State lives under account addresses as resources.
- **Block-STM parallel execution**: Optimistic concurrent execution with conflict detection and re-execution.
- **Object model (v2)**: Layered on top of the resource model for NFTs and composable assets.
- **Resource accounts**: Programmatically created accounts used for autonomous contract deployment.

---

## Scan Priority

| Pattern  | Severity | Scan Priority |
|----------|----------|---------------|
| MOVE-001 | Critical | P0 - Always scan |
| MOVE-002 | High     | P0 - Always scan |
| MOVE-003 | Critical | P0 - Always scan |
| MOVE-004 | Critical | P0 - Always scan |
| MOVE-005 | High     | P1 - Scan if Sui PTBs detected |
| MOVE-006 | High     | P1 - Scan if Aptos target |
| MOVE-007 | Medium   | P2 - Infrastructure review |
| MOVE-008 | Critical | P0 - Always scan |

---

## MOVE-001: Object Ownership Confusion (Sui)

**Severity**: Critical
**Chains**: Sui
**Category**: Access Control / State Management

### Description

Sui's object model distinguishes between owned objects (single-writer), shared objects (consensus-required), and immutable objects. Vulnerabilities arise when:
- A shared object is treated as if it has single-owner semantics, enabling front-running or race conditions.
- Owned objects are incorrectly wrapped/unwrapped, breaking ownership invariants.
- Dynamic fields are used to hide or obscure object access controls.

### Vulnerable Pattern

```move
// BAD: Shared pool with no access control on withdrawal
public entry fun withdraw(pool: &mut SharedPool, amount: u64, ctx: &mut TxContext) {
    let coin = coin::take(&mut pool.balance, amount, ctx);
    transfer::public_transfer(coin, tx_context::sender(ctx));
    // Anyone can call this on the shared object - no ownership check
}

// BAD: Wrapping an object to bypass transfer restrictions
public fun wrap_to_bypass(nft: RestrictedNFT): Wrapper<RestrictedNFT> {
    Wrapper { inner: nft }
    // If Wrapper has `store` but RestrictedNFT should not be freely transferable,
    // wrapping circumvents the restriction
}
```

### Secure Pattern

```move
// GOOD: Shared pool with capability-gated withdrawal
public entry fun withdraw(
    pool: &mut SharedPool,
    admin_cap: &AdminCap,
    amount: u64,
    ctx: &mut TxContext
) {
    assert!(admin_cap.pool_id == object::id(pool), EUnauthorized);
    let coin = coin::take(&mut pool.balance, amount, ctx);
    transfer::public_transfer(coin, tx_context::sender(ctx));
}
```

### What to Scan For

- `shared_object` or `share_object` calls on objects that should have restricted access.
- `dynamic_field::add` / `dynamic_field::remove` without proper authorization checks.
- `transfer::public_transfer` used where `transfer::transfer` (with `store` restriction) is appropriate.
- Object wrapping that escalates abilities (e.g., adding `store` to a wrapped type).

---

## MOVE-002: Ability Constraint Violations

**Severity**: High
**Chains**: Sui, Aptos
**Category**: Type System / Access Control

### Description

Move's linear type system uses four abilities: `copy`, `drop`, `key`, `store`. Missing or incorrect ability constraints can allow:
- Unauthorized copying of value types (e.g., duplicating tokens).
- Dropping resources that should be consumed or returned.
- Storing objects in global storage when they should remain ephemeral.
- Creating objects without `key` that bypass on-chain tracking.

### Vulnerable Pattern

```move
// BAD: Ticket with `drop` allows it to be silently discarded
struct EventTicket has key, store, drop {
    id: UID,
    event_id: u64,
    used: bool,
}

// User can obtain a ticket and never use it, silently dropping it
// If the protocol expects tickets to be explicitly burned/returned, this breaks accounting

// BAD: Receipt with `copy` allows double-claiming
struct WithdrawalReceipt has copy, drop {
    amount: u64,
    recipient: address,
}
```

### Secure Pattern

```move
// GOOD: Ticket without `drop` forces explicit handling
struct EventTicket has key, store {
    id: UID,
    event_id: u64,
    used: bool,
}

// Must be explicitly burned via a dedicated function
public fun use_ticket(ticket: EventTicket) {
    let EventTicket { id, event_id: _, used: _ } = ticket;
    object::delete(id);
}

// GOOD: Hot potato pattern - no abilities forces immediate use
struct FlashLoanReceipt {
    amount: u64,
    fee: u64,
}
// Cannot be stored, copied, dropped, or placed in global storage
// Must be consumed in the same transaction via repay()
```

### What to Scan For

- Structs with `copy` that represent unique assets or entitlements.
- Structs with `drop` that represent obligations or receipts.
- Missing `key` on types that need on-chain identity tracking.
- Generic functions that accept `T: store` when they should require additional constraints.

---

## MOVE-003: Module Upgrade Vulnerabilities

**Severity**: Critical
**Chains**: Sui, Aptos
**Category**: Governance / Lifecycle

### Description

Move supports module upgrades under specific policies. Vulnerabilities include:
- Upgrade policy set too permissively (e.g., `compatible` when `immutable` is intended).
- Friend function declarations exposing internal logic to modules that can be upgraded separately.
- On Aptos, upgrading a module to change resource layouts without proper migration.
- On Sui, `UpgradeCap` held by an EOA instead of a governance contract.

### Vulnerable Pattern

```move
// BAD (Sui): UpgradeCap transferred to a single EOA
fun init(ctx: &mut TxContext) {
    // UpgradeCap sent to deployer - single point of failure
    transfer::transfer(upgrade_cap, tx_context::sender(ctx));
}

// BAD: Friend declaration on a module that can be independently upgraded
module protocol::core {
    friend protocol::router;
    // If protocol::router is upgraded maliciously, it can call
    // friend-only functions in protocol::core
    public(friend) fun mint_internal(amount: u64): Coin<TOKEN> { ... }
}
```

### Secure Pattern

```move
// GOOD (Sui): UpgradeCap held by a multisig or governance object
fun init(ctx: &mut TxContext) {
    let upgrade_cap = ...;
    transfer::public_transfer(upgrade_cap, @governance_multisig);
}

// GOOD: Minimize friend declarations, use capability objects instead
module protocol::core {
    public fun mint_with_cap(cap: &MintCap, amount: u64): Coin<TOKEN> { ... }
}
```

### What to Scan For

- `UpgradeCap` or `UpgradePolicy` held by single addresses.
- `public(friend)` functions that perform privileged operations.
- Upgrade policy set to `compatible` on security-critical packages.
- Aptos: `move_to` on resource types whose layout changes across upgrades.

---

## MOVE-004: Coin/Token Accounting Bugs

**Severity**: Critical
**Chains**: Sui, Aptos
**Category**: Financial / Arithmetic

### Description

Move's `Coin<T>` and `Balance<T>` types require explicit splitting and merging. Accounting bugs arise from:
- Incorrect split/merge arithmetic leaving dust amounts unaccounted for.
- Failing to return change to the user after a partial spend.
- Zero-value coin creation used to bypass minimum amount checks.
- `Balance<T>` manipulation through `balance::join` / `balance::split` without proper assertions.

### Vulnerable Pattern

```move
// BAD: Dust left in temporary balance, permanently locked
public fun swap(input: Coin<SUI>, pool: &mut Pool, ctx: &mut TxContext): Coin<USDC> {
    let input_amount = coin::value(&input);
    let fee = input_amount / 100;
    let swap_amount = input_amount - fee;

    // Fee coins are split but never collected
    let fee_coin = coin::split(&mut input, fee, ctx);
    // fee_coin is dropped here if EventTicket pattern not enforced
    // or if the function doesn't transfer it somewhere

    let output = do_swap(pool, input, swap_amount);
    output
}

// BAD: Zero-value coin bypasses minimum check
public fun deposit(pool: &mut Pool, coin: Coin<SUI>) {
    // Missing: assert!(coin::value(&coin) > 0, EZeroDeposit);
    balance::join(&mut pool.balance, coin::into_balance(coin));
}
```

### Secure Pattern

```move
// GOOD: All coins are accounted for
public fun swap(
    input: Coin<SUI>,
    pool: &mut Pool,
    ctx: &mut TxContext
): Coin<USDC> {
    let input_amount = coin::value(&input);
    assert!(input_amount > 0, EZeroInput);

    let fee = input_amount / 100;
    let fee_coin = coin::split(&mut input, fee, ctx);
    transfer::public_transfer(fee_coin, pool.fee_recipient);

    let output = do_swap(pool, input);
    output
}
```

### What to Scan For

- `coin::split` or `balance::split` without corresponding `transfer` or `balance::join` for both parts.
- Missing zero-value checks on coin inputs.
- Arithmetic on coin values without overflow/underflow consideration.
- Temporary `Balance<T>` variables that go out of scope without being joined or destroyed.

---

## MOVE-005: Transaction Block Composability (Sui PTB)

**Severity**: High
**Chains**: Sui
**Category**: Composability / Logic

### Description

Sui's Programmable Transaction Blocks allow multiple Move calls, splits, merges, and transfers in a single atomic transaction. Vulnerabilities arise when:
- Contracts assume they are called in isolation but are composed with other calls.
- State read in one PTB command is stale by the time a later command executes.
- Flash-loan-style attacks exploit atomicity to borrow, manipulate, and return within one PTB.
- Re-entrancy-like patterns emerge through PTB composition even without traditional callbacks.

### Vulnerable Pattern

```move
// BAD: Price oracle read + swap in separate PTB commands
// Command 1: read_price(oracle) -> price
// Command 2: swap(pool, coin, price)
// An attacker can insert a manipulate_oracle() command between them

// BAD: Assumes function is only called once per transaction
public fun claim_reward(user: &mut UserState, pool: &Pool, ctx: &mut TxContext) {
    let reward = calculate_reward(user, pool);
    // No flag set to prevent re-claim in same PTB
    let coin = coin::take(&mut pool.rewards, reward, ctx);
    transfer::public_transfer(coin, tx_context::sender(ctx));
}
```

### Secure Pattern

```move
// GOOD: Atomic read-and-use with hot potato receipt
public fun begin_swap(oracle: &Oracle, pool: &mut Pool): SwapReceipt {
    let price = oracle::read(oracle);
    SwapReceipt { price, pool_id: object::id(pool) }
}

public fun execute_swap(
    pool: &mut Pool,
    receipt: SwapReceipt,
    input: Coin<SUI>,
    ctx: &mut TxContext
): Coin<USDC> {
    let SwapReceipt { price, pool_id } = receipt;
    assert!(pool_id == object::id(pool), EMismatch);
    // price is locked from the begin_swap call
    do_swap_at_price(pool, input, price, ctx)
}
```

### What to Scan For

- Functions that read external state (oracles, pools) and act on it in separate steps.
- Missing re-entrancy guards or per-epoch/per-transaction claim limits.
- Functions returning mutable references that can be composed with other calls.
- Absence of hot-potato receipt patterns for multi-step operations.

---

## MOVE-006: Aptos-Specific Vulnerabilities

**Severity**: High
**Chains**: Aptos
**Category**: Platform-Specific

### Description

Aptos has unique features that introduce specific vulnerability classes:
- **Resource accounts**: Created via `account::create_resource_account`. The `SignerCapability` must be carefully guarded; if leaked, arbitrary transactions can be signed on behalf of the resource account.
- **Multisig transactions**: The `multisig_account` module can have edge cases around threshold changes, owner rotation, and transaction expiry.
- **Object model edge cases**: Aptos Objects can be transferred, but `LinearTransferRef` and `TransferRef` must be managed carefully.

### Vulnerable Pattern

```move
// BAD: SignerCapability stored in a struct anyone can access
struct ProtocolState has key {
    signer_cap: account::SignerCapability,
    // If any public function exposes a reference to this struct,
    // the signer_cap can be used to sign arbitrary transactions
}

public fun get_protocol_signer(state: &ProtocolState): signer {
    account::create_signer_with_capability(&state.signer_cap)
    // CRITICAL: Returns a signer that can do anything as the resource account
}

// BAD: Object TransferRef not properly guarded
struct TokenRefs has key {
    transfer_ref: object::TransferRef,
    // If publicly accessible, anyone can transfer the object
}
```

### Secure Pattern

```move
// GOOD: SignerCapability gated behind admin check
public fun execute_as_protocol(
    admin: &signer,
    state: &ProtocolState
): signer {
    assert!(signer::address_of(admin) == state.admin, ENotAdmin);
    account::create_signer_with_capability(&state.signer_cap)
}

// GOOD: TransferRef kept internal, only used through guarded functions
public fun transfer_token(
    owner: &signer,
    token_addr: address,
    to: address
) acquires TokenRefs {
    let refs = borrow_global<TokenRefs>(token_addr);
    assert!(object::is_owner(object::address_to_object<Token>(token_addr), signer::address_of(owner)), ENotOwner);
    object::transfer_with_ref(object::generate_linear_transfer_ref(&refs.transfer_ref), to);
}
```

### What to Scan For

- `SignerCapability` exposed through public or friend functions.
- `TransferRef`, `DeleteRef`, `MutatorRef` stored without access controls.
- Resource account creation without immediate `SignerCapability` lockdown.
- Multisig threshold set to 1 or owner set modifications without proper governance.

---

## MOVE-007: Sui Infrastructure Edge Cases

**Severity**: Medium
**Chains**: Sui
**Category**: Infrastructure / Consensus

### Description

Sui's consensus and execution model has infrastructure-level edge cases:
- **Object locking DoS**: An owned object used as input in a pending transaction becomes locked. An attacker who holds a shared reference can submit conflicting transactions to lock victim objects.
- **Consensus vs. fast path divergence**: Owned-object transactions skip consensus (fast path). If a protocol mixes owned and shared objects, timing assumptions can break.
- **Epoch boundary behavior**: Staking rewards, validator set changes, and object version increments at epoch boundaries can create transient inconsistencies.

### Vulnerable Pattern

```move
// BAD: Protocol requires owned object as input in time-sensitive operation
public entry fun bid_in_auction(
    auction: &mut SharedAuction,
    bidder_account: &mut OwnedBidderAccount, // Owned object - can be locked!
    amount: u64,
    ctx: &mut TxContext
) {
    // If bidder_account is locked by a pending equivocating transaction,
    // the bidder cannot participate in the auction
}
```

### Secure Pattern

```move
// GOOD: Use shared objects or coins directly to avoid locking
public entry fun bid_in_auction(
    auction: &mut SharedAuction,
    payment: Coin<SUI>, // Coins can be split from gas, harder to lock
    ctx: &mut TxContext
) {
    let bidder = tx_context::sender(ctx);
    // Use sender address for identification, coin for payment
    process_bid(auction, bidder, payment, ctx);
}
```

### What to Scan For

- Protocols requiring owned objects as inputs for time-sensitive operations (auctions, liquidations).
- Mixing owned and shared objects in the same entry function without understanding ordering guarantees.
- Epoch-dependent calculations (staking, rewards) without boundary checks.
- Assumptions about transaction ordering for owned-object transactions.

---

## MOVE-008: Type Confusion via Generics

**Severity**: Critical
**Chains**: Sui, Aptos
**Category**: Type Safety

### Description

Move's generic type system is powerful but can be exploited if protocols don't properly constrain type parameters. A common attack is passing `Coin<AttackerToken>` where `Coin<USDC>` is expected, when the function is generic over the coin type.

### Vulnerable Pattern

```move
// BAD: Generic swap function with no type validation
public fun add_liquidity<CoinA, CoinB>(
    pool: &mut Pool<CoinA, CoinB>,
    coin_a: Coin<CoinA>,
    coin_b: Coin<CoinB>,
    ctx: &mut TxContext
) {
    // If Pool<CoinA, CoinB> can be created by anyone with arbitrary types,
    // an attacker creates Pool<FakeUSDC, FakeETH> and adds worthless liquidity
}

// BAD: No type witness verification
public fun register_coin<T>(treasury_cap: TreasuryCap<T>, metadata: CoinMetadata<T>) {
    // Attacker registers a coin whose symbol/name matches a legitimate token
    // Protocol or UI may confuse it with the real token
}
```

### Secure Pattern

```move
// GOOD: Pool creation restricted with verified coin types
public fun create_pool<CoinA, CoinB>(
    admin_cap: &AdminCap,
    // Or use a type whitelist
    ctx: &mut TxContext
): Pool<CoinA, CoinB> {
    // Only admin can create pools, ensuring legitimate types
    Pool<CoinA, CoinB> { id: object::new(ctx), balance_a: balance::zero(), balance_b: balance::zero() }
}

// GOOD: Use one-time witness (OTW) pattern for type authentication
public fun register_coin<T: drop>(
    witness: T, // One-time witness - only the defining module can produce this
    ctx: &mut TxContext
): (TreasuryCap<T>, CoinMetadata<T>) {
    assert!(sui::types::is_one_time_witness(&witness), ENotOTW);
    coin::create_currency(witness, 6, b"REAL", b"Real Token", b"", option::none(), ctx)
}
```

### What to Scan For

- Generic functions accepting `Coin<T>` or `Balance<T>` without verifying `T` against a whitelist or registry.
- Pool/vault creation functions that are permissionless with unconstrained generics.
- Missing one-time witness (OTW) checks in coin/token registration.
- Type parameters used in `borrow_global<T>` (Aptos) without address validation.
- Functions where the type parameter is only used for `Coin<T>` operations and an attacker-controlled type could satisfy the constraints.
