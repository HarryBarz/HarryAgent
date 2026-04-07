# Substrate / Polkadot Vulnerability Patterns

Target chains: Astar, Hydration, Gear, Bifrost, Acala, Moonbeam, SORA

## Framework Architecture (for agent context)

```
Parachain / Standalone Chain
    |
Runtime (compiled to Wasm, executes on-chain)
    - Pallets (modular state transition logic, written with FRAME macros)
    - FRAME (Framework for Runtime Aggregation of Modularized Entities)
        - frame_system, frame_support, frame_executive
    - Runtime APIs (metadata, transaction pool, block builder, session keys)
    - Construct Runtime macro (wires pallets together, dispatches calls)
    |
Host Functions (interface between Wasm runtime and native node)
    - sp_io (storage, crypto, hashing, logging, offchain)
    - Allocator (Wasm linear memory management)
    |
Client / Node
    - Networking (libp2p: Kademlia DHT, Gossipsub, GRANDPA protocol)
    - Consensus (BABE/Aura for block production, GRANDPA for finality)
    - Transaction Pool (validation, priority, ordering)
    - RPC (JSON-RPC, WebSocket subscriptions)
    - Offchain Workers (HTTP requests, local storage, signing)
    |
Relay Chain (Polkadot/Kusama, for parachains)
    - Collator -> Relay Validator pipeline
    - XCM (Cross-Consensus Messaging)
    - HRMP / DMP / UMP channels
    - Parachain Validation Function (PVF)
```

Key: most parachains customize at the Pallet layer using FRAME. Bugs in FRAME and sp_io affect all chains. Bugs in custom pallets are chain-specific. XCM bugs affect all parachains that enable cross-chain messaging. EVM-compatible chains (Moonbeam, Astar) have an additional attack surface through the EVM pallet and Frontier layer.

---

## SUB-001: Pallet Weight Miscalculation

**Impact:** Denial of Service via block stuffing or resource exhaustion (High)
**Frequency:** Very common in custom pallets

Substrate uses a weight system instead of gas. Every extrinsic must declare its weight (a measure of computational and storage cost) before execution. If the declared weight is lower than the actual cost, an attacker can submit transactions that consume more resources than accounted for, stuffing blocks and degrading or halting the chain.

**What to check:**
- Does the `#[pallet::weight(...)]` annotation accurately reflect the worst-case execution cost?
- Are weights benchmarked with `frame_benchmarking` or are they hardcoded constants?
- Do benchmarks cover the worst-case input (maximum vector lengths, deepest iteration)?
- Are conditional branches (early returns vs. full execution) handled with proper weight refunds via `DispatchResultWithPostInfo`?
- Does the extrinsic perform any unbounded iteration (loop over user-controlled input without a cap)?
- Is `WeightInfo` actually wired into the pallet, or is the trait defined but the pallet still uses placeholder weights?
- For parachains: does the total block weight exceed the relay chain's proof-of-validity time limit?

**Pattern:**
```rust
// BUG: hardcoded weight does not reflect actual cost
// An attacker passes a vector with 10,000 entries but only pays for constant weight
#[pallet::call_index(0)]
#[pallet::weight(10_000)]
pub fn process_batch(
    origin: OriginFor<T>,
    items: Vec<ItemData>,
) -> DispatchResult {
    let who = ensure_signed(origin)?;
    for item in items.iter() {
        // O(n) storage writes -- actual cost scales linearly
        <ItemStore<T>>::insert(item.id, item.clone());
    }
    Ok(())
}
```

**Correct pattern:**
```rust
#[pallet::call_index(0)]
#[pallet::weight(T::WeightInfo::process_batch(items.len() as u32))]
pub fn process_batch(
    origin: OriginFor<T>,
    items: BoundedVec<ItemData, T::MaxBatchSize>,
) -> DispatchResultWithPostInfo {
    let who = ensure_signed(origin)?;
    let actual_count = items.len() as u32;
    for item in items.iter() {
        <ItemStore<T>>::insert(item.id, item.clone());
    }
    Ok(Some(T::WeightInfo::process_batch(actual_count)).into())
}
```

**Grep for:** `#[pallet::weight(`, `Weight::from_parts(0`, `Weight::zero()`, `10_000`, `100_000` (suspiciously round hardcoded weights), `fn process`, `Vec<` in extrinsic parameters (should be `BoundedVec`), `WeightInfo`

---

## SUB-002: Unsafe Arithmetic in Runtime

**Impact:** Fund theft, incorrect balances, economic exploits (Critical)
**Frequency:** Common -- Substrate runtimes compile to `no_std` and Rust's default overflow behavior in release mode is wrapping

In release builds (which is what on-chain Wasm uses), integer overflow and underflow silently wrap around. This is catastrophic for balance calculations, reward distributions, fee computations, and any financial math.

**What to check:**
- Are arithmetic operations using `checked_add`, `checked_sub`, `checked_mul`, `checked_div`, or `saturating_*` variants?
- Are there any bare `+`, `-`, `*`, `/` operators on integer types in pallet logic?
- Is `sp_arithmetic::PerThing` (Perbill, Permill, etc.) used correctly for percentage calculations?
- Are there any casts between integer types (`as u32`, `as u128`) that could truncate?
- Is division performed before multiplication (precision loss)?
- Are `Balance` types mixed with smaller integer types without proper conversion?

**Pattern:**
```rust
// BUG: overflow wraps in Wasm release builds
pub fn calculate_reward(
    total_stake: u128,
    user_stake: u128,
    reward_pool: u128,
) -> u128 {
    // If total_stake * reward_pool overflows u128, the result wraps to a small number
    // and user gets almost nothing -- or wraps to a huge number
    let user_reward = user_stake * reward_pool / total_stake;
    user_reward
}

// BUG: underflow wraps -- user ends up with near-max balance
let new_balance = account_balance - withdrawal_amount; // if withdrawal > balance, wraps to ~u128::MAX
```

**Correct pattern:**
```rust
let user_reward = reward_pool
    .checked_mul(user_stake)
    .ok_or(Error::<T>::ArithmeticOverflow)?
    .checked_div(total_stake)
    .ok_or(Error::<T>::DivisionByZero)?;

let new_balance = account_balance
    .checked_sub(withdrawal_amount)
    .ok_or(Error::<T>::InsufficientBalance)?;
```

**Grep for:** bare operators on numeric types (hard to grep, look for `+ `, `- `, `* `, `/ ` in pallet code), `as u32`, `as u64`, `as u128`, `as usize`, `.unwrap()` on arithmetic results, absence of `checked_`, `saturating_`, `ensure!`

---

## SUB-003: Storage Exhaustion

**Impact:** State bloat leading to chain degradation, economic DoS (High)
**Frequency:** Common in custom pallets

Substrate state is stored in a Merkle-Patricia trie. Every storage entry increases proof sizes and slows block production. If users can write unbounded data to chain state without paying proportional deposits, they can bloat the state at low cost.

**What to check:**
- Does the pallet require a storage deposit for each entry created? (Substrate's `Currency::reserve` or `frame_support::traits::tokens::fungible::hold`)
- Are `StorageMap` / `StorageDoubleMap` entries bounded? Can an attacker create millions of entries?
- Are `StorageValue<Vec<T>>` or `StorageValue<BTreeMap<K,V>>` used? These grow without limit.
- Is there a mechanism to remove old entries (expiry, garbage collection, user-initiated cleanup)?
- Are `BoundedVec`, `BoundedBTreeMap`, `BoundedBTreeSet` used instead of unbounded collections?
- For parachains: does state growth affect proof-of-validity (PoV) block size limits?

**Pattern:**
```rust
// BUG: anyone can add entries to this map with no deposit and no limit
#[pallet::storage]
pub type UserData<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, Vec<u8>>;

#[pallet::call_index(0)]
#[pallet::weight(10_000)]
pub fn store_data(
    origin: OriginFor<T>,
    data: Vec<u8>,  // unbounded input
) -> DispatchResult {
    let who = ensure_signed(origin)?;
    // No deposit, no size limit, no entry limit per account
    <UserData<T>>::insert(&who, data);
    Ok(())
}
```

**Correct pattern:**
```rust
#[pallet::storage]
pub type UserData<T: Config> = StorageMap<
    _, Blake2_128Concat, T::AccountId, BoundedVec<u8, T::MaxDataSize>
>;

#[pallet::call_index(0)]
#[pallet::weight(T::WeightInfo::store_data(data.len() as u32))]
pub fn store_data(
    origin: OriginFor<T>,
    data: BoundedVec<u8, T::MaxDataSize>,
) -> DispatchResult {
    let who = ensure_signed(origin)?;
    let deposit = T::DepositPerByte::get() * (data.len() as u32).into();
    T::Currency::reserve(&who, deposit)?;
    <UserData<T>>::insert(&who, data);
    Ok(())
}
```

**Grep for:** `StorageMap`, `StorageDoubleMap`, `StorageNMap`, `Vec<u8>` in storage types, absence of `BoundedVec`, `reserve(`, `hold(`, `deposit`, `MaxEncodedLen`

---

## SUB-004: Origin Check Bugs

**Impact:** Privilege escalation, unauthorized state modification (Critical)
**Frequency:** Common -- the origin system is nuanced and easy to misuse

Substrate has a rich origin system. Extrinsics can originate from signed accounts, root (sudo/governance), no origin (unsigned/inherent), or custom origins (council, technical committee, etc.). Confusing or omitting origin checks is a frequent source of critical vulnerabilities.

**What to check:**
- Does every extrinsic have an appropriate origin check (`ensure_signed`, `ensure_root`, `ensure_none`, or custom)?
- Are there extrinsics that should require root/governance but accept `ensure_signed`?
- Are there extrinsics that use `ensure_none` (unsigned) without additional validation? Unsigned extrinsics bypass fee payment.
- Is `T::ForceOrigin` or similar configurable origin used, and is it correctly configured in the runtime?
- For `ensure_signed`: is the returned account ID actually used for authorization, or is it ignored?
- Can `pallet_sudo` bypass intended governance controls?
- Are there extrinsics that use raw `Origin` matching instead of the helper functions?

**Pattern:**
```rust
// BUG: this should be governance-only but any signed account can call it
#[pallet::call_index(0)]
#[pallet::weight(10_000)]
pub fn set_protocol_fee(
    origin: OriginFor<T>,
    new_fee: Perbill,
) -> DispatchResult {
    let _who = ensure_signed(origin)?; // should be ensure_root or T::AdminOrigin
    <ProtocolFee<T>>::put(new_fee);
    Ok(())
}

// BUG: ensure_none with no validation -- anyone can submit unsigned
#[pallet::call_index(1)]
#[pallet::weight(10_000)]
pub fn submit_price(
    origin: OriginFor<T>,
    price: u128,
) -> DispatchResult {
    ensure_none(origin)?;
    // No ValidateUnsigned implementation, no signature check
    // Anyone can submit any price as an "oracle" update
    <OraclePrice<T>>::put(price);
    Ok(())
}
```

**Correct pattern:**
```rust
#[pallet::call_index(0)]
#[pallet::weight(10_000)]
pub fn set_protocol_fee(
    origin: OriginFor<T>,
    new_fee: Perbill,
) -> DispatchResult {
    T::AdminOrigin::ensure_origin(origin)?;
    ensure!(new_fee <= Perbill::from_percent(50), Error::<T>::FeeTooHigh);
    <ProtocolFee<T>>::put(new_fee);
    Ok(())
}
```

**Grep for:** `ensure_signed`, `ensure_root`, `ensure_none`, `EnsureOrigin`, `ForceOrigin`, `AdminOrigin`, `T::Origin`, `RawOrigin`, `ValidateUnsigned`, `pallet_sudo`

---

## SUB-005: XCM (Cross-Consensus Messaging) Vulnerabilities

**Impact:** Cross-chain fund theft, asset minting, fee drainage (Critical)
**Frequency:** Increasing -- XCM adoption growing across Polkadot/Kusama parachains

XCM is the cross-consensus messaging format used between Polkadot parachains, between parachains and the relay chain, and between any XCM-compatible systems. It is extremely powerful and complex, making it a rich attack surface.

**What to check:**

### Asset Teleporting
- Is `teleport_assets` enabled? Between which chains? Teleporting requires absolute trust between source and destination -- the source burns and the destination mints.
- Can an attacker teleport assets from a chain that doesn't actually burn them, causing infinite minting on the destination?
- Is the `IsTeleporter` filter correctly configured? An overly permissive filter allows unauthorized chains to teleport assets in.

### Reserve Transfers
- Is the `IsReserve` filter correctly configured? This controls which chains are trusted as reserve locations for which assets.
- Can an attacker craft a `ReserveAssetDeposited` message from an unauthorized reserve?
- Are reserve assets correctly escrowed on the reserve chain?

### Fee Manipulation
- Is `Trader` (the fee payment handler) configured correctly? Can an attacker pay fees in a worthless token?
- Is `WeightToFee` conversion accurate? Underpriced XCM execution allows DoS.
- Can the `BuyExecution` instruction be abused to underpay for weight?
- Is there a maximum weight that can be purchased per message?

### XCM Instruction Abuse
- Can `Transact` be used to call privileged extrinsics on the destination chain?
- Does `SetAppendix` or `SetErrorHandler` interact dangerously with subsequent instructions?
- Can `ExpectAsset` / `ExpectOrigin` checks be bypassed?
- Are `DescendOrigin` / `UniversalOrigin` correctly restricted?

### XCM Version and Configuration
- Is the chain using a recent XCM version (v3/v4)? Older versions have known vulnerabilities.
- Is the `XcmExecutor` config properly filtering allowed operations?
- Are `Barrier` filters (e.g., `AllowTopLevelPaidExecutionFrom`, `AllowSubscriptionsFrom`) correctly configured?

**Pattern:**
```rust
// BUG: overly permissive teleport filter -- trusts any sibling parachain
pub type IsTeleporter = Everything; // should be specific MultiLocation filter

// BUG: overly permissive barrier -- allows execution from any origin
pub type Barrier = AllowUnpaidExecutionFrom<Everything>; // should require fee payment

// BUG: Transact filter allows any call from any origin
pub type SafeCallFilter = Everything; // should whitelist specific calls
```

**Correct pattern:**
```rust
// Only trust specific chains for teleporting specific assets
pub type IsTeleporter = (
    NativeAsset,
    ConcreteAssetFromSystem<AssetHubLocation>,
);

// Require fee payment from non-system origins
pub type Barrier = (
    AllowUnpaidExecutionFrom<ParentOrSiblings>,
    AllowTopLevelPaidExecutionFrom<Everything>,
);

// Only allow specific safe calls via Transact
pub type SafeCallFilter = (
    pallet_balances::Call<Runtime>,
    pallet_assets::Call<Runtime>,
);
```

**Grep for:** `IsTeleporter`, `IsReserve`, `Barrier`, `AllowUnpaidExecutionFrom`, `Everything`, `Transact`, `BuyExecution`, `XcmExecutor`, `xcm_executor::Config`, `XcmConfig`, `SafeCallFilter`, `teleport_assets`, `reserve_transfer_assets`

---

## SUB-006: Runtime Upgrade Bugs

**Impact:** State corruption, chain halt, bricked chain (Critical)
**Frequency:** Every chain upgrades -- and every upgrade is a risk

Substrate's forkless runtime upgrades are powerful but dangerous. The Wasm runtime is stored on-chain and can be replaced via governance. If the new runtime is incompatible with existing state, or if migrations fail, the chain can halt or corrupt its state.

**What to check:**
- **Storage version tracking**: Does each pallet track its `StorageVersion`? Is it incremented on upgrade?
- **Migration completeness**: Does the migration handle ALL existing storage entries, including edge cases (empty entries, entries with old enum variants)?
- **Migration ordering**: If pallet A's migration depends on pallet B's state, does B migrate first?
- **try_state hooks**: Are `try_state` (integrity test) hooks implemented to verify state consistency post-migration?
- **Pre/post upgrade hooks**: Are `pre_upgrade` and `post_upgrade` hooks implemented for testability?
- **Weight of migration**: Does the migration fit within a single block? If not, is it implemented as a multi-block migration?
- **Decode failures**: Can old storage entries fail to decode under the new type? This causes a panic on read.
- **Removed pallets**: If a pallet is removed, is its storage cleaned up? Leftover storage wastes state.

**Pattern:**
```rust
// BUG: migration does not check storage version -- runs every upgrade, not just the relevant one
pub struct MigrateV1ToV2<T>(PhantomData<T>);
impl<T: Config> OnRuntimeUpgrade for MigrateV1ToV2<T> {
    fn on_runtime_upgrade() -> Weight {
        // No version check! This runs on every upgrade, re-corrupting state
        let old_data: Vec<OldFormat> = OldStorage::<T>::drain().collect();
        for item in old_data {
            NewStorage::<T>::insert(item.key, item.migrate());
        }
        T::DbWeight::get().reads_writes(old_data.len() as u64, old_data.len() as u64)
    }
}
```

**Correct pattern:**
```rust
pub struct MigrateV1ToV2<T>(PhantomData<T>);
impl<T: Config> OnRuntimeUpgrade for MigrateV1ToV2<T> {
    fn on_runtime_upgrade() -> Weight {
        let on_chain_version = Pallet::<T>::on_chain_storage_version();
        if on_chain_version < 2 {
            log::info!("Migrating from v1 to v2");
            // ... perform migration ...
            StorageVersion::new(2).put::<Pallet<T>>();
            T::DbWeight::get().reads_writes(count, count)
        } else {
            log::info!("No migration needed");
            Weight::zero()
        }
    }

    #[cfg(feature = "try-runtime")]
    fn pre_upgrade() -> Result<Vec<u8>, DispatchError> {
        let count = OldStorage::<T>::iter().count() as u32;
        Ok(count.encode())
    }

    #[cfg(feature = "try-runtime")]
    fn post_upgrade(state: Vec<u8>) -> Result<(), DispatchError> {
        let old_count = u32::decode(&mut &state[..]).unwrap();
        let new_count = NewStorage::<T>::iter().count() as u32;
        ensure!(old_count == new_count, "migration count mismatch");
        Ok(())
    }
}
```

**Grep for:** `OnRuntimeUpgrade`, `on_runtime_upgrade`, `StorageVersion`, `on_chain_storage_version`, `pre_upgrade`, `post_upgrade`, `try-runtime`, `Executive`, `set_code`, `system::set_code`

---

## SUB-007: Pallet Hook Panics

**Impact:** Chain halt (Critical)
**Frequency:** Moderate -- hooks run every block, so any reachable panic halts the chain

FRAME pallets can implement hooks that run at specific points in the block lifecycle: `on_initialize` (start of block), `on_finalize` (end of block), `on_idle` (remaining block weight), `on_runtime_upgrade` (after code upgrade), and `offchain_worker` (off-chain, less critical). A panic in `on_initialize` or `on_finalize` halts the chain because these are mandatory -- they cannot be skipped.

**What to check:**
- Are there any `.unwrap()`, `.expect()`, array indexing `[i]`, or division operations in hook functions?
- Do hooks iterate over storage? What if the storage is empty, corrupt, or unexpectedly large?
- Do hooks perform cross-pallet calls that could fail?
- Is `on_initialize` weight correctly accounted for in the block weight limit?
- Can `on_initialize` exceed the block weight limit? (This itself does not halt, but can delay block production beyond relay chain limits for parachains.)
- Are there any codec `Decode` operations that could panic on malformed data?

**Pattern:**
```rust
// BUG: multiple panic vectors in on_initialize
impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_initialize(n: BlockNumberFor<T>) -> Weight {
        let prices: Vec<u128> = PriceBuffer::<T>::get();
        // Panics if prices is empty
        let avg = prices.iter().sum::<u128>() / prices.len() as u128;
        // Panics if index out of bounds
        let latest = prices[prices.len() - 1];
        // Panics if Decode fails on corrupt storage
        let config = ConfigStorage::<T>::get().unwrap();
        CurrentPrice::<T>::put(avg);
        Weight::zero()
    }
}
```

**Correct pattern:**
```rust
fn on_initialize(n: BlockNumberFor<T>) -> Weight {
    let prices: Vec<u128> = PriceBuffer::<T>::get();
    if let Some(avg) = prices.iter().sum::<u128>().checked_div(prices.len() as u128) {
        if let Some(latest) = prices.last() {
            CurrentPrice::<T>::put(avg);
        }
    }
    if let Some(config) = ConfigStorage::<T>::get() {
        // use config safely
    }
    T::DbWeight::get().reads(2)
}
```

**Grep for:** `on_initialize`, `on_finalize`, `on_idle`, `on_runtime_upgrade`, `.unwrap()`, `.expect(`, `panic!`, `unreachable!`, `/ ` (division), `[` (indexing) within hook implementations

---

## SUB-008: Session Key Management Bugs

**Impact:** Consensus failure, validator set corruption, unauthorized block production (High to Critical)
**Frequency:** Less common but high impact when it occurs

Substrate chains using BABE/Aura + GRANDPA consensus rely on session keys for block production and finality voting. Bugs in session key management can cause validators to be unable to produce blocks, or allow unauthorized parties to participate in consensus.

**What to check:**
- **Key rotation**: When validators rotate keys via `set_keys`, are old keys properly invalidated?
- **Session change**: Does `on_new_session` correctly update the authority set? What if a validator is removed during an active session?
- **Key ownership proof**: Does `set_keys` verify that the caller actually owns the keys (via a proof-of-possession)?
- **GRANDPA authority changes**: Are GRANDPA authority set changes applied at the correct block (delayed by one session)? Applying immediately can cause finality stalls.
- **Queued keys**: Is the queued-keys mechanism correct? Early application of queued keys corrupts consensus.
- **Empty authority set**: What happens if all validators are removed (e.g., by slashing)?
- **Duplicate keys**: Can two validators register the same session keys?

**Pattern:**
```rust
// BUG: does not verify key ownership -- anyone can set keys they don't own
#[pallet::call_index(0)]
#[pallet::weight(10_000)]
pub fn register_validator(
    origin: OriginFor<T>,
    keys: T::Keys,
) -> DispatchResult {
    let who = ensure_signed(origin)?;
    // Missing: proof-of-possession verification
    // An attacker could register another validator's keys,
    // causing key conflicts and consensus failures
    <NextKeys<T>>::insert(&who, keys);
    Ok(())
}

// BUG: GRANDPA authority change applied immediately instead of at session boundary
fn on_new_session(changed: bool) {
    if changed {
        let new_authorities = Self::compute_authorities();
        // Applied immediately -- GRANDPA voters see a mid-session change
        // and may fail to finalize blocks
        pallet_grandpa::Pallet::<T>::schedule_change(
            new_authorities,
            Zero::zero(), // BUG: delay of 0 instead of session length
        );
    }
}
```

**Grep for:** `set_keys`, `on_new_session`, `SessionHandler`, `ShouldEndSession`, `SessionManager`, `schedule_change`, `NextKeys`, `QueuedKeys`, `GRANDPA`, `authorities`, `ValidatorSet`

---

## SUB-009: Proxy / Multisig Bypass Patterns

**Impact:** Unauthorized access, fund theft (Critical)
**Frequency:** Moderate -- proxy and multisig are widely used but subtly complex

Substrate's `pallet_proxy` and `pallet_multisig` provide delegation and multi-signature capabilities. Misconfigurations or bugs in custom pallets' interaction with these primitives can allow privilege escalation.

**What to check:**

### Proxy Bypasses
- **ProxyType filter**: Does the custom `ProxyType` enum correctly restrict which calls each proxy type can make?
- **Nested proxies**: Can an attacker chain proxy calls to escalate privileges (proxy A -> proxy B -> privileged call)?
- **Anonymous proxies**: Can `anonymous` (pure) proxies be used to obscure the true caller?
- **Proxy removal race**: Can a proxy execute a transaction after the delegator removes them but before the removal is finalized?
- **Time-delayed proxies**: Are time delays correctly enforced? Can they be bypassed?

### Multisig Bypasses
- **Threshold validation**: Is the multisig threshold validated (threshold <= signatories count, threshold > 0)?
- **Signatory ordering**: Substrate requires signatories to be sorted and unique. Is this enforced?
- **Call hash manipulation**: Can a different call be approved than what was originally proposed?
- **Timepoint**: Is the timepoint (block number + extrinsic index) correctly used to prevent replays?
- **Cancel permission**: Who can cancel a pending multisig operation? Can a single participant grief by canceling?

### Interaction with Custom Pallets
- **Origin stripping**: When a call comes through a proxy, does the target pallet see the original caller or the proxy? Does it matter?
- **Nesting depth**: Is there a limit on proxy/multisig nesting depth?

**Pattern:**
```rust
// BUG: ProxyType filter is too permissive
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Encode, Decode)]
pub enum ProxyType {
    Any,         // can call anything
    Governance,  // governance only
    Staking,     // staking only
    Transfer,    // transfers only
}

impl InstanceFilter<RuntimeCall> for ProxyType {
    fn filter(&self, c: &RuntimeCall) -> bool {
        match self {
            ProxyType::Any => true,
            ProxyType::Transfer => matches!(
                c,
                RuntimeCall::Balances(..) | RuntimeCall::Assets(..)
            ),
            // BUG: Governance proxy can also call Sudo
            ProxyType::Governance => matches!(
                c,
                RuntimeCall::Democracy(..) |
                RuntimeCall::Council(..) |
                RuntimeCall::Sudo(..)  // should NOT be here
            ),
            ProxyType::Staking => matches!(c, RuntimeCall::Staking(..)),
        }
    }
}
```

**Grep for:** `ProxyType`, `InstanceFilter`, `filter(`, `pallet_proxy`, `pallet_multisig`, `as_multi`, `approve_as_multi`, `anonymous`, `add_proxy`, `proxy(`, `proxy_announced`, `Multisig`, `threshold`

---

## SUB-010: EVM Compatibility Layer Bugs

**Impact:** Cross-layer fund theft, state inconsistency, consensus divergence (Critical)
**Frequency:** High on EVM-compatible Substrate chains (Moonbeam, Astar, Acala EVM+)

Chains using Frontier (pallet_evm + pallet_ethereum) run a full EVM inside the Substrate runtime. This creates a dual execution environment with separate account systems, gas/weight models, and state management. The boundary between Substrate-native and EVM execution is a rich attack surface.

**What to check:**

### Account Unification
- **Address mapping**: How are Substrate accounts (SS58, 32 bytes) mapped to Ethereum accounts (H160, 20 bytes)? Is the mapping injective (1-to-1)?
- **Balance inconsistency**: Can a balance appear different when queried via Substrate RPC vs. Ethereum RPC?
- **Nonce synchronization**: Are Substrate and EVM nonces kept in sync? A mismatch can cause transaction replay or rejection.

### Gas/Weight Conversion
- **Gas-to-weight ratio**: Is the conversion factor between EVM gas and Substrate weight correct? An incorrect ratio means EVM transactions are under- or over-charged.
- **Block gas limit**: Does the EVM block gas limit correspond correctly to the Substrate block weight limit?
- **Precompile gas costs**: Do custom precompiles charge correct gas for their actual weight?

### Custom Precompiles
- **Input validation**: Do precompiles validate ABI-encoded input correctly? Solidity ABI encoding allows padding tricks.
- **State access**: Can precompiles access Substrate state (balances, staking, governance) correctly?
- **Reentrancy**: Can an EVM contract call a precompile that calls back into the EVM?
- **Access control**: Do precompiles check `msg.sender` correctly? In the precompile context, is the caller the EOA or the contract?
- **Error handling**: Do precompile failures correctly revert state?

### Cross-VM Interactions
- **Substrate-to-EVM calls**: Can Substrate extrinsics invoke EVM contracts? Are the call results correctly handled?
- **EVM-to-Substrate calls**: Via precompiles -- can EVM contracts call arbitrary Substrate extrinsics?
- **Event translation**: Are Substrate events and EVM logs correctly correlated?
- **XVM (Cross-VM) on Astar**: Astar's XVM allows calling between Wasm and EVM contracts. Is the call boundary secure?

**Pattern:**
```rust
// BUG: precompile does not validate input length -- panics on short input
impl PrecompileHandle for StakingPrecompile {
    fn execute(handle: &mut impl PrecompileHandle) -> PrecompileResult {
        let input = handle.input();
        // ABI decode without length check
        let validator = H256::from_slice(&input[0..32]);   // panic if input < 32 bytes
        let amount = U256::from_big_endian(&input[32..64]); // panic if input < 64 bytes

        // BUG: no gas cost charged for the staking operation
        // The EVM transaction pays only the 21000 base gas
        pallet_staking::Pallet::<Runtime>::bond(
            RawOrigin::Signed(caller).into(),
            amount.as_u128(),
            RewardDestination::Stash,
        )?;

        Ok(PrecompileOutput {
            exit_status: ExitSucceed::Returned,
            output: vec![],
        })
    }
}
```

**Correct pattern:**
```rust
fn execute(handle: &mut impl PrecompileHandle) -> PrecompileResult {
    // Validate minimum input length
    if handle.input().len() < 64 {
        return Err(PrecompileFailure::Error {
            exit_status: ExitError::Other("invalid input length".into()),
        });
    }

    // Charge gas proportional to the Substrate weight
    let weight = <Runtime as pallet_staking::Config>::WeightInfo::bond();
    let gas_cost = <Runtime as pallet_evm::Config>::GasWeightMapping::weight_to_gas(weight);
    handle.record_cost(gas_cost)?;

    // Safe input parsing
    let validator = H256::from_slice(&handle.input()[0..32]);
    let amount = U256::from_big_endian(&handle.input()[32..64]);

    // Execute with proper origin
    // ...
}
```

**Grep for:** `pallet_evm`, `pallet_ethereum`, `Precompile`, `PrecompileHandle`, `PrecompileSet`, `PrecompileResult`, `GasWeightMapping`, `weight_to_gas`, `FrontierCompatible`, `AccountMapping`, `AddressMapping`, `H160`, `EVM`, `XVM`, `cross_vm`, `ethereum::Transaction`

---

## Scan Priority

For Substrate/Polkadot chains, prioritize in this order:

1. **SUB-005: XCM vulnerabilities** -- highest financial impact; cross-chain asset theft can drain entire parachains. Actively exploited category. Especially critical for Bifrost, Hydration, and Acala which handle large cross-chain liquidity flows.

2. **SUB-010: EVM compatibility layer bugs** -- highest bug density on EVM-compatible chains. Custom precompiles are the #1 attack surface for Moonbeam and Astar. Check precompile input validation and gas costing first.

3. **SUB-004: Origin check bugs** -- frequently critical and easy to find. A single `ensure_signed` where `ensure_root` was intended can give any user admin access. Fast to audit, high payoff.

4. **SUB-002: Unsafe arithmetic** -- high financial impact, especially in DeFi pallets on Acala, Hydration, and SORA. Overflow in balance calculations directly translates to fund theft.

5. **SUB-001: Weight miscalculation** -- most common bug class overall. Chains with complex custom pallets (Gear's actor model, SORA's DEX logic) are especially susceptible. Enables chain-level DoS.

6. **SUB-006: Runtime upgrade bugs** -- critical but time-bounded (only relevant during upgrades). Check migration code for any chain that recently upgraded or has an upgrade scheduled.

7. **SUB-007: Pallet hook panics** -- chain-halting severity. All target chains have custom hooks. Gear's message processing hooks and Bifrost's cross-chain hooks are priority targets.

8. **SUB-003: Storage exhaustion** -- slower-burning DoS. Important for chains with user-generated content storage (Gear programs, SORA liquidity pool entries).

9. **SUB-009: Proxy/multisig bypass** -- configuration-level bugs. Quick to audit by reviewing `ProxyType` implementations and multisig thresholds.

10. **SUB-008: Session key management** -- lower frequency but chain-halting impact. Most relevant for chains with custom validator selection (Bifrost's liquid staking validators, Moonbeam's collator selection).
