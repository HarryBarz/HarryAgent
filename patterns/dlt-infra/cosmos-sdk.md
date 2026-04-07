# Cosmos SDK / CometBFT Vulnerability Patterns

Target chains: Sei, Celestia, Cronos, ZetaChain, AtomOne, Coreum, Osmosis, Axelar, Stacks (partial)

## Framework Architecture (for agent context)

```
Application Layer (custom modules in x/)
    |
Cosmos SDK (x/auth, x/bank, x/staking, x/gov, x/distribution, x/slashing, x/ibc)
    |
ABCI Interface (CheckTx, DeliverTx, BeginBlock, EndBlock, Commit)
    |
CometBFT (consensus, P2P, mempool, state sync)
```

Key: most chains customize at the Application Layer. Bugs in SDK and CometBFT affect all chains. Bugs in custom modules are chain-specific.

---

## COS-001: BeginBlocker / EndBlocker Panics

**Impact:** Chain halt (High)
**Frequency:** Common in custom modules

BeginBlocker and EndBlocker run at every block boundary. If they panic, the chain halts.

**What to check:**
- Any `panic()` call reachable from BeginBlocker/EndBlocker
- Any unhandled error (Go error not checked) that later causes nil pointer dereference
- Any map iteration used for deterministic output (Go maps iterate randomly)
- Division by zero in reward calculations when validator set is empty
- Array index out of bounds when processing empty validator updates

**Pattern:**
```go
// BUG: panics if no validators
func (k Keeper) EndBlocker(ctx sdk.Context) {
    validators := k.GetAllValidators(ctx)
    avgStake := totalStake / int64(len(validators)) // division by zero if empty
}
```

**Grep for:** `BeginBlock`, `EndBlock`, `panic(`, map range in these functions

---

## COS-002: Custom Message Handler Missing ValidateBasic

**Impact:** Variable (Medium to Critical depending on what's missing)

Every `sdk.Msg` should implement `ValidateBasic()` for stateless validation. Custom modules often have incomplete validation.

**What to check:**
- Does `ValidateBasic()` validate ALL fields?
- Are amounts checked for negative values? Zero values?
- Are addresses validated? (`sdk.AccAddressFromBech32` can accept invalid addresses if not checked)
- Are string lengths bounded? (unbounded strings -> state bloat)
- Is the signer validated? (message sender matches expected authority)

**Pattern:**
```go
// BUG: ValidateBasic doesn't check Amount
func (msg MsgCustomTransfer) ValidateBasic() error {
    if msg.Sender == "" {
        return errors.New("sender required")
    }
    // Missing: amount > 0 check
    // Missing: recipient validation
    return nil
}
```

---

## COS-003: Module Account Permission Escalation

**Impact:** Critical (infinite minting, fund theft)

Module accounts have specific permissions (Minter, Burner, Staking). If a custom module creates a module account with excess permissions, or if a keeper method can be called to mint/burn without proper authorization.

**What to check:**
- What permissions does each module account have? (check `maccPerms` in `app.go`)
- Can any message handler invoke `MintCoins` or `BurnCoins`?
- Are keeper methods that mint/burn properly gated by authorization checks?
- Can `x/authz` be used to grant someone MsgMint authorization?

**Grep for:** `MintCoins`, `BurnCoins`, `SendCoinsFromModuleToAccount`, `maccPerms`, `authz`

---

## COS-004: IBC Packet Handling Vulnerabilities

**Impact:** Critical (cross-chain fund theft or infinite minting)

IBC (Inter-Blockchain Communication) is complex. Custom IBC modules often have bugs.

**What to check:**
- `OnRecvPacket`: Does it validate the packet data completely? Can malicious relayer craft a packet?
- `OnAcknowledgementPacket`: Does it handle error acknowledgements correctly? (funds refunded on failure?)
- `OnTimeoutPacket`: Same as above -- are funds refunded? Are they refunded to the right account?
- Channel ordering: does the module require ORDERED channels where UNORDERED would cause issues?
- Denom trace: can a crafted IBC denom path create a token that collides with a native token?
- Escrow accounting: do escrowed tokens on source chain == minted tokens on destination chain?

**Pattern:**
```go
// BUG: no validation of packet data -- relayer controls this
func (k Keeper) OnRecvPacket(ctx sdk.Context, packet channeltypes.Packet) error {
    var data types.CustomPacketData
    json.Unmarshal(packet.GetData(), &data) // error ignored!
    k.bankKeeper.MintCoins(ctx, types.ModuleName, data.Amount) // mints whatever the packet says
}
```

---

## COS-005: AnteHandler Chain Bypass

**Impact:** High (fee bypass, replay, auth bypass)

The AnteHandler chain runs before every transaction. Custom AnteHandlers can break the chain or skip checks.

**What to check:**
- Does the custom AnteHandler call `next(ctx, tx, simulate)` to continue the chain?
- If it returns early (before calling next), are all necessary checks still performed?
- Does it handle the `simulate` flag correctly? (simulation should skip some checks but not security-critical ones)
- Does it handle the `reCheckTx` flag correctly? (mempool recheck should still validate)
- Is the AnteHandler order correct? (signature verification before deduction, etc.)

**Grep for:** `AnteHandler`, `NewAnteHandler`, `ante.NewAnteHandler`

---

## COS-006: Keeper Method Authorization

**Impact:** High to Critical

Keeper methods are the internal API of each module. They often lack authorization checks because they assume only authorized callers invoke them. But custom modules might call other modules' keepers without proper authorization.

**What to check:**
- Does every public keeper method that modifies state verify the caller is authorized?
- Can a custom module call `bankKeeper.SendCoins()` to send from any account?
- Can a custom module call `stakingKeeper.Delegate()` with arbitrary parameters?
- Are there any keeper methods that should be restricted to governance but aren't?

---

## COS-007: Non-Determinism in State Transitions

**Impact:** Critical (chain split)

Any non-deterministic behavior in transaction execution causes different validators to produce different state roots -> chain halt or split.

**Common sources in Go:**
```go
// BUG: map iteration order is non-deterministic in Go
for addr, balance := range balances {
    // Different validators process these in different order
    // If processing order matters (e.g., due to side effects), consensus breaks
}
```

**Other sources:**
- `time.Now()` in transaction execution (use `ctx.BlockTime()` instead)
- Floating-point arithmetic (use `sdk.Dec` / `math.LegacyDec`)
- Goroutines in transaction execution
- External HTTP calls in transaction execution
- Random without deterministic seed
- File system reads

**Grep for:** `range` on maps in handlers/keepers, `time.Now()`, `float64`, `go func()`, `http.Get`

---

## COS-008: Gas Metering Bypass

**Impact:** Medium to High (DoS)

Operations that consume disproportionate resources relative to their gas cost.

**What to check:**
- State iteration without gas cost per iteration
- Large data storage without proportional gas cost
- Crypto operations (signature verification) without adequate gas cost
- Recursive message execution (MsgExec in authz) without gas depth limit

**Pattern:**
```go
// BUG: iterates all entries but charges flat gas
func (k Keeper) GetAll(ctx sdk.Context) []types.Entry {
    ctx.GasMeter().ConsumeGas(1000, "get-all") // flat cost
    iterator := k.store.Iterator(nil, nil) // could iterate millions
    // ...
}
```

---

## COS-009: Upgrade Handler State Migration Bugs

**Impact:** High to Critical (state corruption, chain halt)

During chain upgrades, migration handlers transform state from the old format to the new.

**What to check:**
- Does the migration handle all existing state entries? (edge cases with unusual values)
- Does the migration use deterministic iteration order?
- What happens if the migration panics midway? (partial migration = corrupted state)
- Is there a rollback mechanism?
- Does the migration correctly update store keys if the prefix changed?
- Are module store versions correctly incremented?

**Grep for:** `RegisterUpgradeHandler`, `RunMigrations`, `module.Version`

---

## COS-010: CometBFT Specific Patterns

**Consensus timing:**
- `MedianTime` calculation with Byzantine timestamps -- validators can influence block time
- `TimeoutPropose` / `TimeoutPrevote` / `TimeoutPrecommit` -- can these be manipulated?

**Evidence handling:**
- Duplicate vote evidence: is it validated thoroughly?
- Light client attacks: are they detectable?
- Evidence age limit: can a valid evidence expire before submission?

**Mempool:**
- `CheckTx` vs `DeliverTx` divergence
- Mempool recheck after block commit -- is it complete?
- Priority mempool ordering manipulation

**State sync:**
- Snapshot validation: can a malicious node provide a corrupted snapshot?
- Light block verification during fast sync

**Grep for:** `evidence`, `HandleMessage`, `Reactor`, `OnStart`, `mempool.CheckTx`

---

## COS-011: Custom Module Interaction Bugs

**Impact:** Variable

When multiple custom modules interact, bugs can emerge that don't exist in any single module.

**What to check:**
- Module A calls Module B's keeper -- does B validate the call properly?
- Module A emits an event that Module B listens for -- can Module A trigger unintended behavior in B?
- Module A modifies state that Module B reads -- race condition during same block?
- Circular dependencies between modules

---

## COS-012: SDK Version-Specific Bugs

Check the `go.mod` for the Cosmos SDK version and cross-reference against known CVEs:
- **SDK v0.47.x**: Various `x/authz` and `x/feegrant` bugs
- **SDK v0.50.x**: New `x/accounts` module -- less battle-tested
- **CometBFT v0.38.x**: Various consensus edge cases
- **IBC-go v7.x/v8.x**: Channel upgrade bugs

**Always check:** What version of each dependency is used? Are there known CVEs for that version?
