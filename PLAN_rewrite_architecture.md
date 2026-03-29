# SESSION_ROUTER Rewrite — Layered Architecture

## Decisions

| # | Decision | Call |
|---|----------|------|
| 1 | 1.0.x protocol | Drop |
| 2 | Platforms | Linux only |
| 3 | Exit mode | v1.1 (core first) |
| 4 | .loki TLD | Drop |
| 5 | TCP tunnel | Drop |

## Architecture — 6 Layers, No Cycles

```
Layer 0: Crypto          (pure functions, zero dependencies)
Layer 1: Contact         (identity types, depends on crypto only)
Layer 2: Path            (onion construction, depends on crypto + contact)
Layer 3: Session         (E2E encryption, depends on crypto + path)
Layer 4: Link            (QUIC transport, depends on nothing above)
Layer 5: Node            (wires layers together, TUN, DNS, tick loop)
```

### Layer 0 — Crypto

Pure functions. No state. No dependencies except libsodium.

```
crypto/
├── aead.hpp/cpp          xchacha20-poly1305 encrypt/decrypt
├── dh.hpp/cpp            Ed25519 DH with BLAKE2b domain separation
├── keys.hpp/cpp          Key types: Ed25519, X25519, RouterID
├── sealed_box.hpp/cpp    Public-key sealed box (seal/unseal)
├── blind.hpp/cpp         Blinded key derivation
├── mlkem.hpp/cpp         ML-KEM-768 keygen/encapsulate/decapsulate
└── session_keys.hpp/cpp  Session key derivation (k1/k2 swap)
```

Every function takes inputs, returns outputs. No `Router&` parameter.
Full test coverage from day one — these are the foundations everything rests on.

Constraints preserved:
- DH hash order: always (client_pk || server_pk || shared)
- k1/k2 swap: initiator (out=k1, in=k2), receiver (out=k2, in=k1)
- Blinded key domain separation: unique domain strings, no reuse

### Layer 1 — Contact

Identity types and routing table. Depends only on Layer 0.

```
contact/
├── router_id.hpp/cpp       RouterID (Ed25519 pubkey wrapper)
├── relay_contact.hpp/cpp   RelayContact (signed advertisement: addr, port, version)
├── client_contact.hpp/cpp  ClientContact (blinded identity for privacy)
├── nodedb.hpp/cpp          Routing table: store, lookup, bootstrap, bucket hashes
└── profiling.hpp/cpp       Relay profiling (success/fail tracking)
```

NodeDB owns the routing table state. No reference to Link, Path, or Session.
Bootstrap populates it. Gossip updates it. Path building reads it.

### Layer 2 — Path

Onion routing construction. Depends on crypto + contact.

```
path/
├── path.hpp/cpp            Path object: hops, shared secrets, xor nonces
├── path_handler.hpp/cpp    Path building: hop selection, onion construction
├── path_context.hpp/cpp    Path/transit hop lookup table
├── transit_hop.hpp/cpp     Relay-side single hop representation
└── build_stats.hpp/cpp     Path build success/failure tracking
```

Path building reads NodeDB for hop selection. Onion construction uses crypto.
No reference to Session, Link, or Node.

Constraints preserved:
- Onion frames encrypted in reverse (pivot to edge)
- Frame rotation at each relay (asymmetric onion/de-onion)
- xor_nonce derived from shorthash(shared_secret)
- BUILD_FRAME_SIZE = 169, BUILD_LENGTH = 8 (4 real + 4 dummy)

### Layer 3 — Session

End-to-end encrypted sessions. Depends on crypto + path.

```
session/
├── session.hpp/cpp         Session base: key state, encrypt/decrypt data
├── outbound.hpp/cpp        Outbound session: init, sealed box, DH + ML-KEM
├── inbound.hpp/cpp         Inbound session: accept, unseal, derive keys
└── session_types.hpp       SessionTag, TrafficType enums
```

1.1+ only. No _old_accept, no legacy DH, no switch_xor_factor hack.
Session sends/receives through Path objects. No reference to Link or Node.

### Layer 4 — Link

QUIC transport. Depends on nothing above it.

```
link/
├── endpoint.hpp/cpp        QUIC endpoint (oxen-libquic wrapper)
├── connection.hpp/cpp      Single QUIC connection with BTStream + Datagrams
└── manager.hpp/cpp         Connection lifecycle, keep-alive, mesh management
```

Link's job: send bytes to a RouterID, receive bytes from a RouterID.
It does not parse message contents. It does not know about paths or sessions.

### Layer 5 — Node

Orchestration. Wires everything together. Owns the event loop and TUN.

```
node/
├── node.hpp/cpp            Main orchestrator (~200 lines, not 1137)
├── dispatch.hpp/cpp        Message dispatch: register handlers, route messages
├── tun.hpp/cpp             Linux TUN device
├── dns.hpp/cpp             DNS resolver (.sesh only)
├── config.hpp/cpp          INI config parsing
└── tick.hpp/cpp            250ms tick loop, timers
```

Node constructs all layers via dependency injection:
```cpp
auto crypto = Crypto{};
auto nodedb = NodeDB{crypto};
auto path_ctx = PathContext{crypto, nodedb};
auto session_mgr = SessionManager{crypto, path_ctx};
auto link = LinkManager{};
auto dispatch = Dispatch{link};

dispatch.on("path_build", [&](auto msg) { path_ctx.handle_build(msg); });
dispatch.on("session_init", [&](auto msg) { session_mgr.handle_init(msg); });
dispatch.on("gossip_rc", [&](auto msg) { nodedb.handle_gossip(msg); });

auto node = Node{dispatch, link, path_ctx, session_mgr, nodedb, config};
node.run();  // starts tick loop
```

Every component testable with mocks. No circular dependencies. No god object.

## Event System

Replace the "path_died has zero callers" problem:

```cpp
// Path emits events
path_ctx.on(PathEvent::BUILT, [&](auto& p) { session_mgr.try_pending(p); });
path_ctx.on(PathEvent::DIED, [&](auto& p) { session_mgr.handle_path_loss(p); });
path_ctx.on(PathEvent::EXPIRED, [&](auto& p) { /* cleanup */ });

// Session emits events
session_mgr.on(SessionEvent::ESTABLISHED, [&](auto& s) { /* ready */ });
session_mgr.on(SessionEvent::FAILED, [&](auto& s) { /* retry */ });
```

Observable, testable, no forgotten callbacks.

## Threading Model

Real mutexes where needed, not NullMutex. But minimize contention:
- Link callbacks → dispatch queue (lock-free MPSC queue)
- Dispatch drains on tick thread (single consumer)
- Path/session state accessed only from tick thread (no lock needed)
- TUN reads → separate thread → dispatch queue

Same effective model as upstream (single-thread for state) but with
a proper queue boundary instead of an invisible invariant.

## Wire Compatibility

Same protocol, same wire format. An existing session-router node
cannot tell the difference between talking to the original code or ours.

| Message | Format | Identical? |
|---------|--------|-----------|
| path_build | 8 × 169B BT frames | Yes |
| session_init | Sealed box + ML-KEM | Yes (1.1+ only) |
| session_data | AEAD + onion layers | Yes |
| gossip_rc | Signed BT RelayContact | Yes |
| path_control | AEAD BT {e, p} | Yes |
| bfetch_rcs | zstd compressed RC list | Yes |
| fetch_rcs | Bucket hash sync | Yes |

## Build Order

| Phase | What | Tests | Milestone |
|-------|------|-------|-----------|
| 0 | Crypto layer | Full coverage | All primitives verified |
| 1 | Contact + NodeDB | RC parse, bucket hash, profiling | Can load bootstrap |
| 2 | Path building | Onion construct/peel round-trip | Can build paths |
| 3 | Session | Key derivation, sealed box handshake | Can establish sessions |
| 4 | Link | QUIC connect, BTStream send/recv | Can talk to real nodes |
| 5 | Node + TUN + DNS | Integration test against real network | Working client |
| 6 | Exit mode (v1.1) | Route management, egres forwarding | Exit nodes |

Each phase is independently testable. Phase 0-3 need no network.
Phase 4 can test against upstream session-router nodes.
Phase 5 is the integration milestone — a working onion router.

## File Count Estimate

| Layer | Files | Est. Lines |
|-------|-------|-----------|
| Crypto | 14 | ~1,200 |
| Contact | 10 | ~1,500 |
| Path | 10 | ~1,800 |
| Session | 8 | ~1,200 |
| Link | 6 | ~1,000 |
| Node | 12 | ~1,500 |
| Tests | 20+ | ~3,000 |
| **Total** | **~80** | **~11,200** |

vs upstream's 36,900 lines. Clean code is shorter code.
