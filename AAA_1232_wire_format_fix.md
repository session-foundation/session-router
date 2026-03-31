# AAA: SESSION_ROUTER Wire Format Fix

**Issue:** #1232
**Parent:** #1202 (rewrite), #1228 (research)
**Status:** PLANNING

---

## Phase 1: VISION
**Status:** COMPLETE

### What We're Building
Fix every wire format mismatch between our clean session-router rewrite and the upstream protocol so that our implementation can communicate with real Session Network nodes.

### Why It Matters
The rewrite has clean architecture (6 layers, zero cycles, 112 tests) but cannot talk to the network. Every message type uses raw binary concatenation instead of upstream's BT-encoded dicts, and the session key derivation algorithm is wrong. Without wire compatibility, the rewrite is a proof-of-concept, not a usable node.

### Success Criteria
- [ ] Session key derivation produces identical keys to upstream for the same inputs
- [ ] Session init/accept messages are BT-encoded and byte-identical to upstream for the same inputs
- [ ] Path build frames are BT-encoded and byte-identical to upstream for the same inputs
- [ ] Path message framing (nonce/hopid/msgtype trailer) is implemented
- [ ] Session data messages use correct nonce placement and pivot ID
- [ ] Session control message framing is implemented
- [ ] Bootstrap RC parser can read upstream bootstrap.signed files
- [ ] Two instances of our rewrite can establish a session with each other
- [ ] Wire format verified by local two-instance test (stagenet connection is #1235)

---

## Phase 2: FEASIBILITY
**Status:** COMPLETE

### Assessment: MODERATE
### Decision: GO

| Factor | Assessment |
|--------|-----------|
| BT encoding | oxen-encoding (oxenc) is already a submodule in the upstream build. We can either use it or implement minimal BT encode/decode (~200 LOC) |
| Crypto changes | Key derivation fix is exact — upstream code specifies every byte. No ambiguity. |
| Wire format | Research doc (#1231) documents every field, every byte offset. No reverse engineering needed. |
| Test vectors | We can extract test vectors by running upstream code and capturing serialized output |
| Build system | CMake already works for the rewrite |

### Risks
| Risk | Severity | Mitigation |
|------|----------|------------|
| BT encoding edge cases | Medium | Use oxenc library directly rather than reimplementing |
| Signature scope ambiguity | High | Extract exact bytes signed from upstream `append_signature` implementation |
| Missing path message framing | Medium | Well-documented in research, straightforward to implement |
| Upstream protocol changes | Low | Pin to v1.0.2 wire format (current stable) |

### Dependencies
- oxen-encoding (oxenc) library — already a submodule in upstream
- Research doc RESEARCH_1228_wire_format_verification.md — complete

### Constraint
The rewrite currently has its own raw binary serialization throughout. This fix replaces ALL serialization, not patches. Every message type changes.

---

## Phase 3: SPECIFICATIONS
**Status:** COMPLETE

### 3.1 BT Encoding Library

**Requirement:** Implement or integrate BT (bencode) encoding/decoding for all message types.

**Option A (preferred):** Use oxen-encoding (oxenc) from upstream submodule.
- Already handles signature append/verify over BT-encoded prefixes
- Handles dict key sorting automatically
- Used by upstream, guarantees byte-identical output

**Option B (fallback):** Minimal BT encoder/decoder.
- Bencode spec: `d` dict, `l` list, `i<int>e` integer, `<len>:<bytes>` string
- Keys must be sorted lexicographically
- ~200 LOC for encode/decode

**Decision:** Use oxenc. It's already in the dependency tree and guarantees compatibility.

### 3.2 Session Key Derivation (CRITICAL — must be exact)

**Current (wrong):**
```cpp
// Single-phase, wrong domain, wrong ordering
h = BLAKE2b-512(
    key = "session-router-session-keys",
    data = X || Y || DH || k_s || M || I || R
)
```

**Required (upstream):**
```cpp
// Phase 1: Context
context = BLAKE2b-512(
    key = "srouter session context",    // 23 bytes exactly
    data = I || R || tag_i_le4 || tag_r_le4
)

// Phase 2: Key derivation
[k1, k2] = BLAKE2b-512(
    key = context,                       // 64 bytes (full Phase 1 output)
    data = DH_result || X || Y || k_s || M
)
```

Where:
- I = initiator Ed25519 pubkey (RouterID), 32 bytes
- R = receiver Ed25519 pubkey (RouterID), 32 bytes
- tag_i = initiator session tag, uint32 little-endian, 4 bytes
- tag_r = receiver session tag, uint32 little-endian, 4 bytes
- DH_result = X25519 scalar mult of our secret with their public, 32 bytes
- X = initiator's ephemeral X25519 pubkey, 32 bytes (always initiator, regardless of who computes)
- Y = receiver's ephemeral X25519 pubkey, 32 bytes (always receiver, regardless of who computes)
- k_s = ML-KEM shared secret, 32 bytes
- M = initiator's ML-KEM-768 pubkey, 1184 bytes

**Key assignment:**
- Initiator: key_out = k1 (first 32 bytes), key_in = k2 (last 32 bytes)
- Receiver: key_out = k2, key_in = k1

**Function signature must accept:** both RouterIDs, both X25519 pubkeys, our X25519 secret, is_initiator flag, ML-KEM shared secret, ML-KEM pubkey, both session tags.

**Test:** Given known inputs, output must match upstream. Extract test vector from upstream test suite or by instrumenting upstream code.

### 3.3 Session Init Message

**Outer envelope:**
```
BT dict {
    "" : "i"                    // string, handshake type
    "B" : <sealed_box_bytes>    // crypto_box_seal for recipient Ed25519
}
```

**Inner payload (inside sealed box):**
```
BT dict {
    "I" : <32 bytes>     // initiator Ed25519 pubkey
    "M" : <1184 bytes>   // ephemeral ML-KEM-768 pubkey
    "X" : <32 bytes>     // ephemeral X25519 pubkey
    "p" : <16 bytes>     // pivot HopID
    "t" : <uint32>       // session tag (initiator's inbound tag)
    "~" : <64 bytes>     // Ed25519 signature over BT-encoded prefix
}
```

**Signature:** Ed25519 sign over the BT-encoded bytes of the dict from opening `d` up to but NOT including the `"~"` key-value pair. Use oxenc's `append_signature`.

**Message type:** `0x02` (SessionHandshake)

### 3.4 Session Accept Message

**Outer envelope:**
```
BT dict {
    "" : "a"                    // string, handshake type
    "B" : <sealed_box_bytes>    // crypto_box_seal for initiator Ed25519
}
```

**Inner payload (inside sealed box):**
```
BT dict {
    "Y" : <32 bytes>     // server ephemeral X25519 pubkey
    "c" : <1088 bytes>   // ML-KEM-768 ciphertext
    "t" : <uint32>       // recipient session tag
    "~" : <64 bytes>     // Ed25519 signature over BT-encoded prefix
}
```

### 3.5 Session Control Messages

```
BT dict {
    "e" : "<method_name>"    // string: "session_accept", "session_close", "path_switch", "publish_cc"
    "p" : <body_bytes>       // method-specific payload
}
```

Encrypted with xchacha20-poly1305 using session keys. Sent as message type `0x01` (Control).

### 3.6 Session Data Messages

**NOT BT-encoded** (performance path):
```
[Encrypted(PAYLOAD + TYPE_BYTE)] [SESSION_TAG (4 bytes, big-endian)] [PIVOT_ID (16 bytes)]
```

- Type byte appended to payload BEFORE encryption
- Session tag and pivot ID appended AFTER encryption (consumed by relays, not encrypted)
- Nonce is NOT in the session message — it is part of the path framing layer
- Session tag is big-endian encoded

### 3.7 Path Build Frames

Total size: `8 * 169 = 1352 bytes`

Each frame (169 bytes):
```
BT dict {
    "k" : <32 bytes>     // ephemeral Ed25519 pubkey for DH
    "n" : <24 bytes>     // nonce
    "x" : <encrypted>    // encrypted inner payload
}
```

Inner payload (BT-encoded, 113 bytes after encryption overhead):
```
BT dict {
    "l" : <4 bytes>      // path lifetime in seconds, little-endian uint32
    "r" : <16 bytes>     // rxID
    "t" : <16 bytes>     // txID
    "u" : <32 bytes>     // upstream RouterID
}
```

**Hop ID chaining:**
- Hop 0: rxid = random, txid = random
- Hop N (N>0): rxid = hop[N-1].txid
- Pivot hop: txid = rxid (special case)

**Onion encryption:** After building frame i, encrypt all subsequent REAL frames (not dummies) with `xchacha20(data, hop.shared_secret, dh_nonce ^ hop.xor_nonce)`.

### 3.8 Path Message Framing

Trailer appended to every path message:
```
[nonce (24 bytes)] [hopid (16 bytes)] [msgtype (1 byte)]
```

Message types:
- `0x01` — Data or Control (distinguished by QUIC channel: datagram vs stream)
- `0x02` — SessionHandshake

### 3.9 Bootstrap RC Format

BT-encoded dict:
| Key | Type | Size | Description |
|-----|------|------|-------------|
| `""` | uint8 | 1 | RC version. 0 or omitted = version 0. |
| `"#"` | int | varies | Network ID. 0/omitted = mainnet, 1 = testnet. |
| `"4"` | bytes | 6 | IPv4 (4 bytes network order) + port (2 bytes big-endian). Required. |
| `"6"` | bytes | 18 | IPv6 (16 bytes) + port (2 bytes big-endian). Optional. |
| `"p"` | bytes | 32 | Router Ed25519 public key. |
| `"t"` | uint64 | varies | Timestamp (seconds since Unix epoch). |
| `"v"` | bytes | 3 | Version: MAJOR, MINOR, PATCH as raw bytes. |
| `"~"` | bytes | 64 | Ed25519 signature over BT-encoded prefix. |

**Bootstrap file:** Single RC dict or list of RC dicts. Detect by first byte (`l` = list, `d` = single).

**Bootstrap fetch:** BT dict `{"Z": <zstd_compressed_data>}`. Decompress to list of RC dicts. Max 20MB decompressed.

**Validation:** Max 2048 bytes per RC. 30-day lifetime. 12-hour outdated threshold.

---

## Phase 4: ARCHITECTURE
**Status:** COMPLETE

### Execution Order (strict dependencies)

```
Step 1: Integrate oxenc library
    └─ Step 2: Fix session key derivation
        └─ Step 3: Fix session init/accept messages
            └─ Step 4: Implement session control framing
                └─ Step 5: Fix session data messages
    └─ Step 6: Fix path build frames
        └─ Step 7: Implement path message framing
    └─ Step 8: Implement bootstrap RC parser
Step 9: Two-instance local test (wire format verified here)
```

Steps 2-5 (session) and 6-7 (path) can run in parallel after Step 1.
Step 8 (bootstrap) is independent after Step 1.
Step 9 requires all of 2-8.

**Out of scope (separate issues):**
- oxen-libquic QUIC transport integration (#1233)
- Service node staking and registration (#1234)
- Stagenet connection and network join (#1235)

### Files to Create

| File | Purpose |
|------|---------|
| `rewrite/src/encoding/bt.hpp` | Header for BT encoding utilities (thin wrapper over oxenc) |
| `rewrite/src/encoding/bt.cpp` | BT encoding utilities |
| `rewrite/test/test_bt.cpp` | BT encoding tests |
| `rewrite/test/test_wire_compat.cpp` | Cross-implementation wire format tests |

### Files to Modify

| File | Changes |
|------|---------|
| `rewrite/CMakeLists.txt` | Add oxenc dependency, new source files |
| `rewrite/src/crypto/session_keys.cpp` | Two-phase BLAKE2b derivation, add session tags |
| `rewrite/include/sr/crypto/session_keys.hpp` | Update function signature (add tag params) |
| `rewrite/src/session/session.cpp` | BT-encoded init/accept, control framing, data message format |
| `rewrite/include/sr/session/session.hpp` | Add pivot_id, update message types |
| `rewrite/src/path/path.cpp` | BT-encoded frames, hop ID chaining |
| `rewrite/src/path/onion.cpp` | Path message framing (nonce/hopid/msgtype trailer) |
| `rewrite/include/sr/path/path.hpp` | Add upstream/downstream fields, framing |
| `rewrite/src/contact/relay_contact.cpp` | Add IPv6, network ID, version fields |
| `rewrite/include/sr/contact/relay_contact.hpp` | Add fields to RelayContact struct |
| `rewrite/src/node/config.cpp` | Bootstrap file loading |
| `rewrite/test/test_session_keys.cpp` | Update tests for two-phase derivation |
| `rewrite/test/test_session.cpp` | Update tests for BT-encoded messages |
| `rewrite/test/test_path.cpp` | Update tests for BT-encoded frames |
| `rewrite/test/test_relay_contact.cpp` | Add IPv6, netid, version tests |

### Build Changes

Add to CMakeLists.txt:
```cmake
# oxen-encoding (BT encode/decode + signature helpers)
add_subdirectory(external/oxen-encoding)
target_link_libraries(session-router PRIVATE oxenc)
```

### Test Strategy

1. **Unit tests per step:** Each step gets tests that verify byte-identical output to upstream spec
2. **Test vectors:** Extract from upstream test suite where available, construct manually where not
3. **Key derivation test:** Known inputs → known output. This is the most critical test. One wrong byte = silent failure.
4. **Round-trip tests:** Encode → decode → verify fields match
5. **Integration test (Step 9):** Two instances, full session establishment, send data, verify receipt

---

## Phase 5: VALIDATION
**Status:** COMPLETE

### Checklist

- [x] **Alignment:** Vision → specs → architecture consistent. Every spec item has a corresponding architecture step and file change.
- [x] **Completeness:** Every mismatch from the research doc is addressed. No mismatch is deferred.
- [x] **Feasibility:** oxenc is available, crypto primitives are the same (libsodium), build system supports additions.
- [x] **Risk:** Signature scope is the highest risk — mitigated by using oxenc's `append_signature` directly. Key derivation risk mitigated by test vectors.
- [x] **Scope:** 10 steps, 4 new files, 15 modified files. No architectural changes to the 6-layer structure — only serialization changes within existing modules.
- [x] **Coding plan:** Execution order defined with dependencies. Parallel paths identified (session vs path vs bootstrap).

### Validation Gates

| Gate | Check |
|------|-------|
| VG-1 | oxenc integrates and compiles with rewrite |
| VG-2 | Session key derivation test vector passes |
| VG-3 | Session init BT encoding matches upstream byte layout |
| VG-4 | Session accept BT encoding matches upstream byte layout |
| VG-5 | Path build frame is exactly 169 bytes with correct BT structure |
| VG-6 | Path message framing produces correct trailer |
| VG-7 | Bootstrap RC parser reads upstream bootstrap.signed files |
| VG-8 | Two-instance local session establishment succeeds |
| VG-9 | All existing 112 tests still pass (no regressions) |

### HITM Gate
- [ ] **Human approves before coding begins**

---

**End of PLANNING. Awaiting HITM approval to proceed to EXECUTION.**
