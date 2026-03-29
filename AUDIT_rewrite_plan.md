# Session Router Rewrite — Full Audit Plan

**Target:** SESSION_ROUTER/rewrite/ (~5,000 lines C++20)
**Purpose:** Verify the rewrite is production-ready before deployment as a service node
**Standard:** GUIDE_professional_code.md + security audit for crypto network software

---

## Audit Scope

| Area | What's Audited | Risk Level |
|------|---------------|-----------|
| Cryptographic correctness | All libsodium calls match upstream wire format | CRITICAL |
| Wire compatibility | BT-encoding, frame sizes, ALPN strings interoperate | CRITICAL |
| Memory safety | No UB, no leaks, no use-after-free | HIGH |
| Thread safety | Atomic operations, mutex discipline, no races | HIGH |
| Network security | No injection, no MITM, proper TLS | HIGH |
| Key management | Generation, storage, permissions, zeroing | HIGH |
| Error handling | No silent failures, no swallowed exceptions | MEDIUM |
| Test coverage | All layers tested, edge cases covered | MEDIUM |
| Build system | Correct dependencies, reproducible builds | LOW |
| Code quality | Naming, formatting, documentation | LOW |

---

## Phase 1: Static Analysis (no execution)

### 1.1 Automated Scanning

| Tool | What It Checks | Command |
|------|---------------|---------|
| clang-tidy | C++ anti-patterns, modernize, bugprone | `clang-tidy src/**/*.cpp -- -std=c++20` |
| cppcheck | Buffer overflows, null deref, leaks | `cppcheck --enable=all src/ include/` |
| scan-build | Clang static analyzer | `scan-build cmake .. && scan-build make` |
| AddressSanitizer | Memory errors at runtime | Build with `-fsanitize=address` |
| UBSanitizer | Undefined behavior | Build with `-fsanitize=undefined` |
| ThreadSanitizer | Data races | Build with `-fsanitize=thread` |

### 1.2 Manual Code Review Checklist

For every source file:

**Crypto (Layer 0)**
- [ ] Every `crypto_sign_*`, `crypto_box_*`, `crypto_aead_*` call has correct buffer sizes
- [ ] Every `crypto_scalarmult` result is checked for zero (low-order point)
- [ ] `sodium_memzero` called on all temporary secret key material
- [ ] No secret key material logged, printed, or returned in error messages
- [ ] DH hash order matches upstream: `blake2b(nonce_key, client_pk || server_pk || dh)`
- [ ] Session key k1/k2 swap: initiator `(out=k1, in=k2)`, receiver `(out=k2, in=k1)`
- [ ] Nonce reuse prevention: counter-based nonce in Session, random in path build
- [ ] ML-KEM placeholder clearly marked and gated behind build flag

**Contact (Layer 1)**
- [ ] BT-encoding field order matches upstream: "4", "p", "t", "v", "~"
- [ ] Port encoding uses `htons`/`ntohs` (not `htonl`)
- [ ] RC signature verification uses the RC's own pubkey, not a stored key
- [ ] NodeDB mutex protects all member access
- [ ] Bucket hash XOR logic matches upstream (byte 16, & 0x7F)
- [ ] Reservoir sampling is unbiased

**Path (Layer 2)**
- [ ] Onion frames encrypted in reverse order (pivot to edge)
- [ ] Nonce XOR chain: pre-computed for encrypt, applied incrementally for decrypt
- [ ] Frame size is exactly BUILD_FRAME_SIZE (169) bytes
- [ ] Total message is BUILD_LENGTH (8) frames, including dummy frames
- [ ] Dummy frames filled with random data (not zeros)
- [ ] `decrypt_build_frame` uses correct DH role (we=server, they=client)
- [ ] Path lifetime fuzz is 0-180 seconds (not 0-3 steps)

**Session (Layer 3)**
- [ ] Sealed box uses Ed25519→X25519 conversion correctly
- [ ] SessionInit/SessionAccept serialization sizes match expected wire format
- [ ] Nonce counter is atomic (thread-safe)
- [ ] Session encrypt appends type byte, decrypt strips it
- [ ] Empty plaintext encrypt/decrypt works correctly

**Link (Layer 4)**
- [ ] ALPN strings match upstream: "Session_Router_R", "_C", "_BS"
- [ ] GnuTLS credentials created from Ed25519 seed (not pubkey)
- [ ] Connection map protected by mutex
- [ ] Callbacks don't capture raw `this` without lifetime guarantee
- [ ] Send to disconnected peer is a no-op (not a crash)
- [ ] Datagram splitting enabled with 2MB queue limit

**Node (Layer 5)**
- [ ] Key file written with 0600 permissions
- [ ] Tilde expansion in data_dir path
- [ ] Config --relay flag survives --config file loading
- [ ] TUN device failure doesn't crash (relay-only mode continues)
- [ ] Signal handler sets atomic flag (no complex logic in handler)
- [ ] Tick loop doesn't busy-wait (sleeps between ticks)

**Exit (v1.1)**
- [ ] NAT port wraparound at 65534 (not overflow)
- [ ] NAT entry expiry prevents unbounded growth
- [ ] Route management validates interface names (no shell injection)
- [ ] IP forwarding enabled via /proc (not shell command)
- [ ] iptables rules cleaned up on teardown

---

## Phase 2: Dynamic Analysis (with execution)

### 2.1 Sanitizer Test Runs

```bash
# AddressSanitizer
cmake -S rewrite -B build-asan -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer"
make -C build-asan -j$(nproc) && cd build-asan && ctest

# UndefinedBehaviorSanitizer
cmake -S rewrite -B build-ubsan -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_CXX_FLAGS="-fsanitize=undefined"
make -C build-ubsan -j$(nproc) && cd build-ubsan && ctest

# ThreadSanitizer
cmake -S rewrite -B build-tsan -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_CXX_FLAGS="-fsanitize=thread"
make -C build-tsan -j$(nproc) && cd build-tsan && ctest
```

### 2.2 Fuzz Testing

| Target | What's Fuzzed | Input |
|--------|-------------|-------|
| `RelayContact::from_bt` | BT parsing | Random bytes |
| `decrypt_build_frame` | Path build frame parsing | Random 169-byte frames |
| `Session::decrypt` | Session message parsing | Random encrypted blobs |
| `aead_decrypt` | AEAD MAC verification | Random ciphertext |
| `unseal` | Sealed box decryption | Random sealed data |

```cpp
// Example fuzz target for libFuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    sr::contact::RelayContact::from_bt(
        {reinterpret_cast<const std::byte*>(data), size});
    return 0;
}
```

### 2.3 Integration Testing

| Test | What's Verified | Requires |
|------|----------------|----------|
| Connect to upstream node | QUIC handshake, ALPN negotiation | Live network |
| Bootstrap RC fetch | Fetch RCs from bootstrap nodes | Live network |
| Path build end-to-end | Build a 3-hop path through real relays | Live network + root |
| Session establishment | Full handshake with a real session-router node | Live network + root |
| Packet round-trip | Send IP packet through onion path, receive response | Live network + root |
| Exit traffic | Route packet to internet via exit node | Live network + root + exit node |

---

## Phase 3: Wire Compatibility Verification

### 3.1 Cross-Implementation Testing

Run both our binary and upstream session-router side by side:

| Test | Method |
|------|--------|
| RC serialization | Serialize RC, parse with upstream code, compare |
| Path build frame | Build onion, send to upstream relay, verify it accepts |
| Session init | Send sealed box init to upstream node, verify handshake |
| Session data | Exchange encrypted packets between implementations |
| RC gossip | Gossip an RC, verify upstream stores it |
| Bucket hashes | Compare bucket hashes between implementations for same RC set |

### 3.2 Wire Format Validation

For each message type, capture with packet dump and verify:

| Message | Size | Encoding | Crypto |
|---------|------|----------|--------|
| path_build | 1352 bytes | 8 × 169B frames | xchacha20 per-hop |
| session_init | Variable | Sealed box + BT | Ed25519→X25519 |
| session_data | Variable | AEAD + onion layers | xchacha20-poly1305 |
| gossip_rc | ≤2048 | BT dict | Ed25519 signature |
| path_control | Variable | AEAD + BT | xchacha20-poly1305 |
| bfetch_rcs | Variable | zstd + BT list | None |
| fetch_rcs | Variable | 128 × 8B hashes | None |

---

## Phase 4: Security-Specific Checks

### 4.1 Cryptographic Review

| Property | How to Verify |
|----------|--------------|
| No nonce reuse | Counter-based (session), random (path build) — verify no overflow/collision |
| Forward secrecy | Ephemeral X25519 + ML-KEM per session — verify keys destroyed after derivation |
| Key separation | Different keys for different purposes — verify domain separation strings |
| Side channels | No timing differences on crypto failure paths — verify constant-time operations |
| Entropy quality | All randomness from libsodium CSRNG — verify no `rand()` or `std::rand()` |

### 4.2 Network Attack Surface

| Attack | Mitigation | Verify |
|--------|-----------|--------|
| Malformed packet | All parsers return nullopt on bad input | Fuzz testing |
| Memory exhaustion | Transit hops have max lifetime, NAT entries expire | Load test |
| Connection flood | QUIC handles this at transport layer | Stress test |
| Path build flood | Rate limiting on path builds | Not yet implemented — flag for v1.1 |
| RC poisoning | Signature verification on all RCs | Unit tested |
| Replay attack | Nonce counter prevents session replay | Verify counter never resets |

### 4.3 Key Material Handling

| Check | File | Expected |
|-------|------|----------|
| Key file permissions | node.cpp | 0600 (owner read/write only) |
| Key material zeroed | dh.cpp, blind.cpp, sealed_box.cpp, session_keys.cpp | sodium_memzero on all temporaries |
| No key in logs | All files | grep for sk, secret, key in log/print statements |
| No key in errors | All files | Error messages don't include key material |

---

## Phase 5: Performance Baseline

| Metric | Target | How to Measure |
|--------|--------|---------------|
| Path build latency | < 10s (matches upstream timeout) | Time from build_onion to response |
| Session handshake | < 5s | Time from init to established |
| Packet throughput | > 10 Mbps through 3-hop path | iperf through tunnel |
| Memory usage | < 100 MB idle, < 500 MB under load | /proc/pid/status |
| CPU usage | < 10% idle | top/htop |
| RC gossip convergence | < 5 minutes for new RC | Time from publish to network-wide |

---

## Phase 6: Deployment Readiness

### 6.1 Pre-Deployment Checklist

- [ ] All sanitizers pass with zero findings
- [ ] All 112+ tests pass
- [ ] Fuzz targets run for >1 hour with zero crashes
- [ ] Integration test against live network succeeds
- [ ] Wire compatibility verified against upstream session-router
- [ ] Key management verified (permissions, zeroing, no leaks)
- [ ] Exit mode iptables rules verified (setup and teardown)
- [ ] Performance baseline meets targets
- [ ] README is accurate (build, test, run instructions work)
- [ ] Professional code checklist complete (all 11 steps)

### 6.2 Ongoing Monitoring (Post-Deployment)

- [ ] Uptime monitoring (service node stays registered)
- [ ] Path build success rate (> 90%)
- [ ] Session establishment rate (> 95%)
- [ ] Memory growth over 24h (should be stable)
- [ ] RC count stability (stays above MIN_ACTIVE_RCS)
- [ ] Exit traffic throughput (if exit mode enabled)

---

## Audit Results Template

```
## Audit Results — YYYY-MM-DD

### Summary
- Files audited: N
- Lines audited: N
- Findings: N critical, N high, N medium, N low
- Tests: N pass, N fail
- Sanitizer: clean / N findings

### Critical Findings
(none expected — must be zero before deployment)

### High Findings
1. [FILE:LINE] Description — Fix: ...

### Medium Findings
1. [FILE:LINE] Description — Fix: ...

### Low Findings
1. [FILE:LINE] Description — Fix or accept: ...

### Sign-off
- [ ] Auditor: ___
- [ ] Developer: ___
- [ ] Deployer: ___
```

---

## Tools Required

| Tool | Install | Purpose |
|------|---------|---------|
| clang-tidy | `sudo apt install clang-tidy` | Static analysis |
| cppcheck | `sudo apt install cppcheck` | Static analysis |
| libFuzzer | Built into clang | Fuzz testing |
| valgrind | `sudo apt install valgrind` | Memory checking |
| tcpdump/wireshark | `sudo apt install tcpdump` | Wire format capture |
| iperf3 | `sudo apt install iperf3` | Throughput testing |

---

*This audit plan covers the full lifecycle from code review through deployment.
Each phase can be executed independently. Phases 1-2 can run without network access.
Phases 3-5 require a live Session network. Phase 6 is post-deployment.*
