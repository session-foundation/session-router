# AAA: Session Router QUIC Layer — Test Suite and Fix

**Issue:** TRUGS-DEVELOPMENT#1281
**Sub-issue:** TRUGS-DEVELOPMENT#1282 (TRUG analysis — COMPLETE)
**Supersedes:** AAA_1234_quic_transport.md (subset — 7 items without data model)
**Status:** PLANNING
**Analysis:** quic_layer.trug.json (37 nodes, 38 edges)

---

## Phase 1: VISION
**Status:** COMPLETE

### What We're Doing

Write a comprehensive test suite for the session-router QUIC transport layer (`src/link/`), then fix everything that fails.

### Why Test-First

The upstream has zero test coverage on its active QUIC namespace (`srouter::link`). Our rewrite's link layer tests (test_manager.cpp, 9 tests) only cover null safety — no actual connections, no lifecycle, no protocol behavior.

Test-first is the right approach because:

1. **Tests are the most valuable contribution.** A test suite that covers the QUIC layer is what prevents the codebase from rotting further. The upstream can't maintain what they can't test.
2. **Tests prove the bugs.** Each known issue becomes a failing test. Undeniable, reproducible, specific.
3. **Tests are non-controversial.** "Here are tests" gets merged. "I rewrote your code" starts a fight.
4. **Tests enable everything else.** Our C++ rewrite validates against the same tests. The Go clean room targets the same behaviors. The security audit verifies against the same assertions.

### What We're Testing

From quic_layer.trug.json analysis, the QUIC layer has 6 connection maps, 2 tickers, 3 ALPN types, a bidirectional dedup algorithm, key verification, 0-RTT support, ordered shutdown, and a dual-loop threading model. All of it untested.

---

## Phase 2: FEASIBILITY
**Status:** COMPLETE

### Can We Test Without a Live Network?

Yes. The Catch2 framework is already in place and all 9 existing test suites pass. The QUIC layer can be tested at three levels:

1. **Unit tests (no network).** Test data structures in isolation: relay_conn winner selection, connection map operations, ALPN constant values, shutdown ordering. These run instantly.

2. **Loopback tests (localhost QUIC).** Create two Endpoint instances on localhost, connect them, and exercise the full lifecycle. This tests real QUIC connections without any external dependency. oxen-libquic supports this — the existing endpoint test proves it compiles and links.

3. **Integration tests (two-node).** Two full Node instances on localhost, building paths, exchanging messages. This is the hardest to set up but tests the full stack.

### Build Dependencies

- Catch2 (already linked)
- oxen-libquic (already linked)
- libsodium (already linked)
- No additional dependencies required

### GO/NO-GO

**GO.** Testing infrastructure exists. No new dependencies. Loopback testing is viable.

---

## Phase 3: SPECIFICATIONS
**Status:** COMPLETE

### Test Categories

Each category maps directly to nodes and edges in quic_layer.trug.json.

#### Category 1: relay_conn Data Structure (Unit)

Tests for the `relay_conn` struct (endpoint.hpp:49-79). No network required.

| # | Test | Verifies | Expected |
|---|------|----------|----------|
| 1.1 | Winner selection: A < B | `relay_conn(true)` when remote < local | `inbound_wins == true` |
| 1.2 | Winner selection: A > B | `relay_conn(false)` when remote > local | `inbound_wins == false` |
| 1.3 | Winner symmetry | Both sides compute same physical winner | A.conn and B.conn point to same direction |
| 1.4 | set_conn inbound only | Set inbound, no outbound | `conn == inbound.get()` |
| 1.5 | set_conn outbound only | Set outbound, no inbound | `conn == outbound.get()` |
| 1.6 | set_conn both — inbound wins | Set both when inbound_wins=true | `conn == inbound.get()` |
| 1.7 | set_conn both — outbound wins | Set both when inbound_wins=false | `conn == outbound.get()` |
| 1.8 | set_conn replaces existing | Set inbound when inbound already exists | Old inbound closed, new inbound set |
| 1.9 | close inbound, outbound remains | Close inbound direction | `conn == outbound.get()` |
| 1.10 | close outbound, inbound remains | Close outbound direction | `conn == inbound.get()` |
| 1.11 | close both | close_all() | `conn == nullptr`, both ptrs null |
| 1.12 | close_redundant — inbound wins | close_redundant() when inbound_wins | outbound closed with errcode 6 |
| 1.13 | close_redundant — outbound wins | close_redundant() when !inbound_wins | inbound closed with errcode 6 |

#### Category 2: Connection Map Operations (Unit)

Tests for the 6-map data model. Mock or minimal Connection objects.

| # | Test | Verifies | Map |
|---|------|----------|-----|
| 2.1 | Relay connection storage | Store and retrieve from relay_conns | relay_conns |
| 2.2 | Relay bidir tracking | Entry added when both directions exist | relay_bidir |
| 2.3 | Pending outbound tracking | Store pre-establishment, remove on establish | pending_outbound |
| 2.4 | Pending outbound dedup | Second connect to same peer reuses pending | pending_outbound |
| 2.5 | Client connection storage | Store outbound edge connections | client_conns |
| 2.6 | Inbound client by CID | Store by ConnectionID, not RouterID | inbound_clients |
| 2.7 | Pending dead tracking | Add with timestamp, retrieve for age check | pending_dead |
| 2.8 | Pending dead resurrection | Remove if relay re-registers | pending_dead |
| 2.9 | get_current_relays | Returns all connected, optionally pending | all relay maps |
| 2.10 | connected_to_relay with pending | Includes pending when flag set | relay_conns + pending |
| 2.11 | relay_connection_counts | Correct breakdown: total, out, in, pending, clients | all maps |
| 2.12 | num_relay_conns no double count | Pending relay already in relay_conns not double counted | relay_conns + pending |

#### Category 3: ALPN Routing (Loopback)

Tests for per-ALPN connection handling. Requires localhost QUIC connections.

| # | Test | Verifies |
|---|------|----------|
| 3.1 | Relay ALPN → relay_conns | Inbound relay connection stored in relay_conns |
| 3.2 | Client ALPN → inbound_clients | Inbound client connection stored in inbound_clients |
| 3.3 | Bootstrap ALPN → untracked | Bootstrap connection NOT stored in any map |
| 3.4 | Relay ALPN timeout | Keep-alive 10s, idle 33s |
| 3.5 | Client ALPN timeout | Keep-alive 20s, idle 63s |
| 3.6 | Bootstrap ALPN timeout | No keep-alive, idle 10s |
| 3.7 | Relay ALPN commands registered | path_build, fetch_rcs, gossip_rc, publish_cc, find_cc, ping |
| 3.8 | Client ALPN commands registered | path_control, session_control only |
| 3.9 | Bootstrap ALPN commands registered | bfetch_rcs only |

#### Category 4: Key Verification (Loopback)

Tests for the TLS key verification callback (endpoint.cpp:130-181).

| # | Test | Verifies |
|---|------|----------|
| 4.1 | Relay ALPN: registered key accepted | Registered RouterID → connection accepted |
| 4.2 | Relay ALPN: unregistered key rejected | Unknown RouterID → connection rejected |
| 4.3 | Relay ALPN: missing key rejected | No key provided → connection rejected |
| 4.4 | Relay ALPN: wrong size key rejected | Key != 32 bytes → connection rejected |
| 4.5 | Relay ALPN: own key rejected | Self-connection → connection rejected |
| 4.6 | Client ALPN: no key accepted | Anonymous client → connection accepted |
| 4.7 | Client ALPN: valid key accepted | Client with key → connection accepted |
| 4.8 | Client ALPN: wrong size key rejected | Invalid key size → connection rejected |

#### Category 5: Bidirectional Dedup (Loopback)

Tests for relay_conn lifecycle with two relay instances.

| # | Test | Verifies |
|---|------|----------|
| 5.1 | Single direction works | A connects to B → A has outbound, B has inbound |
| 5.2 | Both directions established | A→B and B→A both connect → both have relay_conns with 2 entries |
| 5.3 | Bidir tracked | Both directions → relay_bidir has entry with timestamp |
| 5.4 | Winner selected correctly | A < B → A's inbound wins, B's outbound wins |
| 5.5 | Redundant closed after linger | After REDUNDANT_LINGER, loser connection closed with errcode 6 |
| 5.6 | Messages flow on winner | After dedup, commands sent on preferred connection |
| 5.7 | Loser close doesn't disrupt | Closing redundant doesn't affect the winner |

#### Category 6: Connection Lifecycle (Loopback)

Tests for pending → established → closed lifecycle.

| # | Test | Verifies |
|---|------|----------|
| 6.1 | Outbound starts in pending | connect() creates entry in pending_outbound |
| 6.2 | Establishment moves to relay_conns | on_conn_established → moved from pending to relay_conns |
| 6.3 | Establishment moves to client_conns | Client mode: moved from pending to client_conns |
| 6.4 | Failed connection cleaned | Connection fails → removed from pending_outbound |
| 6.5 | Close inbound relay | Relay close → direction removed from relay_conn |
| 6.6 | Close outbound relay | Outbound close → direction removed, conn switches |
| 6.7 | Close both → erase relay_conn | Both directions closed → relay_conn entry removed |
| 6.8 | Close client conn | Client close → removed from client_conns |
| 6.9 | Close inbound client | Relay side: removed from inbound_clients |
| 6.10 | Pre-negotiation failure | ALPN empty → cleaned from pending_outbound |
| 6.11 | Edge conn change callback | Client: on_edge_conn_change called on establish/close |

#### Category 7: Tickers (Loopback)

Tests for the two periodic lifecycle managers.

| # | Test | Verifies |
|---|------|----------|
| 7.1 | Redundancy ticker fires | close_redundant() called every REDUNDANT_LINGER |
| 7.2 | Redundancy closes correct direction | Loser direction closed, winner untouched |
| 7.3 | Redundancy cleans relay_bidir | Entry removed after close |
| 7.4 | Dereg ticker detects unregistered | Newly unregistered relay added to pending_dead |
| 7.5 | Dereg ticker linger period | Connection NOT closed before DEREGGED_LINGER |
| 7.6 | Dereg ticker closes expired | Connection closed after DEREGGED_LINGER |
| 7.7 | Dereg resurrection | Re-registered relay removed from pending_dead without closing |
| 7.8 | Dereg cleans all maps | Dead relay cleaned from relay_conns, pending_outbound, relay_bidir |

#### Category 8: Command Dispatch (Loopback)

Tests for Manager command registration and response handling.

| # | Test | Verifies |
|---|------|----------|
| 8.1 | Send command to connected relay | Command reaches remote, response received |
| 8.2 | Send command initiates connection | Command to unconnected relay creates pending_outbound |
| 8.3 | Response on router loop | Response handler executes in router loop, not network loop |
| 8.4 | Send datagram to connected | Datagram delivered to connected peer |
| 8.5 | Send datagram to unconnected drops | Datagram to unknown peer returns false, no connection initiated |
| 8.6 | Send command while stopping | is_stopping=true → command silently dropped |
| 8.7 | Gossip RC to peers | gossip_rc sends to all relay peers except origin and sender |
| 8.8 | Ping/pong | Ping command returns "pong" |

#### Category 9: Shutdown and Safety (Loopback)

Tests for ordered teardown and lifetime safety.

| # | Test | Verifies |
|---|------|----------|
| 9.1 | Ordered shutdown | All maps cleared in correct order |
| 9.2 | Double stop is safe | stop() called twice, no crash |
| 9.3 | Canary prevents use-after-free | Callback fires after Endpoint destroyed → early return |
| 9.4 | Control stream before loop transfer | Inbound: BTRequestStream queued before data processed |
| 9.5 | Weak_from_this handles death | Connection dies between callback and router loop → no crash |

#### Category 10: 0-RTT (Loopback)

| # | Test | Verifies |
|---|------|----------|
| 10.1 | Ticket stored on first connect | 0-RTT store callback fires, ticket in NodeDB |
| 10.2 | Ticket extracted on reconnect | 0-RTT extract callback returns stored ticket |
| 10.3 | Expired ticket not used | Ticket past expiry → extract returns empty |
| 10.4 | Inbound 0-RTT enabled for relay | enable_inbound_0rtt(0s, 48h) configured |

---

### Test Count Summary

| Category | Tests | Level | Network Required |
|----------|-------|-------|-----------------|
| 1. relay_conn struct | 13 | Unit | No |
| 2. Connection maps | 12 | Unit | No |
| 3. ALPN routing | 9 | Loopback | Yes |
| 4. Key verification | 8 | Loopback | Yes |
| 5. Bidirectional dedup | 7 | Loopback | Yes |
| 6. Connection lifecycle | 11 | Loopback | Yes |
| 7. Tickers | 8 | Loopback | Yes |
| 8. Command dispatch | 8 | Loopback | Yes |
| 9. Shutdown and safety | 5 | Loopback | Yes |
| 10. 0-RTT | 4 | Loopback | Yes |
| **Total** | **85** | | |

---

## Phase 4: ARCHITECTURE
**Status:** COMPLETE

### File Structure

```
rewrite/test/
├── test_relay_conn.cpp      — Category 1: relay_conn struct (unit)
├── test_connection_maps.cpp — Category 2: connection map operations (unit)
├── test_quic_alpn.cpp       — Category 3: ALPN routing (loopback)
├── test_quic_keys.cpp       — Category 4: key verification (loopback)
├── test_quic_dedup.cpp      — Category 5: bidirectional dedup (loopback)
├── test_quic_lifecycle.cpp  — Category 6: connection lifecycle (loopback)
├── test_quic_tickers.cpp    — Category 7: ticker systems (loopback)
├── test_quic_commands.cpp   — Category 8: command dispatch (loopback)
├── test_quic_shutdown.cpp   — Category 9: shutdown and safety (loopback)
├── test_quic_0rtt.cpp       — Category 10: 0-RTT (loopback)
└── helpers/
    └── quic_test_harness.hpp — Shared loopback test infrastructure
```

### Test Harness Design

The loopback tests (categories 3-10) all need the same setup: two QUIC endpoints on localhost that can connect to each other. A shared test harness provides:

```cpp
// quic_test_harness.hpp
struct TestRelay {
    Ed25519KeyPair keys;
    RouterID rid;
    std::unique_ptr<quic::Loop> loop;
    std::shared_ptr<quic::Endpoint> endpoint;
    std::shared_ptr<quic::GNUTLSCreds> creds;
    // + mock NodeDB for registration checks
    // + mock Router for _jq loop transfer
};

struct QuicTestHarness {
    TestRelay relay_a;  // "lower" RouterID
    TestRelay relay_b;  // "higher" RouterID
    // Guarantee: relay_a.rid < relay_b.rid (for winner selection tests)
    
    void connect_a_to_b();
    void connect_b_to_a();
    void wait_established();
    void run_for(std::chrono::milliseconds);
};
```

### Execution Order

1. **Unit tests first** (categories 1-2) — no network, instant, validate data model
2. **Harness** — build the QuicTestHarness
3. **Loopback tests** (categories 3-10) — require harness, test real QUIC behavior
4. **Fix failures** — each failing test becomes a fix commit
5. **Audit** — review all fixes for security implications

### Dependencies on Existing Code

The tests import from:
- `sr/link/endpoint.hpp` — Endpoint class
- `sr/link/manager.hpp` — Manager class
- `sr/crypto/types.hpp` — Ed25519KeyPair, RouterID
- `sr/contact/nodedb.hpp` — NodeDB (mock for registration checks)
- oxen-libquic headers
- Catch2

No new external dependencies.

### CMake Changes

Add to `rewrite/CMakeLists.txt`:
```cmake
add_executable(test_quic
    test/test_relay_conn.cpp
    test/test_connection_maps.cpp
    test/test_quic_alpn.cpp
    test/test_quic_keys.cpp
    test/test_quic_dedup.cpp
    test/test_quic_lifecycle.cpp
    test/test_quic_tickers.cpp
    test/test_quic_commands.cpp
    test/test_quic_shutdown.cpp
    test/test_quic_0rtt.cpp
)
target_link_libraries(test_quic PRIVATE sr_link sr_crypto sr_contact Catch2::Catch2WithMain oxen-quic)
add_test(NAME quic COMMAND test_quic)
```

---

## Phase 5: VALIDATION
**Status:** AWAITING HITM

### Alignment Check

| Check | Status | Notes |
|-------|--------|-------|
| Vision → Specs consistent? | PASS | 85 tests cover all 37 TRUG nodes |
| Enough detail to code? | PASS | Every test has ID, description, expected result |
| Technology choices verified? | PASS | Catch2 + oxen-libquic loopback proven viable |
| Risks identified? | PASS | See below |
| Architecture delivers specs? | PASS | 10 files + 1 harness, no over-engineering |
| Execution order defined? | PASS | Unit → Harness → Loopback → Fix → Audit |

### Risks

| Risk | Mitigation |
|------|------------|
| oxen-libquic loopback may not support two endpoints in same process | Test with separate threads + ports. Fallback: fork to separate processes with pipe IPC. |
| Mock NodeDB may not satisfy all code paths | Start minimal, expand mock as tests reveal requirements |
| Ticker timing tests may be flaky | Use controlled time injection or short timeouts with generous margins |
| Some tests may require upstream code changes to become testable | Document as findings — each is a PR opportunity |

### Coding Plan

| Step | Files | Depends On | Tests |
|------|-------|------------|-------|
| 1 | test_relay_conn.cpp | Nothing | 13 unit tests |
| 2 | test_connection_maps.cpp | Step 1 | 12 unit tests |
| 3 | helpers/quic_test_harness.hpp | Steps 1-2 passing | Harness infrastructure |
| 4 | test_quic_lifecycle.cpp | Harness | 11 lifecycle tests |
| 5 | test_quic_alpn.cpp | Harness | 9 ALPN tests |
| 6 | test_quic_keys.cpp | Harness | 8 key verification tests |
| 7 | test_quic_dedup.cpp | Harness + lifecycle | 7 dedup tests |
| 8 | test_quic_tickers.cpp | Harness + dedup | 8 ticker tests |
| 9 | test_quic_commands.cpp | Harness | 8 command tests |
| 10 | test_quic_shutdown.cpp | Harness | 5 shutdown tests |
| 11 | test_quic_0rtt.cpp | Harness | 4 0-RTT tests |
| 12 | Fix all failures | All tests written | Bug fixes |
| 13 | Audit fixes | All fixes committed | Security review |

---

## Phase 6: CODING
**Status:** NOT STARTED — awaiting HITM approval of Phase 5

---

## Phase 7: TESTING
**Status:** NOT STARTED

The tests ARE the deliverable. Phase 7 validates that:
- All 85 tests compile and run
- Unit tests (25) pass on current code
- Loopback tests document which pass and which fail on current code
- Each failure is traced to a specific code issue
- Fix commits make each test pass

---

## Phase 8: AUDIT
**Status:** NOT STARTED

Each fix commit gets a security review:
- Does the fix introduce new vulnerabilities?
- Does the fix change wire format or crypto behavior?
- Is the fix minimal (no unnecessary changes)?
- Does the fix have its own test?

---

## Phase 9: DEPLOYMENT
**Status:** NOT STARTED

Deliverables:
1. Test suite PR to Xepayac/session-router (our fork)
2. Fix PRs to session-foundation/session-router (upstream)
3. Updated STUDY_session_router_rewrite.md with test results
4. Updated quic_layer.trug.json with findings from test development

---

## Audit — 2026-04-03

### Gaps Found

13 issues identified by cross-referencing 85 tests against 37 TRUG nodes and 38 edges.

#### Missing Test Coverage (10 gaps)

| # | Gap | TRUG Node | Action |
|---|-----|-----------|--------|
| A1 | Threading model (call/call_get, deadlock risk) | threading_model | Add Category 11: Threading (3 tests) |
| A2 | make_control() ALPN dispatch branching | ep_make_control | Add to Category 3: tests 3.10-3.12 |
| A3 | for_each_relay_conn iteration + is_stopping | ep_queries | Add to Category 8: test 8.9 |
| A4 | unique_edge_range() client IP grouping | ep_queries | Add to Category 2: test 2.13 (via public API) |
| A5 | send_command to client by ConnectionID | ep_send_command | Add to Category 8: test 8.10 |
| A6 | testing_client_connect() untracked | ep_special_connect | Add to Category 3: test 3.13 |
| A7 | make_static_secret() determinism | ep_constructor | Add to Category 1: test 1.14 |
| A8 | CONN_CLOSE_REDUNDANT error code recognition | ep_conn_closed | Add to Category 5: test 5.8 |
| A9 | Gossip verify_store dedup decision | mgr_gossip | Add to Category 8: test 8.11 |
| A10 | Bootstrap RC fetch with zstd compression | mgr_register_bootstrap | Add to Category 8: test 8.12 |

#### Structural Issues (3 issues)

| # | Issue | Action |
|---|-------|--------|
| S1 | Category 2 tests can't access private members | Reclassify as loopback tests using public query functions. Or add `friend class QuicTestAccessor;` to Endpoint. |
| S2 | Harness underspecified — mock Router needs _jq, loop(), port allocation, event loop lifetime | Expand harness design in Phase 4 with concrete mock implementations. |
| S3 | Ticker tests timing — REDUNDANT_LINGER=20s, DEREGGED_LINGER=30min too slow for CI | Add `#ifdef TESTING` overrides: REDUNDANT_LINGER=200ms, DEREGGED_LINGER=500ms. Document as required code change. |

### Revised Test Count

| Category | Original | Added | New Total |
|----------|----------|-------|-----------|
| 1. relay_conn struct | 13 | +1 (A7) | 14 |
| 2. Connection maps | 12 | +1 (A4) | 13 |
| 3. ALPN routing | 9 | +4 (A2: 3, A6: 1) | 13 |
| 4. Key verification | 8 | — | 8 |
| 5. Bidirectional dedup | 7 | +1 (A8) | 8 |
| 6. Connection lifecycle | 11 | — | 11 |
| 7. Tickers | 8 | — | 8 |
| 8. Command dispatch | 8 | +4 (A3, A5, A9, A10) | 12 |
| 9. Shutdown and safety | 5 | — | 5 |
| 10. 0-RTT | 4 | — | 4 |
| **11. Threading** | **0** | **+3 (A1)** | **3** |
| **Total** | **85** | **+14** | **99** |

### New Tests Detail

#### Category 11: Threading (NEW — Loopback)

| # | Test | Verifies |
|---|------|----------|
| 11.1 | Network callback transfers to router loop | on_conn_established fires in network loop, state change visible in router loop |
| 11.2 | call_get returns value across loops | get_relay_conn() returns correct value when called from outside router loop |
| 11.3 | Concurrent access doesn't corrupt | Rapid connect/disconnect while querying connection counts |

#### Added Tests

| # | Test | Category | Verifies |
|---|------|----------|----------|
| 1.14 | Static secret determinism | 1 | Same key → same secret, different key → different secret |
| 2.13 | unique_edge_range grouping | 2 | Client with same-subnet edges → returns range, mixed subnets → nullopt |
| 3.10 | make_control inbound creates queue_incoming_stream | 3 | Inbound: stream ID = 0, BTRequestStream type |
| 3.11 | make_control outbound creates open_stream | 3 | Outbound: BTRequestStream with stream_notify |
| 3.12 | make_control relay uses RouterID as remote | 3 | RELAY_ALPN: remote = RouterID. CLIENT_ALPN: remote = ConnectionID |
| 3.13 | testing_client_connect untracked | 3 | Connection not in any map, uses CLIENT_ALPN, no keep_alive |
| 5.8 | CONN_CLOSE_REDUNDANT recognized | 5 | Errcode 6 close doesn't trigger warning log |
| 8.9 | for_each_relay_conn preferred only | 8 | Only preferred connection visited, not both directions |
| 8.10 | send_command to client by CID | 8 | Command reaches inbound client, response on router loop |
| 8.11 | Gossip dedup — known RC not re-gossipped | 8 | Duplicate RC not forwarded to peers |
| 8.12 | Bootstrap fetch returns compressed RCs | 8 | bfetch_rcs returns zstd-compressed BT-encoded RC list |
| 11.1-11.3 | (See Category 11 above) | 11 | Threading correctness |

### Updated Harness Design

```cpp
struct MockJobQueue {
    quic::Loop& loop;  // Actual event loop for call/call_get
    
    template <typename F> void call(F&& f) { loop.call(std::forward<F>(f)); }
    template <typename F> auto call_get(F&& f) { return loop.call_get(std::forward<F>(f)); }
};

struct MockNodeDB {
    std::unordered_set<RouterID> registered;
    std::unordered_map<RouterID, std::vector<unsigned char>> stored_0rtt;
    
    bool is_registered(const RouterID& rid) const { return registered.contains(rid); }
    void store_0rtt(const RouterID& rid, std::vector<unsigned char> data, auto) { stored_0rtt[rid] = std::move(data); }
    std::optional<std::vector<unsigned char>> extract_0rtt(const RouterID& rid) { /*...*/ }
};

struct MockRouter {
    Ed25519KeyPair keys;
    RouterID id;
    bool is_service_node;
    MockJobQueue jq;
    MockNodeDB node_db;
    quic::Address listen_addr;      // localhost:0 (OS-assigned port)
    int edge_conn_changes = 0;      // Counter for on_edge_conn_change calls
    
    quic::Loop& loop() { return jq.loop; }
    void on_edge_conn_change() { ++edge_conn_changes; }
};

struct QuicTestHarness {
    MockRouter router_a;  // Guarantee: router_a.id < router_b.id
    MockRouter router_b;
    link::Manager manager_a;
    link::Manager manager_b;
    
    // Setup: both registered in each other's NodeDB
    QuicTestHarness();
    
    void connect_a_to_b();
    void connect_b_to_a();
    void wait_established(std::chrono::milliseconds timeout = 5s);
    void run_for(std::chrono::milliseconds);
    void tick();  // Advance one event loop cycle on both loops
    
    // For ticker tests:
    static constexpr auto TEST_REDUNDANT_LINGER = 200ms;
    static constexpr auto TEST_DEREGGED_LINGER = 500ms;
};
```

### Port Allocation

Each `MockRouter` binds to `127.0.0.1:0` (OS assigns port). After bind, read actual port via `endpoint->local().port()`. No port conflicts possible.

### Ticker Constants for Testing

Requires one code change — make linger constants configurable:

```cpp
// endpoint.hpp — change from:
inline constexpr auto REDUNDANT_LINGER = 20s;
inline constexpr auto DEREGGED_LINGER = 30min;

// to:
#ifndef SROUTER_TEST_TIMING
inline constexpr auto REDUNDANT_LINGER = 20s;
inline constexpr auto DEREGGED_LINGER = 30min;
#else
inline constexpr auto REDUNDANT_LINGER = 200ms;
inline constexpr auto DEREGGED_LINGER = 500ms;
#endif
```

This is the ONLY required upstream code change for testability.

---

*Analysis source: quic_layer.trug.json (37 nodes, 38 edges)*
*Supersedes: AAA_1234_quic_transport.md*
