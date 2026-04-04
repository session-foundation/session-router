# AUDIT: Wire Format Fix (PR #2, issue/1232-wire-format-fix)

**Auditor:** Claude Code
**Date:** 2026-03-30
**Scope:** 18 files, 2,326 lines changed
**Verdict:** FAIL — 3 critical findings, 2 high findings

---

## 1. Summary

The PR rewrites session-router wire format to be byte-compatible with the upstream Session Network protocol. The crypto key derivation (two-phase BLAKE2b) is correctly implemented. However, three critical wire format mismatches prevent interoperability with the upstream network: session tag encoding uses a 4-byte string instead of a BT integer, onion encryption applies per-frame instead of as a contiguous block, and the SessionAccept signature is never verified.

---

## 2. Critical Findings

### CRITICAL-1: Session tag "t" encoded as 4-byte string, upstream uses BT integer

**Files:** `rewrite/src/session/session.cpp` (SessionInit::seal_for, SessionAccept::seal_for)

The rewrite encodes the session tag "t" as a 4-byte little-endian binary string:
```cpp
uint32_t t = tag_to_uint(tag);
std::array<char, 4> tag_buf;
std::memcpy(tag_buf.data(), &t, 4);
dp.append("t", std::string_view{tag_buf.data(), 4});
```

This produces BT encoding: `1:t4:<4 raw bytes>` (a 4-byte string value).

The upstream encodes "t" as a BT integer:
```cpp
inner_btdp.append("t", _inbound_tag);  // _inbound_tag is uint32_t
```

This produces BT encoding: `1:ti<decimal number>e` (an integer value).

These are completely different wire encodings. A session tag of 0xDEADBEEF would be:
- **Rewrite:** `1:t4:\xef\xbe\xad\xde` (9 bytes)
- **Upstream:** `1:ti3735928559e` (16 bytes)

Every session init and accept message produced by the rewrite will be rejected by upstream nodes.

**Fix:** Change `dp.append("t", string_view{...4 bytes...})` to `dp.append("t", tag_to_uint(tag))` in both SessionInit::seal_for and SessionAccept::seal_for. Update the corresponding unseal methods to use `idc.consume_integer<uint32_t>()` instead of consuming a string.

### CRITICAL-2: Onion encryption applies per-frame instead of contiguous block

**File:** `rewrite/src/path/onion.cpp` (build_onion)

The rewrite encrypts following frames individually:
```cpp
for (size_t j = i + 1; j < n_hops; ++j)
{
    auto other_frame = std::span<std::byte>(
        result.frames.data() + j * BUILD_FRAME_SIZE, BUILD_FRAME_SIZE);
    Nonce onion_nonce = nonce;
    for (size_t k = 0; k < onion_nonce.size(); ++k)
        onion_nonce[k] ^= hop.xor_nonce[k];
    xchacha20_inplace(other_frame, sym_key, onion_nonce);
}
```

The upstream encrypts all following real frames as one contiguous block:
```cpp
crypto::xchacha20(
    rspan.subspan((i + 1) * BUILD_FRAME_SIZE, following_frames * BUILD_FRAME_SIZE),
    hop.shared_secret,
    dh_nonce ^ hop.xor_nonce);
```

XChaCha20 is a stream cipher. The keystream is position-dependent. Encrypting a 507-byte block (3 x 169) produces different output than encrypting three separate 169-byte blocks with the same key and nonce, because in the per-frame approach each frame starts at keystream offset 0, while in the contiguous approach frame 2 starts at offset 169 and frame 3 at offset 338.

This means every path build message with more than 2 hops will be incorrectly encrypted and rejected by upstream relays.

**Fix:** Encrypt all following real frames as a single contiguous span:
```cpp
size_t following = n_hops - 1 - i;
if (following > 0) {
    auto span = std::span<std::byte>(
        result.frames.data() + (i + 1) * BUILD_FRAME_SIZE,
        following * BUILD_FRAME_SIZE);
    xchacha20_inplace(span, sym_key, onion_nonce);
}
```

### CRITICAL-3: SessionAccept signature never verified

**File:** `rewrite/src/session/session.cpp` (SessionAccept::unseal)

The unseal method reads the signature from the "~" field but never verifies it:
```cpp
// "~" -> signature
if (!idc.skip_until("~"))
    return std::nullopt;
auto sig_sv = idc.consume_string_view();
if (sig_sv.size() < 64)
    return std::nullopt;
std::memcpy(sa.signature.data(), sig_sv.data(), 64);

return sa;  // <-- returns without verifying!
```

The upstream verifies the signature against the remote's Ed25519 pubkey:
```cpp
inner_btdc.require_signature("~", [this](std::span<const std::byte> msg, std::span<const std::byte> sig) {
    if (not _remote.pubkey.verify(msg, SignatureView{sig.first<Signature::SIZE>()}))
        throw std::runtime_error{"Failed to verify session_init identity signature"};
});
```

Without signature verification, an attacker who intercepts the sealed box could forge a session accept with arbitrary keys, leading to a man-in-the-middle attack. The SessionInit::unseal correctly verifies signatures; SessionAccept must do the same.

**Fix:** Add `verify_signature(inner_str, <receiver_pubkey>)` call before returning. Note that SessionAccept::unseal does not currently receive the expected remote pubkey as a parameter — the API needs extending to accept it.

---

## 3. High Findings

### HIGH-1: Tag endianness in key derivation is platform-dependent

**File:** `rewrite/src/crypto/session_keys.cpp`

The rewrite hashes the tag directly from memory:
```cpp
crypto_generichash_update(&state, reinterpret_cast<const unsigned char*>(&tag_i), 4);
```

The upstream explicitly converts to little-endian:
```cpp
oxenc::write_host_as_little(tag_i, tag_i_bytes.data());
hash_add(st, ..., tag_i_bytes, tag_r_bytes);
```

On x86/AMD64 (little-endian), these produce the same bytes. On a big-endian platform, the rewrite would hash different bytes than the upstream. While the Session Network is primarily x86, this is a portability bug that silently breaks key derivation on big-endian architectures.

**Fix:** Explicitly convert to little-endian before hashing:
```cpp
uint32_t tag_i_le = htole32(tag_i);
crypto_generichash_update(&state, reinterpret_cast<const unsigned char*>(&tag_i_le), 4);
```

### HIGH-2: Session data tag described as "big-endian" but stored as raw bytes

**Files:** `rewrite/include/sr/session/session.hpp`, `rewrite/src/session/session.cpp`

The header comments say `[SESSION_TAG 4 bytes BE]` but the tag is stored as `std::array<std::byte, 4>` and copied directly to the wire:
```cpp
msg.insert(msg.end(), _tag.begin(), _tag.end());
```

The upstream explicitly writes the tag in big-endian:
```cpp
oxenc::write_host_as_big(_outbound_tag, tag_span.data());
```

In the upstream, `session_tag` is `uint32_t` and is explicitly converted to big-endian before writing to the wire. In the rewrite, `SessionTag` is `std::array<std::byte, 4>` which is just raw bytes — no endianness conversion happens.

If the tag value is generated randomly (as 4 random bytes), then the byte order doesn't matter because both sides see the same raw bytes. However, the tag is also used as `uint32_t` in key derivation (via `tag_to_uint`), and the upstream writes it as big-endian on the wire but uses the host-endian value for key derivation. The rewrite writes the raw bytes (which are host-endian from `uint_to_tag`) — this means the wire format of the session tag in data messages differs from upstream.

**Fix:** Either match the upstream by using `uint32_t` for tags with explicit big-endian wire encoding, or ensure that `tag_to_uint` and `uint_to_tag` account for the endianness difference.

---

## 4. Medium Findings

### MEDIUM-1: `to_bt_signed` manually constructs BT signature instead of using `append_signature`

**File:** `rewrite/src/contact/relay_contact.cpp`

The `to_bt_signed` method manually appends the signature:
```cpp
unsigned_str.append("1:~");
unsigned_str.append("64:");
unsigned_str.append(reinterpret_cast<const char*>(_sig.data()), 64);
unsigned_str.append("e");
```

This bypasses the `append_signature` helper function used elsewhere. While functionally equivalent, it creates a maintenance risk — if the signature encoding changes, this code would be missed. It also doesn't re-sign; it just appends the stored signature, which may be stale if any fields changed after signing.

### MEDIUM-2: `find_dict_end` BT parser is fragile

**File:** `rewrite/src/contact/relay_contact.cpp`

The `find_dict_end` helper used by `from_bootstrap` implements a minimal BT parser. It doesn't handle negative integers (`i-123e`), and integer overflow in string length parsing could cause issues. This parser should be replaced with oxenc's BT parsing capabilities.

### MEDIUM-3: `get_signable_prefix` uses `rfind` which could match within binary data

**File:** `rewrite/src/encoding/bt.cpp`

The function finds the signature key by searching for `"1:~"` backwards through the string:
```cpp
auto pos = bt_dict.rfind("1:~");
```

If a binary value in the dict happens to contain the bytes `1:~`, this would find the wrong position. The upstream uses structured parsing (`require_signature` / `append_signature`) that doesn't have this problem. For the current message types this is unlikely to be hit in practice, but it's a latent bug.

### MEDIUM-4: `build_frame` pads with zeros if frame is shorter than BUILD_FRAME_SIZE

**File:** `rewrite/src/path/onion.cpp`

```cpp
if (frame_str.size() < BUILD_FRAME_SIZE)
    std::memset(frame_out + frame_str.size(), 0, BUILD_FRAME_SIZE - frame_str.size());
```

The upstream asserts frame size is exactly 169 and throws if it isn't. Zero-padding would silently produce an invalid frame that no relay could parse. This should be an assertion/error, not silent padding.

---

## 5. Low Findings

### LOW-1: Unused helper functions in `bt.hpp`

The `append_bytes`, `append_le4`, and `read_le4` helper functions are defined but unused in the codebase. The code manually performs the same operations inline.

### LOW-2: `strip_path_trailer` uses `const_cast`

**File:** `rewrite/src/path/onion.cpp`

```cpp
payload_out = std::span<std::byte>(const_cast<std::byte*>(msg.data()), payload_len);
```

This casts away const from the input span, which is a code smell. The function signature should be redesigned to avoid this.

### LOW-3: Missing `#include <arpa/inet.h>` in relay_contact.cpp

The rewrite uses `htons`/`ntohs` but relies on transitive includes for `arpa/inet.h`. This was added to `test_relay_contact.cpp` but not to the source file itself.

---

## 6. Per-File Review

| # | File | Assessment |
|---|------|-----------|
| 1 | `rewrite/src/crypto/session_keys.cpp` | **CONDITIONAL** — Two-phase BLAKE2b is correct. Phase 1 domain, data order, Phase 2 data order all match upstream. HIGH-1 (endianness) is a portability issue. |
| 2 | `rewrite/src/session/session.cpp` | **FAIL** — CRITICAL-1 (tag encoding), CRITICAL-3 (no sig verify on accept), HIGH-2 (tag endianness on wire). Session data format structure is correct (encrypted + tag + pivot). SessionControl BT format matches spec. |
| 3 | `rewrite/src/path/onion.cpp` | **FAIL** — CRITICAL-2 (per-frame vs contiguous onion). Inner BT payload keys (l, r, t, u) and sizes match upstream. Frame BT structure (k, n, x) matches upstream. Hop ID chaining logic is correct. Path trailer format is correct. |
| 4 | `rewrite/src/contact/relay_contact.cpp` | **PASS** — BT key ordering matches upstream ("", "#", "4", "6", "p", "t", "v", "~"). IPv4/IPv6 encoding matches. Network ID encoding matches. Bootstrap format detection (l vs d) is reasonable. |
| 5 | `rewrite/src/encoding/bt.cpp` | **CONDITIONAL** — MEDIUM-3 (rfind vulnerability). Signature append/verify logic is correct. |
| 6 | `rewrite/src/encoding/bt.hpp` | **PASS** — Clean wrapper over oxenc. |
| 7 | `rewrite/include/sr/session/session.hpp` | **PASS** — API properly extended with PivotID, Nonce parameter, SessionControl. |
| 8 | `rewrite/include/sr/crypto/session_keys.hpp` | **PASS** — Correct signature with tag_i/tag_r parameters. |
| 9 | `rewrite/include/sr/crypto/bt.hpp` | **PASS** — Backward compatibility re-export. |
| 10 | `rewrite/include/sr/path/onion.hpp` | **PASS** — Correct constants (169, 41). Correct message types. |
| 11 | `rewrite/include/sr/contact/relay_contact.hpp` | **PASS** — Correct constants (RC_MAX_SIZE=2048). IPv6 support. |
| 12 | `rewrite/CMakeLists.txt` | **PASS** — sr_encoding library correctly integrated, linked to all dependent targets. |
| 13 | `rewrite/test/test_wire_compat.cpp` | **CONDITIONAL** — Tests verify round-trip but do not catch CRITICAL-1 because both encode and decode use the same wrong format. See section 8. |
| 14 | `rewrite/test/test_session.cpp` | **PASS** — Good coverage of new APIs. |
| 15 | `rewrite/test/test_session_keys.cpp` | **PASS** — Tests verify both sides agree, tag sensitivity, domain length. |
| 16 | `rewrite/test/test_onion.cpp` | **CONDITIONAL** — Tests verify hop chaining and framing but do not catch CRITICAL-2 because they only test single-hop decrypt, not multi-hop onion peel. |
| 17 | `rewrite/test/test_relay_contact.cpp` | **PASS** — Good coverage including IPv6, network ID, max size, error cases. |
| 18 | `AAA_1232_wire_format_fix.md` | N/A — Planning document. |

---

## 7. Comparison with Upstream

| Message Type | Rewrite Match? | Issues |
|-------------|---------------|--------|
| **Session Init (outer)** | YES | `{"":"i", "B":sealed}` matches upstream |
| **Session Init (inner)** | **NO** | "t" field encoding differs (string vs integer) — CRITICAL-1 |
| **Session Accept (outer)** | YES | `{"":"a", "B":sealed}` matches upstream |
| **Session Accept (inner)** | **NO** | "t" field encoding differs — CRITICAL-1. Signature not verified — CRITICAL-3 |
| **Session Control** | YES | `{"e":method, "p":body}` matches upstream |
| **Session Data** | **PARTIAL** | Structure [encrypted][tag][pivot] matches, but tag endianness differs — HIGH-2 |
| **Path Build Frame (outer)** | YES | `{"k":pk, "n":nonce, "x":encrypted}` matches upstream |
| **Path Build Frame (inner)** | YES | `{"l":lifetime, "r":rxid, "t":txid, "u":upstream}` matches upstream |
| **Path Build Onion** | **NO** | Per-frame encryption vs contiguous — CRITICAL-2 |
| **Path Message Trailer** | YES | [nonce 24][hopid 16][msgtype 1] matches upstream |
| **Relay Contact** | YES | All fields match upstream encoding |
| **Bootstrap RC** | YES | First-byte detection matches upstream |
| **Key Derivation (Phase 1)** | YES | Domain, data order match. Tag endianness — HIGH-1 |
| **Key Derivation (Phase 2)** | YES | DH, X, Y, k_s, M order matches upstream |
| **Key Assignment** | YES | Initiator k1/k2, receiver k2/k1 matches upstream |

---

## 8. Test Coverage Assessment

The PR adds 18 test cases in `test_wire_compat.cpp` plus updates to existing test files. Total new test cases: ~35.

**Strengths:**
- BT dict key ordering verification
- Signature round-trip (append + verify + wrong-key rejection)
- Session key derivation agreement between both sides
- SessionInit/Accept full round-trip (seal + unseal)
- Path build frame format (BT dict structure)
- Hop ID chaining (3-hop, pivot constraint)
- Path trailer size and message type
- RC round-trip with IPv6, network ID
- Bootstrap format parsing (single dict, list)
- RC max size enforcement
- Error handling (garbage input, empty input)

**Gaps (critical):**
1. **No cross-implementation test.** All round-trip tests encode and decode with the rewrite. This masks CRITICAL-1 (tag encoding) because both sides use the same wrong format.
2. **No multi-hop onion peel test.** The tests verify single-frame decryption but never test a complete multi-hop scenario where hop 2 de-onions hop 3's frame. This masks CRITICAL-2.
3. **No byte-level format comparison against known upstream vectors.** The tests should include at least one hardcoded upstream-produced byte sequence for each message type and verify the rewrite can parse it.
4. **No signature verification test for SessionAccept.** The SessionInit tests verify signatures work, but there is no test that SessionAccept rejects a forged signature.

**Missing tests:**
- Session data message encrypt/decrypt with the SAME nonce as path layer (the upstream reuses nonces)
- Large payload handling (path build with 4+ hops)
- BT dict with unknown/extra keys (forward compatibility)
- RC signature verification after parsing

---

## 9. Recommendations

### Must fix before merging (blockers):

1. **CRITICAL-1:** Change session tag "t" to BT integer encoding in both SessionInit and SessionAccept (seal and unseal).

2. **CRITICAL-2:** Change onion encryption to encrypt all following real frames as a single contiguous span, matching upstream's behavior.

3. **CRITICAL-3:** Add signature verification to `SessionAccept::unseal`. The method needs the expected remote pubkey as a parameter.

4. **HIGH-2:** Use explicit big-endian encoding for session tag on the wire in data messages, matching `oxenc::write_host_as_big`.

### Should fix before merging (recommended):

5. **HIGH-1:** Use explicit `htole32` for tag bytes in key derivation instead of relying on platform endianness.

6. Add cross-implementation tests: hardcode a known upstream-produced byte sequence for at least SessionInit, SessionAccept, and a 3-hop path build, and verify the rewrite can parse them.

7. Add a multi-hop onion build+decrypt integration test that verifies all hops can peel their layer.

8. Change `build_frame` padding to an assertion/error instead of silent zero-padding (MEDIUM-4).

### Nice to have (post-merge):

9. Replace `rfind("1:~")` in `get_signable_prefix` with structured parsing (MEDIUM-3).

10. Replace manual BT parser in `find_dict_end` with oxenc utilities (MEDIUM-2).

11. Remove `const_cast` in `strip_path_trailer` (LOW-2).
