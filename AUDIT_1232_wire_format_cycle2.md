# AUDIT Cycle 2: Wire Format Fix (PR #2, issue/1232-wire-format-fix)

**Auditor:** Claude Code
**Date:** 2026-03-30
**Scope:** Full codebase re-audit after fixing 5 findings from Cycle 1
**Verdict:** PASS — No CRITICAL or HIGH findings remain

---

## 1. Cycle 1 Fix Verification

### CRITICAL-1: Session tag "t" BT integer encoding — VERIFIED FIXED

**SessionInit::seal_for** (line 117): `dp.append("t", static_cast<uint64_t>(tag_to_uint(tag)))` — produces `1:ti<decimal>e`, matching upstream's BT integer encoding.

**SessionInit::unseal** (line 215): `idc.consume_integer<uint32_t>()` — correctly reads a BT integer and converts to uint32_t.

**SessionAccept::seal_for** (line 253): Same integer encoding pattern. Correct.

**SessionAccept::unseal** (line 331): Same integer reading pattern. Correct.

**Signature scope analysis:** The `pop_back()` approach still works correctly. With integer "t", the dict ends `...1:ti<decimal>ee` — the last 'e' closes the dict, the second-to-last closes the integer. `pop_back()` removes only the dict-closing 'e', preserving the integer's closing 'e'. The signable prefix is correct.

**Verified:** `get_signable_prefix` uses `rfind("1:~")` which correctly finds the signature key after the integer-encoded "t" field. No conflict.

### CRITICAL-2: Contiguous onion encryption — VERIFIED FIXED

**build_onion** (lines 167-180): The fix correctly computes `following = n_hops - 1 - i` and encrypts a single contiguous span of `following * BUILD_FRAME_SIZE` bytes. This matches upstream behavior where all following real frames are encrypted as one block, ensuring the XChaCha20 keystream is continuous across frame boundaries.

**Edge case: i == n_hops - 1 (pivot):** `following = 0`, so the block is skipped. Correct — the pivot has no subsequent frames.

**Edge case: i == 0 (edge), 3 hops:** `following = 2`, encrypts frames 1 and 2 as a 338-byte contiguous block. Correct.

### CRITICAL-3: SessionAccept signature verification — VERIFIED FIXED

**SessionAccept::unseal** (lines 342-344): Now calls `verify_signature(inner_str, as_uchar(remote_pk))` before returning, exactly matching the pattern in `SessionInit::unseal`.

**API change:** The function signature now requires `remote_pk` as the 4th parameter. All callers updated (test_session.cpp line 134).

**Signature scope:** `inner_str` is constructed from `inner_sv` which is the full unsealed inner BT dict. `verify_signature` extracts the prefix (everything before "1:~") and verifies the Ed25519 signature against `remote_pk`. Correct.

### HIGH-1: Explicit little-endian tags in key derivation — VERIFIED FIXED

**session_keys.cpp** (lines 49-53): `htole32(tag_i)` and `htole32(tag_r)` before hashing. On little-endian platforms (x86/AMD64), `htole32` is a no-op, so existing behavior is preserved. On big-endian platforms, bytes are swapped to match upstream's `write_host_as_little` convention.

**Include:** `<endian.h>` added at line 5. Correct for Linux/glibc.

### HIGH-2: Big-endian session data tag on wire — VERIFIED FIXED

**Session::encrypt** (lines 69-71): `htobe32(tag_to_uint(_tag))` converts the host-endian uint32 to big-endian before writing to wire. This matches upstream's `write_host_as_big` convention.

**Session::decrypt** (lines 86-89): The decrypt path strips 4+16 bytes from the end without interpreting the tag value, so no endianness conversion needed on the read side (the tag is just stripped, not parsed for lookup). Correct.

**Include:** `<endian.h>` added at line 6. Correct.

---

## 2. New Issue Check — Did Fixes Introduce Problems?

### Checked: Integer overflow in consume_integer<uint32_t>

If the BT integer value exceeds UINT32_MAX, `consume_integer<uint32_t>()` from oxenc will throw. The catch(...) handlers in both unseal methods will convert this to `std::nullopt`. This is correct behavior — an out-of-range tag should be rejected.

### Checked: tag_to_uint / uint_to_tag consistency

`tag_to_uint` copies 4 raw bytes to uint32_t (host-endian). `uint_to_tag` copies uint32_t bytes back. These are symmetric. The BT integer encoding uses the numeric value (not raw bytes), so the round-trip is: `tag bytes -> memcpy -> uint32_t(host) -> BT integer(decimal) -> consume_integer -> uint32_t(host) -> memcpy -> tag bytes`. This is correct regardless of platform endianness because the intermediate BT format uses decimal text.

### Checked: htobe32 / htole32 portability

Both `<endian.h>` functions are POSIX (Linux, glibc, musl, BSDs). Not available on Windows. Since this is a Linux-targeted project (session network routers run on Linux), this is acceptable.

### Checked: SessionAccept::unseal remote_pk parameter

The API breaking change is intentional. Any caller that previously called `SessionAccept::unseal(data, pk, sk)` will now get a compile error, forcing them to provide the remote public key. This is a safety improvement — it's impossible to accidentally skip signature verification.

---

## 3. Full Codebase Re-Audit

### session.cpp — PASS

- **SessionInit seal/unseal:** BT format correct. Integer "t" matches upstream. Signature verified against identity pubkey. Sealed box wrapping correct.
- **SessionAccept seal/unseal:** BT format correct. Integer "t" matches upstream. Signature now verified against remote_pk. API requires explicit remote key.
- **Session encrypt:** AEAD encrypt correct. Tag written big-endian. Pivot ID appended raw. Format: [ct][tag_be_4][pivot_16].
- **Session decrypt:** Correctly strips 4+16 from end. AEAD decrypt with key_in. Type byte stripped. Size check includes AEAD_TAG_SIZE.
- **SessionControl:** BT format {"e":method, "p":body} correct. Round-trip verified by tests.

### onion.cpp — PASS

- **build_inner_bt:** Keys in correct BT sort order (l < r < t < u). Lifetime as 4-byte LE string. HopIDs as 16-byte strings. Upstream RouterID as 32-byte string. All match upstream.
- **build_frame:** Keys in correct order (k < n < x). Ephemeral PK 32 bytes, nonce 24 bytes, encrypted inner as string. Zero-padding still present (MEDIUM-4 from cycle 1, acceptable).
- **build_onion:** Reverse iteration (pivot to edge). DH with ephemeral keys. XOR nonce derivation. Contiguous onion encryption. Hop ID chaining correct. Dummy frame randomization correct.
- **decrypt_build_frame:** Correct BT parsing. DH with (their_pk, our_pk, our_sk, their_pk, nonce) — matches the server-side role. XChaCha20 decrypt of inner. Inner BT parsing correct.
- **Path trailer:** [nonce 24][hopid 16][msgtype 1] = 41 bytes. Correct.

### session_keys.cpp — PASS

- **Phase 1 context:** Domain "srouter session context" (23 bytes) as BLAKE2b key. Data order: I || R || tag_i_le || tag_r_le. Explicit htole32 conversion. Correct.
- **Phase 2 key derivation:** Context (64 bytes) as BLAKE2b key. Data order: DH_result || X || Y || k_s || M. Correct.
- **Key assignment:** Initiator (out=k1, in=k2), receiver (out=k2, in=k1). Correct.
- **Cleanup:** dh_result and context zeroed with sodium_memzero. h zeroed after key copy. Correct.

### relay_contact.cpp — PASS (unchanged from cycle 1)

- BT key ordering matches upstream: "" < "#" < "4" < "6" < "p" < "t" < "v" < "~".
- IPv4 encoding: 4 bytes raw + 2 bytes big-endian port. Correct.
- IPv6 encoding: 16 bytes raw + 2 bytes big-endian port. Correct.
- Timestamp as BT integer. Correct.
- Signature: manual append of "1:~64:<sig>e" (MEDIUM-1 from cycle 1, acceptable).

### bt.cpp — PASS (unchanged from cycle 1)

- `get_signable_prefix`: rfind("1:~") approach. MEDIUM-3 from cycle 1 (theoretical binary collision), acceptable.
- `append_signature`: Signs prefix bytes, appends "1:~64:<sig>e". Correct.
- `verify_signature`: Extracts prefix via get_signable_prefix, reads "~" value, crypto_sign_verify_detached. Correct.

### dh.cpp — PASS

- Ed25519-to-X25519 conversion for DH. Correct.
- BLAKE2b(nonce_key, client_pk || server_pk || dh_result). Ordering is always client||server regardless of role. Correct.
- derive_xor_nonce uses crypto_shorthash with zero key. Correct.
- dh_result and x_sk zeroed. Correct.

### sealed_box.cpp — PASS

- crypto_box_seal / crypto_box_seal_open with Ed25519-to-X25519 conversion. Correct.
- x_sk zeroed on all paths. Correct.

### aead.cpp — PASS

- xchacha20poly1305_ietf for AEAD. Correct.
- crypto_stream_xchacha20_xor for stream cipher. Correct.

### path.cpp — PASS

- Nonce chaining: hop[i+1].nonce = hop[i].nonce ^ hop[i].xor_nonce. Correct.
- Encrypt in reverse (pivot first). Correct.
- Decrypt forward (edge first). Correct.
- Lifetime fuzz with mt19937. Acceptable.

---

## 4. Cross-Reference: Message Types vs Upstream

| Message Type | Match? | Notes |
|-------------|--------|-------|
| Session Init outer | YES | `{"":"i", "B":<sealed>}` |
| Session Init inner | YES | `{"I":pk, "M":mlkem, "X":x25519, "p":pivot, "t":integer, "~":sig}` — FIXED |
| Session Accept outer | YES | `{"":"a", "B":<sealed>}` |
| Session Accept inner | YES | `{"Y":x25519, "c":mlkem_ct, "t":integer, "~":sig}` — FIXED, sig verified |
| Session Control | YES | `{"e":method, "p":body}` |
| Session Data | YES | `[ct][tag_be_4][pivot_16]` — FIXED (big-endian tag) |
| Path Build Frame outer | YES | `{"k":pk, "n":nonce, "x":encrypted}` |
| Path Build Frame inner | YES | `{"l":lifetime_le4, "r":rxid, "t":txid, "u":upstream}` |
| Path Build Onion | YES | Contiguous encryption — FIXED |
| Path Trailer | YES | `[nonce_24][hopid_16][msgtype_1]` |
| Relay Contact | YES | All fields match |
| Key Derivation Phase 1 | YES | Explicit LE tags — FIXED |
| Key Derivation Phase 2 | YES | DH||X||Y||k_s||M order |
| Key Assignment | YES | Initiator k1/k2, receiver k2/k1 |

---

## 5. Remaining Findings (from Cycle 1, not blockers)

### MEDIUM-1: to_bt_signed manual signature append
Unchanged. Not a correctness issue.

### MEDIUM-2: find_dict_end fragile BT parser
Unchanged. Works for current message types.

### MEDIUM-3: get_signable_prefix rfind vulnerability
Unchanged. Theoretical binary collision risk.

### MEDIUM-4: build_frame zero-padding instead of assertion
Unchanged. Should be an error, not silent padding.

### LOW-1: Unused helper functions
Unchanged.

### LOW-2: const_cast in strip_path_trailer
Unchanged.

### LOW-3: Missing arpa/inet.h include
Unchanged.

---

## 6. Test Coverage After Fixes

### New regression tests added:
1. **CRITICAL-1 regression:** Verifies tag round-trips through BT integer encoding with known value 0xDEADBEEF.
2. **CRITICAL-2 regression:** Full 3-hop onion build + layered decryption. Each hop de-onions the contiguous block and decrypts its own frame. This test would have FAILED with per-frame encryption.
3. **CRITICAL-3 regression:** SessionAccept with wrong signer is rejected (signature verification works).
4. **HIGH-1 regression:** Byte-swapped tags produce different keys (proves tag bytes are correctly included in hash).
5. **HIGH-2 regression:** Verifies 0x01020304 appears as 01 02 03 04 on wire (big-endian byte order).

### Updated existing tests:
- `test_wire_compat.cpp`: Session data test updated to use `uint_to_tag(0xAABBCCDD)` and verify big-endian byte order.
- `test_session.cpp`: Tag endianness test updated. SessionAccept::unseal calls updated with remote_pk parameter.

### Remaining test gaps (non-blocking):
- No hardcoded upstream-produced byte vectors for cross-implementation verification
- No test for session data encrypt/decrypt symmetry with big-endian tag (encrypt writes BE, decrypt strips without interpreting — correct but untested explicitly)
- No test for BT dict with unknown/extra keys (forward compatibility)

---

## 7. Final Assessment

All 3 CRITICAL and 2 HIGH findings from Cycle 1 have been correctly fixed. The fixes:
- Do not introduce new CRITICAL or HIGH issues
- Are consistent with upstream wire format
- Are covered by regression tests
- Compile cleanly with -Wall -Wextra -Werror -Wpedantic
- Pass all 9 test suites (35+ test cases)

**Verdict: PASS** — Ready for human review and merge.
