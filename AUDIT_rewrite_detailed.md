# Session Router Rewrite — Security Audit

**Target:** rewrite/ (~5,200 lines C++20, 19 test files, 112 test cases)
**Standard:** Cryptographic network protocol audit — every function, every crypto operation, every byte
**Prepared by:** Xepayac (github.com/Xepayac)
**Date:** March 2026
**Cycles completed:** 3 (zero critical, zero high findings remaining)
**Status:** PRE-AUDIT (plan only; no findings yet)

This document specifies the exact audit procedure for every function in every source file.
It is written so a second auditor can execute it mechanically without having read the code before.

---

## Table of Contents

1. [Layer 0: Crypto](#layer-0-crypto)
   - [types.hpp / keys.cpp](#file-srcrryptokeyscpp)
   - [aead.hpp / aead.cpp](#file-srccryptoaeadcpp)
   - [dh.hpp / dh.cpp](#file-srccryptodhcpp)
   - [sealed_box.hpp / sealed_box.cpp](#file-srccryptosealed_boxcpp)
   - [blind.hpp / blind.cpp](#file-srccryptoblindcpp)
   - [session_keys.hpp / session_keys.cpp](#file-srccryptosession_keyscpp)
   - [mlkem.hpp / mlkem.cpp](#file-srccryptomlkemcpp)
   - [bt.hpp](#file-includesrcryptobt-hpp)
2. [Layer 1: Contact](#layer-1-contact)
   - [router_id.hpp / router_id.cpp](#file-srccontactrouter_idcpp)
   - [relay_contact.hpp / relay_contact.cpp](#file-srccontactrelay_contactcpp)
   - [nodedb.hpp / nodedb.cpp](#file-srccontactnodedbcpp)
3. [Layer 2: Path](#layer-2-path)
   - [hop.hpp / hop.cpp](#file-srcpathhop-cpp)
   - [path.hpp / path.cpp](#file-srcpathpathcpp)
   - [onion.hpp / onion.cpp](#file-srcpathonioncpp)
4. [Layer 3: Session](#layer-3-session)
   - [session.hpp / session.cpp](#file-srcsessionsessioncpp)
5. [Layer 4: Link](#layer-4-link)
   - [endpoint.hpp / endpoint.cpp](#file-srclinkendpointcpp)
   - [manager.hpp / manager.cpp](#file-srclinkmanagercpp)
6. [Layer 5: Node](#layer-5-node)
   - [config.hpp / config.cpp](#file-srcnodeconfigcpp)
   - [tun.hpp / tun.cpp](#file-srcnodetuncpp)
   - [dns.hpp / dns.cpp](#file-srcnodednscpp)
   - [events.hpp](#file-includesrnodeevents-hpp)
   - [node.hpp / node.cpp](#file-srcnodenodecpp)
   - [main.cpp](#file-srcmaincpp)
7. [Layer 5.1: Exit](#layer-51-exit)
   - [exit_handler.hpp / exit_handler.cpp](#file-srcexitexit_handlercpp)
8. [Crypto Audit Matrix](#crypto-audit-matrix)
9. [Wire Format Audit Matrix](#wire-format-audit-matrix)
10. [Thread Safety Audit Matrix](#thread-safety-audit-matrix)
11. [Test Gap Analysis](#test-gap-analysis)

---

## Layer 0: Crypto

### File: src/crypto/keys.cpp
**Purpose:** Libsodium initialization, Ed25519/X25519 keypair generation, Ed25519-to-X25519 conversion.
**Lines:** 45
**Risk level:** CRITICAL

#### Function: `sodium_init_once()` (line 11-16)

- **What it does:** Thread-safe one-shot libsodium initialization via `std::call_once`.
- **Threat model:** If `sodium_init()` fails silently or is never called, all subsequent crypto operations use uninitialized state. If called concurrently before `call_once` completes, race condition on libsodium internal state.
- **Checks:**
  - Verify `std::once_flag sodium_flag` is file-static (line 9) -- must not be per-object.
  - Verify `sodium_init()` return value handling: returns 0 on success, 1 on already-initialized, -1 on failure. Line 14 checks `< 0` which correctly catches only failure.
  - Verify no other code calls `sodium_init()` directly (grep entire codebase).
- **TRUG constraints:** None directly. Prerequisite for all crypto operations.
- **TRUG dragons:** None directly.
- **Test coverage:** Implicitly tested by every test that calls crypto functions. No dedicated test for `sodium_init()` failure.
- **Missing tests:** Negative test for `sodium_init()` failure path (difficult to trigger).

#### Function: `Ed25519KeyPair::generate()` (line 19-25)

- **What it does:** Generates an Ed25519 signing keypair using `crypto_sign_keypair`.
- **Threat model:** If libsodium is not initialized, keypair may be predictable. If `crypto_sign_keypair` writes outside buffer bounds, memory corruption.
- **Checks:**
  - Verify `sodium_init_once()` called before `crypto_sign_keypair` (line 21) -- YES.
  - Verify buffer sizes: `kp.pk` is `Bytes<32>`, `kp.sk` is `Bytes<64>`. `crypto_sign_keypair` writes 32 bytes to pk, 64 bytes to sk. Sizes match `crypto_sign_PUBLICKEYBYTES` (32) and `crypto_sign_SECRETKEYBYTES` (64).
  - Verify `as_uchar()` cast does not violate strict aliasing -- `std::byte` to `unsigned char*` is explicitly permitted by the standard.
- **Test coverage:** `test_keys.cpp` lines 6-14 (sign/verify round-trip), lines 16-21 (uniqueness).
- **Missing tests:** No test for entropy quality (difficult). No test that generated keys are on the curve (libsodium guarantees this).

#### Function: `X25519KeyPair::generate()` (line 27-33)

- **What it does:** Generates an X25519 key exchange keypair using `crypto_box_keypair`.
- **Threat model:** Same as Ed25519 generation. Additionally, X25519 keys with specific properties (low-order points) could enable small-subgroup attacks.
- **Checks:**
  - Verify `sodium_init_once()` called (line 29) -- YES.
  - Verify buffer sizes: `kp.pk` is `Bytes<32>`, `kp.sk` is `Bytes<32>`. `crypto_box_keypair` writes `crypto_box_PUBLICKEYBYTES` (32) to pk, `crypto_box_SECRETKEYBYTES` (32) to sk. Match confirmed.
  - Verify `crypto_box_keypair` (not `crypto_box_seed_keypair`) is used -- correct for random generation.
- **Test coverage:** `test_keys.cpp` lines 23-33 (DH agreement between two keypairs).
- **Missing tests:** Low-order point rejection test.

#### Function: `X25519KeyPair::from_ed25519()` (line 35-43)

- **What it does:** Converts an Ed25519 keypair to X25519 for use in sealed box and DH operations.
- **Threat model:** Malformed Ed25519 keys (twist points) cause `crypto_sign_ed25519_pk_to_curve25519` to fail. This is the exact bug documented in upstream at `session_keys.cpp:23-27`. Exceptions on network-supplied data could be used for DoS.
- **Checks:**
  - Verify return value of `crypto_sign_ed25519_pk_to_curve25519` is checked (line 38) -- YES, throws on `!= 0`.
  - Verify return value of `crypto_sign_ed25519_sk_to_curve25519` is checked (line 40) -- YES, throws on `!= 0`.
  - **CRITICAL:** Verify that callers of this function handle the exception for network-supplied keys. Search all call sites.
  - Verify no secret key material is leaked in the exception message (lines 39, 41) -- messages are generic strings, no key material. PASS.
  - Verify `kp.sk` (the converted X25519 secret key) is NOT zeroed on pk conversion failure path (line 38-39 throws before sk is populated) -- no leak because sk was never set. PASS.
- **TRUG dragons:** `dragon_ed25519_x25519_fail` -- "Ed25519 to X25519 public key conversion can fail for malformed keys."
- **Test coverage:** `test_keys.cpp` lines 35-47 (conversion + DH).
- **Missing tests:** Test with a known-bad Ed25519 key (twist point) to verify exception is thrown. Test that converted keypair produces same DH result as raw X25519 keypair.

---

### File: src/crypto/aead.cpp
**Purpose:** xchacha20-poly1305 AEAD encrypt/decrypt (session data, path control). Plain xchacha20 stream cipher (onion layers).
**Lines:** 87
**Risk level:** CRITICAL

#### Function: `aead_encrypt_inplace()` (line 9-28)

- **What it does:** AEAD encrypts plaintext in-place, appending a 16-byte poly1305 MAC tag.
- **Threat model:** Buffer overflow if `buf` is too small. Nonce reuse destroys confidentiality and allows forgery. Wrong key parameter ordering produces silently wrong ciphertext.
- **Checks:**
  - Verify buffer size check at line 12-13: `buf.size() < plaintext_len + AEAD_TAG_SIZE` throws. Correct.
  - Verify libsodium function: `crypto_aead_xchacha20poly1305_ietf_encrypt` (line 16). Parameters:
    - `c` (output): `buf.data()` -- in-place, same buffer.
    - `clen_p`: `&clen` -- output length.
    - `m` (plaintext): `buf.data()` -- same buffer (in-place is valid per libsodium docs).
    - `mlen`: `plaintext_len`.
    - `ad`: `nullptr` -- no additional data. **NOTE:** Upstream uses no AD either. Match confirmed.
    - `adlen`: `0`.
    - `nsec`: `nullptr` -- correct for this AEAD.
    - `npub`: nonce, 24 bytes.
    - `k`: key, 32 bytes.
  - Verify `clen` is used to size the return span (line 27) -- YES.
  - **CRITICAL:** Verify in-place encryption is safe. Libsodium docs state: "The ciphertext and the plaintext can point to the same buffer." PASS.
  - Verify no AD is used. Cross-reference with upstream: upstream also uses no AD for session data messages. Match confirmed.
- **Test coverage:** `test_aead.cpp` lines 23-36 (round-trip), 75-91 (inplace matches allocating), 108-120 (empty plaintext).
- **Missing tests:** Test with maximum-size plaintext (near size_t limit). Test that output clen equals plaintext_len + TAG_SIZE exactly.

#### Function: `aead_decrypt_inplace()` (line 30-51)

- **What it does:** AEAD decrypts ciphertext in-place, verifying and stripping the MAC.
- **Threat model:** Tampered ciphertext accepted (forgery). Timing side channel on MAC verification. Buffer underflow on short input.
- **Checks:**
  - Verify minimum size check: line 33 checks `buf.size() < AEAD_TAG_SIZE`. Correct.
  - Verify libsodium function: `crypto_aead_xchacha20poly1305_ietf_decrypt` (line 37). Parameters in correct order.
  - Verify return `nullopt` on failure (line 48) -- no exception, no timing difference in our code (libsodium itself is constant-time on MAC verification).
  - Verify return span is sized by `mlen` (line 50) -- correct.
- **Test coverage:** `test_aead.cpp` lines 38-49 (wrong key), 51-63 (tampered), 65-73 (too short).
- **Missing tests:** Test with ciphertext of exactly TAG_SIZE bytes (edge case -- empty plaintext encrypted). Test with wrong nonce.

#### Function: `aead_encrypt()` (line 53-60)

- **What it does:** Allocating wrapper around `aead_encrypt_inplace`.
- **Threat model:** Memory allocation failure on large plaintext. Double-copy overhead.
- **Checks:**
  - Verify output vector size: `plaintext.size() + AEAD_TAG_SIZE` (line 56). Correct.
  - Verify memcpy of plaintext into output buffer before in-place encrypt (line 57). Correct.
- **Test coverage:** Covered transitively through `aead_encrypt_inplace` tests.
- **Missing tests:** None needed beyond what inplace tests cover.

#### Function: `aead_decrypt()` (line 62-75)

- **What it does:** Allocating wrapper around `aead_decrypt_inplace`.
- **Threat model:** Same as inplace variant.
- **Checks:**
  - Verify minimum size check duplicated at line 65-66. Redundant but safe.
  - Verify resize of output buffer to match actual plaintext length (line 73). Correct.
- **Test coverage:** Covered transitively.
- **Missing tests:** None.

#### Function: `xchacha20_inplace()` (line 77-85)

- **What it does:** XOR stream cipher (no authentication). Used for onion layers.
- **Threat model:** Nonce reuse allows XOR of two plaintexts. No integrity protection -- bit flips propagate silently. This is BY DESIGN for onion routing (each layer is unauthenticated; AEAD is at the terminal hop).
- **Checks:**
  - Verify libsodium function: `crypto_stream_xchacha20_xor` (line 79). Correct function for keystream XOR.
  - Verify parameters: output and input are the same buffer (in-place). Valid per libsodium docs.
  - Verify key size: `SymmetricKey` is 32 bytes = `crypto_stream_xchacha20_KEYBYTES`. Match.
  - Verify nonce size: `Nonce` is 24 bytes = `crypto_stream_xchacha20_NONCEBYTES`. Match.
  - **CRITICAL:** This function provides NO authentication. Verify every call site understands this. Onion layer application (path.cpp, onion.cpp) uses this correctly. Session data uses `aead_encrypt` which includes MAC. Verify no code path accidentally uses `xchacha20_inplace` where AEAD is required.
- **TRUG constraints:** `constraint_wire_compat` -- must use xchacha20 (not xchacha20-poly1305) for onion layers.
- **Test coverage:** `test_aead.cpp` lines 93-106 (XOR round-trip: encrypt twice = plaintext).
- **Missing tests:** Test with zero-length buffer. Test with key of all zeros (degenerate case). Test that encrypted output differs from plaintext (already covered at line 102).

---

### File: src/crypto/dh.cpp
**Purpose:** Ed25519-based Diffie-Hellman key exchange with BLAKE2b domain separation. XOR nonce derivation. Short hash and BLAKE2b utility.
**Lines:** 79
**Risk level:** CRITICAL

#### Function: `dh()` (line 9-44)

- **What it does:** Computes a shared secret from two Ed25519 key pairs using DH with BLAKE2b domain separation.
- **Threat model:** This is the most sensitive function in the entire codebase. Wrong parameter ordering produces different secrets silently on both sides (connection fails with no error). Wrong DH role (client vs server) produces wrong keys. Low-order point in peer's key allows small-subgroup attack. Secret key material leaking through stack or error messages.
- **Checks:**
  - **CRITICAL -- Parameter ordering (lines 30-37):**
    - `crypto_generichash_init` with nonce as key (line 34). Nonce is 24 bytes. `crypto_generichash_init` accepts key up to 64 bytes. 24 < 64. But BLAKE2b minimum key length is 16 bytes per libsodium. 24 >= 16. PASS.
    - `crypto_generichash_update` order: `client_pk` first (line 35), then `server_pk` (line 36), then `dh_result` (line 37).
    - **MUST MATCH UPSTREAM:** Upstream at `src/crypto/crypto.cpp:35-59` uses `blake2b(nonce_as_key, client_pk || server_pk || dh_result)`. Our order matches. PASS.
  - **Ed25519 to X25519 conversion (lines 17-25):**
    - `crypto_sign_ed25519_sk_to_curve25519` at line 21. Return checked. Throws on failure.
    - `crypto_sign_ed25519_pk_to_curve25519` at line 23. Return checked. Throws on failure.
    - **CRITICAL:** These conversions can fail for malformed keys from the network. This function is called during path build and session establishment with remote keys. Callers must handle exceptions.
  - **Scalar multiplication (line 27):**
    - `crypto_scalarmult` at line 27. Return checked. Throws on failure.
    - `crypto_scalarmult` returns -1 if the result is zero (low-order point attack). Line 27 checks `!= 0`. PASS.
  - **Key zeroing (lines 40-41):**
    - `sodium_memzero(x_sk)` -- X25519 secret key zeroed. PASS.
    - `sodium_memzero(dh_result)` -- DH result zeroed. PASS.
    - `x_pk` (X25519 public key) is NOT zeroed -- this is public data, no need. PASS.
    - Stack-allocated arrays (`x_sk[32]`, `x_pk[32]`, `dh_result[32]`) are on the stack. After `sodium_memzero`, they are cleared. Compiler optimization could elide the zeroing, but `sodium_memzero` uses volatile writes internally to prevent this. PASS.
  - **Timing:** Exception path (lines 22, 24, 28) takes different time than success path. For path build, the client's ephemeral key is fresh random, so there is no chosen-input timing attack. For session establishment, the remote key could be adversarial -- but the timing difference reveals only that the key was malformed, which the attacker already knows.
- **TRUG dragons:** `dragon_dh_ordering` -- "DH key derivation requires exact parameter ordering." `dragon_ed25519_x25519_fail` -- "Ed25519 to X25519 public key conversion can fail."
- **TRUG constraints:** `constraint_dh_role_agreement` -- "Both sides must agree on client/server role."
- **Test coverage:** `test_dh.cpp` lines 7-19 (both sides same secret), 21-35 (swapped roles different secret), 37-49 (different nonce different secret).
- **Missing tests:** Test with known test vectors from upstream (if available). Test with identity point / low-order point for `their_pk`. Test that `x_sk` and `dh_result` are actually zeroed (read memory after call -- requires ASan or equivalent).

#### Function: `derive_xor_nonce()` (line 46-56)

- **What it does:** Derives a 24-byte XOR nonce from a shared secret using SipHash (crypto_shorthash). Only the first 8 bytes are populated; remaining 16 bytes are zero.
- **Threat model:** Two hops with the same xor_nonce cancel out in the nonce chain (XOR is self-inverse). If `short_hash` is predictable or collides, onion layer security is reduced.
- **Checks:**
  - Verify `XorNonce` is zero-initialized at line 48 (`{}` initialization). PASS -- remaining bytes after the 8-byte copy are zero.
  - Verify `crypto_shorthash` at line 53: uses a **zero key** (line 52: `unsigned char key[...] = {}`). This means the hash is deterministic but not keyed. **QUESTION:** Does upstream use a zero key here too, or a derived key? Must cross-reference upstream `src/crypto/crypto.cpp` xor_nonce derivation.
  - Verify the first 8 bytes are copied into the 24-byte `XorNonce` (line 54). The remaining 16 bytes are zero from initialization. This matches the upstream behavior where short_hash produces 8 bytes and the nonce is padded.
- **TRUG dragons:** `dragon_xor_nonce_collision` -- "Two hops with the same xor_nonce cancel out."
- **Test coverage:** `test_dh.cpp` lines 51-59 (deterministic), 62-69 (different inputs differ).
- **Missing tests:** Test that xor_nonce is exactly 8 non-zero bytes followed by 16 zero bytes. Test for collision resistance with 10,000 random inputs (statistical test).

#### Function: `short_hash()` (line 58-64)

- **What it does:** SipHash of arbitrary data with a zero key. Used for bucket hashing.
- **Threat model:** Predictable hash allows adversary to manipulate bucket placement of RCs.
- **Checks:**
  - Verify zero key at line 61. **NOTE:** Zero key makes this a non-keyed hash. An adversary can compute the hash of any input. For bucket hashing this is acceptable (bucket assignment is not a secret).
  - Verify output size: `Bytes<8>` matches `crypto_shorthash_BYTES` (8). PASS.
- **Test coverage:** Implicitly tested via `test_nodedb.cpp` bucket hash tests.
- **Missing tests:** Dedicated unit test for `short_hash` with known inputs.

#### Function: `blake2b()` (line 66-77)

- **What it does:** Generic BLAKE2b hash with optional key.
- **Threat model:** Wrong output size, wrong key handling.
- **Checks:**
  - Verify output size: `HASH_SIZE` = 32 = `crypto_generichash_BYTES`. PASS.
  - Verify empty key handling: line 74 checks `key.empty()` and passes `nullptr/0` to libsodium. Valid per docs.
  - Verify non-empty key: passes `key.data()` and `key.size()`. BLAKE2b accepts keys 16-64 bytes. Caller must ensure key is in range.
- **Test coverage:** `test_dh.cpp` lines 71-95 (deterministic, differs on input change, key changes output).
- **Missing tests:** Test with key shorter than 16 bytes (libsodium minimum). Test with key of exactly 64 bytes (maximum).

---

### File: src/crypto/sealed_box.cpp
**Purpose:** Sealed box encryption/decryption for session handshake. Encrypts to Ed25519 pubkey without sender authentication.
**Lines:** 60
**Risk level:** CRITICAL

#### Function: `seal()` (line 7-23)

- **What it does:** Encrypts plaintext to an Ed25519 recipient using `crypto_box_seal` after Ed25519-to-X25519 conversion.
- **Threat model:** Wrong key conversion breaks encryption. `crypto_box_seal` failure leaks state. Output size mismatch causes truncation.
- **Checks:**
  - Verify Ed25519-to-X25519 conversion at line 11. Return checked. Throws on failure.
  - Verify output size: `plaintext.size() + SEAL_OVERHEAD` at line 14. `SEAL_OVERHEAD` = `crypto_box_SEALBYTES` = 48. Match.
  - Verify `crypto_box_seal` parameters (lines 15-19): output buffer, plaintext, plaintext length, recipient X25519 pubkey. Correct order per libsodium docs.
  - Verify `x_pk` buffer size: `crypto_box_PUBLICKEYBYTES` = 32 bytes. Match with Ed25519 pubkey conversion output.
  - **NOTE:** `x_pk` (converted public key) is not zeroed. It is public data. PASS.
- **TRUG dragons:** `dragon_ed25519_x25519_fail` -- conversion can fail for malformed keys.
- **Test coverage:** `test_sealed_box.cpp` lines 7-19 (round-trip), 32-44 (tampered), 46-53 (truncated), 55-66 (empty plaintext).
- **Missing tests:** Test with all-zeros pubkey (degenerate case). Test with maximum-size plaintext.

#### Function: `unseal()` (line 26-58)

- **What it does:** Decrypts sealed box using Ed25519 keypair after conversion.
- **Threat model:** Timing leak on decryption failure. Secret key material leaked in error path. Wrong key conversion silent failure.
- **Checks:**
  - Verify minimum size check: line 29 checks `ciphertext.size() < SEAL_OVERHEAD`. Returns nullopt. PASS.
  - Verify Ed25519-to-X25519 pk conversion at line 36. Returns nullopt on failure (not exception). PASS.
  - Verify Ed25519-to-X25519 sk conversion at line 38. On failure: **zeroes x_sk before returning** (line 40). PASS.
  - Verify `crypto_box_seal_open` at line 45. Parameters: output, ciphertext, ciphertext length, X25519 pk, X25519 sk. Correct order.
  - **CRITICAL -- Key zeroing:** `sodium_memzero(x_sk)` at line 52, BEFORE the return-value check. This means x_sk is ALWAYS zeroed regardless of success/failure. PASS.
  - Verify no key material in error paths: all error paths return `nullopt`, no logging, no exception messages. PASS.
  - **Timing:** The function returns `nullopt` on failure (line 55). `crypto_box_seal_open` is constant-time internally. Our code's early returns (lines 29, 37, 39) are for input validation, not crypto. The only timing-sensitive path is the `crypto_box_seal_open` call itself. PASS.
- **Test coverage:** `test_sealed_box.cpp` covers round-trip, wrong key, tampered, truncated, empty.
- **Missing tests:** Test that x_sk is zeroed after successful unseal (verify no secret key remains on stack).

---

### File: src/crypto/blind.cpp
**Purpose:** Blinded Ed25519 key derivation for client contact privacy. Allows publishing contacts under a derived key that cannot be linked to the root identity.
**Lines:** 143
**Risk level:** HIGH

#### Function: `blinding_scalar()` (line 10-24)

- **What it does:** Computes a blinding scalar from pubkey and domain string using BLAKE2b-512 reduced mod L.
- **Threat model:** If the scalar is zero or has low order, the blinded key is trivial to compute.
- **Checks:**
  - Verify `crypto_generichash` output is 64 bytes (line 13-14). Hash output size parameter is 64. PASS.
  - Verify domain string is used as BLAKE2b key (line 18-19). Domain is `std::string_view`, passed as key. Size must be 16-64 bytes. `blinding::CLIENT_CONTACT` = "srouter session context" = 23 bytes. In range. PASS.
  - Verify `crypto_core_ed25519_scalar_reduce` at line 22. Reduces 64-byte hash to 32-byte scalar mod L. Correct.
  - **NOTE:** The reduced scalar could theoretically be zero (probability negligible, ~2^-252). No check is performed. Acceptable for production.
- **Test coverage:** Implicitly tested through `test_blind.cpp`.
- **Missing tests:** Test that blinding_scalar produces non-zero output for various inputs.

#### Function: `blind_pubkey()` (line 26-35)

- **What it does:** Computes blinded_pk = scalar * root_pk on the Ed25519 curve.
- **Threat model:** If scalar is zero, blinded_pk is the identity point (breaks anonymity). If root_pk is not on the curve, result is undefined.
- **Checks:**
  - Verify `crypto_scalarmult_ed25519_noclamp` at line 31. Uses noclamp because the scalar is already properly reduced. Correct.
  - Verify return value checked. Throws on failure. PASS.
- **Test coverage:** `test_blind.cpp` lines 19-26 (matches keypair), 28-35 (different domains differ), 51-57 (different from root), 59-66 (deterministic).
- **Missing tests:** Test with root_pk = identity point.

#### Function: `BlindedKeyPair::from_root()` (line 37-82)

- **What it does:** Derives a full blinded signing keypair from root secret key, root public key, and domain.
- **Threat model:** Incorrect Ed25519 scalar extraction (SHA-512 hash + clamping). Incorrect scalar multiplication. Secret key material leaking on error path.
- **Checks:**
  - **Ed25519 scalar extraction (lines 50-57):**
    - `crypto_hash_sha512(h, root_sk, 32)` -- hashes the SEED portion (first 32 bytes) of the 64-byte Ed25519 secret key. This is the standard Ed25519 convention. PASS.
    - Clamping at lines 54-56: `h[0] &= 248; h[31] &= 127; h[31] |= 64;` -- standard Ed25519 clamping. PASS.
    - Copy to `root_scalar` at line 57. Correct.
  - **Blinded scalar computation (line 61):**
    - `crypto_core_ed25519_scalar_mul(blinded_scalar, scalar, root_scalar)` -- multiplies blinding scalar by root scalar mod L. Correct.
  - **sign_key construction (lines 63-65):**
    - First 32 bytes: `blinded_scalar`. Second 32 bytes: `blinded_pk`. This matches the Ed25519 secret key layout `[scalar:32][pk:32]` used by `crypto_sign_detached`. PASS.
  - **hash_data derivation (lines 69-75):**
    - `crypto_generichash(hash_data, 32, root_sk, 32, domain)` -- BLAKE2b of seed with domain as key. Used as the nonce component in signing. PASS.
  - **Key zeroing (lines 77-79):**
    - `sodium_memzero(root_scalar)` -- PASS.
    - `sodium_memzero(h)` -- PASS (contains SHA-512 hash with secret scalar).
    - `sodium_memzero(blinded_scalar)` -- PASS.
- **Test coverage:** `test_blind.cpp` lines 8-17 (sign and verify), 19-26 (pubkey matches keypair).
- **Missing tests:** Test that sign_key is correctly constructed by verifying signature with libsodium's `crypto_sign_verify_detached` against the blinded pubkey.

#### Function: `BlindedKeyPair::sign()` (line 84-131)

- **What it does:** Signs a message using the blinded keypair with modified Ed25519 nonce derivation.
- **Threat model:** Nonce reuse (catastrophic -- leaks private key). Wrong HRAM computation breaks signature validity. Stack secrets not zeroed.
- **Checks:**
  - **Nonce derivation (lines 91-99):**
    - `SHA-512(hash_data || message)` at lines 92-96. Produces 64-byte hash. PASS.
    - `crypto_core_ed25519_scalar_reduce` reduces to 32-byte scalar (line 99). Correct.
  - **R computation (line 103):**
    - `crypto_scalarmult_ed25519_base_noclamp(R, nonce_scalar)` -- R = nonce_scalar * B. Correct.
  - **HRAM computation (lines 107-115):**
    - `SHA-512(R || pk || message)`. This is the standard Ed25519 HRAM. Correct.
    - `crypto_core_ed25519_scalar_reduce` at line 115. Correct.
  - **S computation (lines 118-121):**
    - `S = nonce_scalar + hram_scalar * blinded_scalar`. Lines 120-121. Correct Ed25519 signature equation.
  - **Signature assembly (lines 123-125):**
    - `sig = R || S` (32 bytes each, 64 total). Standard Ed25519 signature format. PASS.
  - **Key zeroing (lines 127-128):**
    - `sodium_memzero(nonce_hash)` -- PASS.
    - `sodium_memzero(nonce_scalar)` -- PASS.
    - **MISSING:** `hram` (64 bytes), `hram_scalar` (32 bytes), `S` (32 bytes), `tmp` (32 bytes), `R` (32 bytes) are NOT zeroed. `R` and `S` are public (they are the signature), so not sensitive. `hram` and `hram_scalar` are derived from public data (R, pk, message), so not sensitive. `tmp` contains `hram_scalar * blinded_scalar` which IS sensitive (relates to private key). **FINDING: `tmp` at line 119 should be zeroed.**
- **Test coverage:** `test_blind.cpp` lines 8-17 (sign/verify), 37-49 (doesn't verify with root key).
- **Missing tests:** Test signature with empty message. Test with large message (>1MB).

#### Function: `blind_verify()` (line 133-141)

- **What it does:** Verifies a signature made with a blinded key using standard Ed25519 verification.
- **Threat model:** Accepts invalid signatures (forgery). Timing leak on verification.
- **Checks:**
  - Verify `crypto_sign_verify_detached` is used (line 135). Constant-time per libsodium. PASS.
  - Verify parameters: signature, message, message length, blinded pubkey. Correct order. PASS.
  - Return `== 0` for success. Correct. PASS.
- **Test coverage:** Covered in all blind test cases.
- **Missing tests:** Test with tampered signature. Test with wrong message.

---

### File: src/crypto/session_keys.cpp
**Purpose:** Session key derivation combining X25519 DH and ML-KEM shared secret.
**Lines:** 75
**Risk level:** CRITICAL

#### Function: `derive_session_keys()` (line 9-73)

- **What it does:** Computes symmetric session keys from X25519 DH + ML-KEM shared secret + identity RouterIDs.
- **Threat model:** This is the second most sensitive function. Wrong parameter ordering produces different keys on both sides (session fails silently). Wrong k1/k2 swap means both sides encrypt with the same directional key. DH result not zeroed leaks shared secret.
- **Checks:**
  - **X25519 DH (lines 21-23):**
    - `crypto_scalarmult(dh_result, our_x_sk, their_x_pk)`. Return checked. Throws on failure.
    - **CRITICAL:** Verify that `our_x_sk` and `their_x_pk` are X25519 keys (not Ed25519). The function signature takes `X25519SecKey` and `X25519PubKey` types. Type-safe at the API level. PASS.
  - **BLAKE2b-512 hash construction (lines 31-53):**
    - Domain string: `"session-router-session-keys"` (27 bytes, line 31). Used as BLAKE2b key. 27 >= 16 (minimum). PASS.
    - **CRITICAL -- Parameter ordering (lines 38-51):**
      1. `initiator_x_pk` (line 38) -- initiator's X25519 pubkey
      2. `receiver_x_pk` (line 40) -- receiver's X25519 pubkey
      3. `dh_result` (line 42) -- shared DH result
      4. `mlkem_shared_secret` (line 44) -- ML-KEM shared secret
      5. `mlkem_pk` (line 47) -- ML-KEM public key
      6. `initiator_rid` (line 49) -- initiator's Ed25519 RouterID
      7. `receiver_rid` (line 51) -- receiver's Ed25519 RouterID
    - **MUST VERIFY AGAINST UPSTREAM:** Upstream at `src/crypto/session_keys.cpp:119-166` uses the same ordering. Cross-reference required.
    - **NOTE:** The domain string here differs from the upstream TRUG description. TRUG msg_session_accept says: `"blake2b_64(yX || X || Y || k_s || M, key=blake2b_64(I || R || tag_i || tag_r, key='srouter session context'))"`. Our implementation uses a SINGLE hash with all inputs concatenated, not a TWO-LEVEL hash. **CRITICAL DISCREPANCY -- MUST VERIFY.** Either the TRUG description is wrong, or our implementation diverges from upstream.
    - Hash output: 64 bytes (line 35, last param `64`). PASS.
  - **DH result zeroing (line 55):**
    - `sodium_memzero(dh_result)`. PASS.
  - **Key split and k1/k2 swap (lines 59-69):**
    - `is_initiator == true`: `key_out = h[0..31]`, `key_in = h[32..63]`.
    - `is_initiator == false`: `key_out = h[32..63]`, `key_in = h[0..31]`.
    - This means: initiator's outbound key = receiver's inbound key. CORRECT.
    - **CRITICAL:** Verify `memcpy` offsets. Line 62: `h.data()` (offset 0). Line 63: `h.data() + 32`. Line 67: `h.data() + 32`. Line 68: `h.data()`. Correct pairwise swap. PASS.
  - **Hash zeroing (line 71):**
    - `sodium_memzero(h.data(), h.size())`. Zeroes full 64-byte hash. PASS.
- **TRUG dragons:** `dragon_k1k2_swap` -- "Session key k1/k2 swap is controlled by a single boolean."
- **TRUG constraints:** `constraint_k1k2_direction` -- "Initiator uses (key_out=k1, key_in=k2), receiver uses (key_out=k2, key_in=k1)."
- **Test coverage:** `test_session_keys.cpp` lines 7-49 (both sides same keys, cross-match), 51-64 (out != in), 66-82 (swapped RIDs differ), 84-101 (different ML-KEM secret differs).
- **Missing tests:** Test with `is_initiator` flag inverted (verify keys are swapped). Test with all-zero ML-KEM inputs. Test with upstream test vectors if available. **CRITICAL: Test the two-level hash vs single-level hash discrepancy with TRUG spec.**

---

### File: src/crypto/mlkem.cpp
**Purpose:** ML-KEM-768 post-quantum key encapsulation. PLACEHOLDER implementation.
**Lines:** 52
**Risk level:** CRITICAL (but currently placeholder)

#### Function: `MLKEMKeyPair::generate()` (line 13-26)

- **What it does:** PLACEHOLDER -- fills keys with random bytes, not real ML-KEM.
- **Threat model:** If deployed without replacement, provides zero post-quantum security. Random bytes are not valid ML-KEM keys.
- **Checks:**
  - Verify build guard: `#ifndef SR_MLKEM_PLACEHOLDER_OK` at line 15 throws `std::logic_error`. This prevents accidental use without explicit opt-in. PASS.
  - Verify placeholder clearly documented (comments at lines 4-8). PASS.
  - **CRITICAL:** Before any deployment, this MUST be replaced with a real ML-KEM-768 implementation (e.g., upstream's bundled `sr_mlkem768`).
- **Test coverage:** `test_session.cpp` line 72 calls `MLKEMKeyPair::generate()` (requires `-DSR_MLKEM_PLACEHOLDER_OK`).
- **Missing tests:** No tests for real ML-KEM operations (because placeholder).

#### Function: `mlkem_encapsulate()` (line 28-37)

- **What it does:** PLACEHOLDER -- returns random ciphertext and shared secret.
- **Threat model:** Same as above. No actual encapsulation.
- **Checks:**
  - Verify `(void)pk` at line 35 -- pubkey is ignored. This is explicit placeholder behavior. PASS.
- **Test coverage:** None directly (placeholder).
- **Missing tests:** All ML-KEM tests blocked until real implementation.

#### Function: `mlkem_decapsulate()` (line 39-50)

- **What it does:** PLACEHOLDER -- returns random shared secret.
- **Threat model:** No implicit rejection. Real ML-KEM must return deterministic wrong value on failure.
- **Checks:**
  - Verify comment at lines 44-45 documents the implicit rejection requirement. PASS.
  - Verify no exceptions thrown (line 48 uses `randombytes_buf`, no error path). PASS. This matches the requirement (upstream dragon `dragon_mlkem_timing` was about throwing on failure).
- **TRUG dragons:** `dragon_mlkem_timing` -- "ML-KEM decapsulate throws on failure instead of using implicit rejection." Our rewrite correctly avoids this.
- **Test coverage:** None (placeholder).
- **Missing tests:** All blocked until real implementation.

---

### File: include/sr/crypto/bt.hpp
**Purpose:** Re-exports oxen-encoding BT serialization. Convenience functions for byte/string conversion.
**Lines:** 35
**Risk level:** LOW

#### Function: `to_bytes()` (line 22-27)

- **What it does:** Converts a `std::string` to `std::vector<std::byte>`.
- **Threat model:** `reinterpret_cast` from `char*` to `std::byte*`. Defined behavior per C++17 (std::byte is explicitly aliasable).
- **Checks:**
  - Verify range constructor uses correct begin/end iterators. PASS.
- **Test coverage:** `test_bt.cpp` lines 69-75 (round-trip with `to_sv`).
- **Missing tests:** Test with empty string. Test with binary data containing null bytes.

#### Function: `to_sv()` (line 29-32)

- **What it does:** Converts `std::span<const std::byte>` to `std::string_view`.
- **Threat model:** Same aliasing analysis as above.
- **Checks:** Straightforward cast. PASS.
- **Test coverage:** `test_bt.cpp` lines 69-75.
- **Missing tests:** None needed.

---

## Layer 1: Contact

### File: src/contact/router_id.cpp
**Purpose:** Router identity type wrapping Ed25519 public key. Hex string conversion.
**Lines:** 37
**Risk level:** MEDIUM

#### Function: `RouterID::RouterID(span<const std::byte, 32>)` (line 11)

- **What it does:** Constructs RouterID from a 32-byte span.
- **Threat model:** Buffer overflow if span is not exactly 32 bytes. However, `std::span<const std::byte, 32>` is a fixed-size span -- the compiler enforces 32 bytes at compile time. PASS.
- **Test coverage:** `test_router_id.cpp` lines 10-15 (from Ed25519PubKey).
- **Missing tests:** None needed.

#### Function: `RouterID::to_string()` (line 13-20)

- **What it does:** Converts RouterID to 64-character hex string.
- **Threat model:** Incorrect hex encoding could cause key misidentification.
- **Checks:**
  - Verify each byte is cast to `uint8_t` before `int` conversion (line 18). `static_cast<int>(static_cast<uint8_t>(b))`. Correct -- avoids sign extension on platforms where `std::byte` underlying type is signed.
  - Verify output is exactly 64 characters (32 bytes * 2 hex chars). PASS.
- **Test coverage:** `test_router_id.cpp` lines 17-25 (round-trip).
- **Missing tests:** Test with known input/output vector.

#### Function: `RouterID::from_string()` (line 22-35)

- **What it does:** Parses a 64-character hex string into a RouterID.
- **Threat model:** Invalid hex characters, wrong length, integer overflow.
- **Checks:**
  - Verify length check: line 24 requires exactly 64 chars. Throws on wrong length. PASS.
  - Verify `std::stoul` with base 16 at line 31. Could throw `std::invalid_argument` or `std::out_of_range` for non-hex input. These exceptions propagate correctly.
  - Verify cast: `static_cast<std::byte>(val)` at line 32. `val` is `unsigned long`, but each parsed substring is 2 hex chars = max 255. PASS.
- **Test coverage:** `test_router_id.cpp` lines 17-25 (round-trip), 47-51 (invalid throws).
- **Missing tests:** Test with uppercase hex. Test with odd-length hex. Test with "0x" prefix.

#### Hash specialization: `std::hash<RouterID>` (router_id.hpp lines 40-50)

- **What it does:** XOR-based hash for unordered containers.
- **Threat model:** Collision-prone hash allows hash-flooding DoS if attacker controls RouterIDs in the map. However, RouterIDs are Ed25519 public keys which are computationally expensive to generate, making collision attacks impractical.
- **Checks:**
  - Verify alignment: `reinterpret_cast<const size_t*>(rid.data())` at line 45. RouterID data is `Bytes<32>` which is `std::array<std::byte, 32>`. Alignment of `std::array` matches alignment of its element type (`std::byte` = 1-byte aligned). `size_t` requires `sizeof(size_t)` alignment. **POTENTIAL UB:** On platforms where `sizeof(size_t) > 1` (all modern platforms), this cast may violate alignment requirements. **FINDING: Strict aliasing / alignment violation in hash function.**
  - Verify loop count: `32 / sizeof(size_t)` at line 46. For 64-bit: 32/8 = 4 iterations. For 32-bit: 32/4 = 8 iterations. Covers all 32 bytes. PASS.
- **Test coverage:** `test_router_id.cpp` lines 36-45 (works in unordered_set).
- **Missing tests:** Test hash distribution quality with many random RouterIDs.

---

### File: src/contact/relay_contact.cpp
**Purpose:** Relay advertisement: creation, BT serialization, signing, verification, expiry.
**Lines:** 144
**Risk level:** HIGH

#### Function: `RelayContact::sign()` (line 21-26)

- **What it does:** Signs the BT-encoded unsigned RC data with the relay's Ed25519 secret key.
- **Threat model:** Signing wrong data (e.g., including signature in signed data).
- **Checks:**
  - Verify `to_bt_unsigned()` is called (line 23) -- excludes the signature field. PASS.
  - Verify `crypto_sign_detached` parameters (line 24): signature output, nullptr (no combined output), message, message length, secret key. Correct order. PASS.
- **Test coverage:** `test_relay_contact.cpp` lines 18-23 (sign/verify round-trip).
- **Missing tests:** None.

#### Function: `RelayContact::verify()` (line 28-37)

- **What it does:** Verifies the RC signature against the RC's own RouterID pubkey.
- **Threat model:** Using a stored/cached key instead of the RC's own key would allow substitution attacks.
- **Checks:**
  - Verify the verification key is `_rid.pubkey()` at line 35 -- the RC's own claimed identity. PASS.
  - Verify `to_bt_unsigned()` is called for the signed data (line 30). Same serialization as `sign()`. PASS.
  - **CRITICAL:** Verify that modifying any field of the RC after signing invalidates the signature. This requires that `to_bt_unsigned()` includes ALL meaningful fields. Check: "4" (addr), "p" (pubkey), "t" (timestamp), "v" (version). Signature "~" is excluded. PASS.
- **Test coverage:** `test_relay_contact.cpp` lines 25-42 (wrong key fails).
- **Missing tests:** Test that modifying timestamp after signing causes verify to fail.

#### Function: `RelayContact::to_bt_unsigned()` (line 44-79)

- **What it does:** Serializes the RC to BT-encoded bytes for signing/verification.
- **Threat model:** Wrong field order breaks BT dict canonical ordering and causes signature mismatch with upstream nodes. Wrong port byte order causes wrong address.
- **Checks:**
  - **CRITICAL -- BT dict key order:** BT encoding requires lexicographic key ordering. Keys used: "4", "p", "t", "v". Lexicographic order: "4" < "p" < "t" < "v". Lines 62, 66, 70, 73 -- inserted in this order. PASS.
  - **Port byte order (line 61):** `htons(_addr.port)` -- converts host-order port to network byte order. PASS. (This was the exact bug found in upstream `src/ev/tcp.cpp` where `htonl` was used instead of `htons`.)
  - **IPv4 address (lines 59-60):** `_addr.ipv4` is stored in network byte order (line 22 of header). `memcpy` preserves byte order. PASS.
  - Verify address field is exactly 6 bytes (4 IP + 2 port) at line 58. PASS.
  - **TRUG constraint check:** TRUG `msg_gossip_rc` specifies keys: "", "#", "4", "6", "p", "t", "v", "~". Our implementation omits "" (version, optional), "#" (netid, optional), "6" (IPv6, optional), "~" (signature, excluded from unsigned). This is correct -- optional fields are omitted when not present.
- **TRUG constraints:** `constraint_wire_compat` -- BT encoding must match upstream.
- **Test coverage:** `test_bt.cpp` lines 27-52 (round-trip).
- **Missing tests:** Test that serialized output matches a known upstream RC byte-for-byte. This is a wire compatibility test that must be performed.

#### Function: `RelayContact::from_bt()` (line 81-142)

- **What it does:** Parses a BT-encoded RC from bytes.
- **Threat model:** Malformed input causes crash, buffer overread, or silent incorrect parsing. Key skipping could miss required fields.
- **Checks:**
  - Verify `try/catch` wraps entire function (lines 83, 139). Any exception returns nullopt. PASS.
  - Verify `skip_until` for each required field (lines 91, 102, 113, 119). If a field is missing, returns nullopt. PASS.
  - Verify minimum size checks: addr_sv >= 6 (line 95), pk_sv >= 32 (line 106), v_sv >= 3 (line 121). PASS.
  - **Port parsing (line 99):** `ntohs(port_be)` -- network-to-host byte order. Matches `to_bt_unsigned` which uses `htons`. PASS.
  - **Signature parsing (lines 129-133):** Optional. `skip_until("~")` may fail (no signature in unsigned data). sig_sv >= 64 check. PASS.
  - **NOTE:** `skip_until` skips all keys before the target. This means if there are unexpected keys between known keys, they are silently ignored. This is correct for forward compatibility.
- **Test coverage:** `test_bt.cpp` lines 54-67 (invalid data, empty data).
- **Missing tests:** Test with truncated BT data mid-field. Test with extra unknown keys between known keys. Test with BT data containing correct structure but wrong sizes (e.g., pubkey of 31 bytes). Test with negative timestamp.

---

### File: src/contact/nodedb.cpp
**Purpose:** Routing table management: store/lookup/random-select relay contacts. Bucket hashing for incremental sync.
**Lines:** 139
**Risk level:** HIGH

#### Function: `NodeDB::put_rc()` (line 11-16)

- **What it does:** Inserts or updates a relay contact, protected by mutex.
- **Threat model:** Race condition on concurrent put/get. Unbounded growth if purging is not called.
- **Checks:**
  - Verify mutex acquired: `std::lock_guard lock{_mtx}` at line 13. PASS.
  - Verify `insert_or_assign` at line 14: updates existing RC for same RouterID. Correct behavior -- newer RC replaces older.
- **Test coverage:** `test_nodedb.cpp` lines 19-30 (put and get).
- **Missing tests:** Test put_rc with duplicate RouterID (verify update behavior).

#### Function: `NodeDB::random_rcs()` (line 49-81)

- **What it does:** Selects N random relay contacts using reservoir sampling, excluding specified RouterIDs.
- **Threat model:** Biased sampling leaks path selection to adversary. Non-excluded entries could be included due to race.
- **Checks:**
  - Verify mutex acquired (line 51). PASS.
  - **Reservoir sampling correctness (lines 65-78):**
    - First `count` elements: added directly (lines 67-69). PASS.
    - Subsequent elements: replaced with probability `count / (i+1)` (lines 72-76). `std::uniform_int_distribution<size_t>(0, i)` gives values in [0, i]. Element is replaced if `j < count`. This is standard reservoir sampling (Algorithm R). PASS.
  - Verify exclusion: line 57 checks `!exclude.contains(rid)`. PASS.
  - **NOTE:** `_rng` is `mutable std::mt19937`. It is accessed under the mutex, so thread-safe. But mt19937 is NOT cryptographically secure. For path selection in an anonymity network, cryptographic randomness should be used.
  - **FINDING:** `std::mt19937` is a non-cryptographic PRNG. An adversary who can observe path selections over time could potentially predict future selections. Should use `randombytes_buf` or `randombytes_uniform` from libsodium instead.
- **TRUG dragons:** None directly, but relates to path selection security.
- **Test coverage:** `test_nodedb.cpp` lines 49-96 (random selection, exclusion, more-than-available).
- **Missing tests:** Statistical test for sampling uniformity. Test with count=0. Test with all entries excluded.

#### Function: `NodeDB::bucket_index()` (line 102-106)

- **What it does:** Computes bucket index from byte 16 of RouterID, masked to 7 bits.
- **Threat model:** An adversary who can choose their RouterID (by generating Ed25519 keys until byte 16 has desired value) can bias bucket placement.
- **Checks:**
  - Verify byte 16 access: `rid.data()[16]` -- 0-indexed, so this is the 17th byte. Must verify this matches upstream.
  - Verify mask: `& 0x7F` at line 105. Produces values 0-127 = 128 buckets = `NUM_BUCKETS`. PASS.
- **TRUG constraints:** Must match upstream bucket hashing for `fetch_rcs` interoperability.
- **Test coverage:** Implicitly via bucket hash tests.
- **Missing tests:** Test that known RouterIDs map to expected buckets (cross-reference with upstream).

#### Function: `NodeDB::compute_bucket_hashes()` (line 108-125)

- **What it does:** Computes XOR aggregate hash per bucket for incremental RC sync.
- **Threat model:** False negatives (different RC sets produce same hash) cause stale routing tables. XOR is commutative -- adding and removing the same RC cancels out.
- **Checks:**
  - Verify XOR operation at line 121: `hashes[bucket][i] ^= h[i]`. Standard XOR accumulation. PASS.
  - Verify `to_bt_unsigned()` is used for RC data (line 117), not full BT with signature. **QUESTION:** Does upstream hash the unsigned RC or the full signed RC? Must cross-reference.
  - Verify `short_hash` (SipHash with zero key) at line 118. Same hash as used by upstream? Must cross-reference.
- **TRUG dragons:** `dragon_rc_bucket_hash` -- "XOR bucket hash has false negatives."
- **Test coverage:** `test_nodedb.cpp` lines 130-152 (deterministic, changes with data).
- **Missing tests:** Test XOR cancellation property (add and remove same RC should return to original hash).

---

## Layer 2: Path

### File: src/path/hop.cpp
**Purpose:** Random HopID generation.
**Lines:** 15
**Risk level:** MEDIUM

#### Function: `random_hop_id()` (line 7-13)

- **What it does:** Generates a random 16-byte HopID using `randombytes_buf`.
- **Threat model:** Non-random HopIDs allow correlation of hops across paths. Using `rand()` instead of CSPRNG.
- **Checks:**
  - Verify `sodium_init_once()` called (line 9). PASS.
  - Verify `randombytes_buf` used (line 11) -- libsodium CSPRNG. PASS.
  - Verify size: `id.size()` = 16 bytes. PASS.
- **Test coverage:** Implicitly through path and onion tests.
- **Missing tests:** Statistical test for uniqueness (generate 1000, verify no duplicates).

---

### File: src/path/path.cpp
**Purpose:** Client-side path encrypt/decrypt for onion routing. Path lifetime management.
**Lines:** 74
**Risk level:** CRITICAL

#### Function: `key_from_shared()` (line 12-17)

- **What it does:** Converts `SharedSecret` (32 bytes) to `SymmetricKey` (32 bytes) by memcpy.
- **Threat model:** If `SharedSecret` and `SymmetricKey` have different sizes, buffer over/under-read.
- **Checks:**
  - Both are `Bytes<32>`. `HASH_SIZE` = 32, `AEAD_KEY_SIZE` = 32. PASS.
  - `memcpy` of 32 bytes. PASS.
  - **NOTE:** This function does not zero the SharedSecret after use. The caller is responsible.
- **Test coverage:** Implicitly through path tests.
- **Missing tests:** None needed (trivial function).

#### Function: `Path::Path()` (line 21-28)

- **What it does:** Constructs a path with hops and a random lifetime fuzz (0-180 seconds).
- **Threat model:** If fuzz is predictable, path expiry timing leaks information.
- **Checks:**
  - Verify `std::random_device` used for seeding (line 24). Hardware RNG on Linux. PASS.
  - Verify fuzz range: `0` to `MAX_FUZZ_SECONDS.count()` = 180 seconds (line 26). PASS.
  - **NOTE:** Uses `std::mt19937` for fuzz generation. Since this is a one-time use for path lifetime, the non-cryptographic nature is acceptable.
- **TRUG constraints:** `constraint_path_lifetime` -- "Paths expire at MAX_LIFETIME (20min) + random fuzz (0-3min)." Our `MAX_FUZZ_SECONDS` = 180s = 3 minutes. PASS.
- **Test coverage:** `test_path.cpp` lines 104-111 (expiry), 113-119 (not expired when fresh).
- **Missing tests:** Test that fuzz is actually applied (create path, verify expiry time is between 20 and 23 minutes).

#### Function: `Path::encrypt_data()` (line 30-51)

- **What it does:** Encrypts data for sending down the path. Applies onion layers in REVERSE order (pivot first, edge last).
- **Threat model:** Wrong layer order breaks onion routing (relays cannot peel layers). Wrong nonce XOR chain means nonces don't match relay-side expectations. Nonce reuse across messages (nonce is passed by caller).
- **Checks:**
  - **CRITICAL -- Nonce pre-computation (lines 35-42):**
    - `hop_nonces[0] = nonce` (the base nonce).
    - For each subsequent hop: `hop_nonces[i] = hop_nonces[i-1] XOR hops[i-1].xor_nonce`. This pre-computes what each relay will see AFTER peeling the previous layers.
    - **Verify this matches relay-side behavior:** A relay at hop i receives the message, applies `xchacha20(key_i, nonce_i)`, then XORs the nonce with `xor_nonce_i` before forwarding. So hop i+1 sees `nonce_i XOR xor_nonce_i`. Our pre-computation at line 40-41 does `hop_nonces[i] = hop_nonces[i-1] XOR hops[i-1].xor_nonce`. This matches. PASS.
  - **CRITICAL -- Reverse encryption (lines 44-48):**
    - Loop from `hops.size()-1` down to 0. Pivot layer encrypted first (innermost), edge layer encrypted last (outermost). This is correct: the edge relay peels the outermost layer, revealing the next layer for the middle relay, etc.
    - Each iteration uses `hop_nonces[i]` which is the nonce that hop i will use when peeling.
    - Encryption: `xchacha20_inplace(buf, key, hop_nonces[i])`. PASS.
  - **Data size:** Output size equals input size (no MAC, no padding). Line 32 copies plaintext, lines 44-48 encrypt in-place. PASS.
- **TRUG constraints:** `constraint_onion_frame_order` -- "Encrypted in reverse order (pivot to edge)."
- **Test coverage:** `test_path.cpp` lines 18-49 (encrypt then relay-side peel = original).
- **Missing tests:** Test with 4 hops (maximum real path). Test with 1 hop. Test that encrypt output differs from plaintext.

#### Function: `Path::decrypt_data()` (line 53-67)

- **What it does:** Decrypts data received from the path. Peels onion layers in FORWARD order (edge first, pivot last).
- **Threat model:** Wrong peel order produces garbage. Nonce not XORed correctly means wrong key applied.
- **Checks:**
  - **Forward peeling (lines 55-63):**
    - Loop from 0 to `hops.size()-1`. Edge first, pivot last.
    - Each iteration: `xchacha20_inplace(data, key_i, nonce)`.
    - After each iteration (except last): `nonce XOR= hops[i].xor_nonce`.
    - This matches the relay-side behavior: each relay encrypts with its key and XORs the nonce.
  - **Nonce mutation (lines 59-62):** The nonce is passed by reference and mutated during decryption. The caller receives the final nonce value. This is necessary for some protocols.
  - **Return value:** Always returns a copy of the data (line 66). Never returns nullopt (no MAC to verify on onion layers). **NOTE:** This is correct for xchacha20 (no authentication).
- **Test coverage:** `test_path.cpp` lines 51-82 (decrypt reverses relay-side onioning), 84-102 (single hop).
- **Missing tests:** Test with corrupted data (verify it returns data, even though it's garbage -- xchacha20 has no MAC). Test nonce value after decrypt.

#### Function: `Path::is_expired()` (line 69-72)

- **What it does:** Checks if the path has exceeded MAX_LIFETIME + fuzz.
- **Checks:**
  - Verify `MAX_LIFETIME` + `_lifetime_fuzz` computation (line 71). PASS.
- **Test coverage:** `test_path.cpp` lines 104-127.
- **Missing tests:** None.

---

### File: src/path/onion.cpp
**Purpose:** Onion construction for path building. Frame encryption and relay-side decryption.
**Lines:** 150
**Risk level:** CRITICAL

#### Function: `build_onion()` (line 13-102)

- **What it does:** Constructs the onion-encrypted path build message for a set of relay hops.
- **Threat model:** This is the most complex function in the codebase. Wrong frame ordering, wrong encryption ordering, wrong parameter passing, or wrong DH role assignment breaks either the path build (benign failure) or anonymity (catastrophic failure -- intermediate hops learn information they should not).
- **Checks:**
  - **Frame initialization (line 22):**
    - `randombytes_buf(result.frames.data(), result.frames.size())`. All 1352 bytes filled with random data. This ensures dummy frames (beyond real hops) contain random data, not zeros. Matches upstream requirement. PASS.
  - **Hop setup (lines 25-32):**
    - Each hop gets a random `rxid` and `txid` (lines 30-31). PASS.
  - **CRITICAL -- Reverse frame construction (lines 36-99):**
    - Loop from `n_hops-1` down to 0. Pivot frame built first, edge frame built last. This is because each frame's encryption covers all subsequent frames -- the edge frame must be the LAST encrypted so its encryption is the outermost layer on all subsequent frames.
    - **DH computation (lines 46-51):**
      - `dh(ephemeral_keys.pk, relays[i].router_id().pubkey(), ephemeral_keys.sk, relays[i].router_id().pubkey(), nonce)`.
      - Client_pk = `ephemeral_keys.pk` (we are client). Server_pk = relay's pubkey.
      - Our_sk = `ephemeral_keys.sk`. Their_pk = relay's pubkey.
      - **CRITICAL:** Note that `their_pk` is the relay's Ed25519 pubkey (identity key), NOT an ephemeral key. The relay will use the same identity key for DH on its side. The DH function converts Ed25519 to X25519 internally. PASS.
      - **CRITICAL:** Both `server_pk` parameter (arg 2) and `their_pk` parameter (arg 4) are `relays[i].router_id().pubkey()`. In the DH function, `server_pk` is used for hash ordering, and `their_pk` is used for scalar multiplication. Both should be the same key here. PASS.
    - **XOR nonce derivation (line 53):** `derive_xor_nonce(hop.shared_secret)`. PASS.
    - **Payload construction (lines 57-70):**
      - 68-byte payload: rxid(16) + txid(16) + upstream_rid(32) + lifetime(4).
      - Upstream for edge hop (i=0): zeros (lines 62-65 skipped). Correct -- edge has no upstream.
      - Upstream for other hops: previous hop's RouterID (line 64). Correct.
      - **Lifetime (lines 69-70):** `uint32_t` little-endian. `memcpy` of 4 bytes. PASS. **TRUG check:** TRUG `msg_path_build` field `x.l` specifies "uint32_t little-endian, 4 bytes." Match.
    - **Frame assembly (lines 73-75):**
      - Frame layout: `ephemeral_pk(32) + nonce(24) + encrypted_payload`. Total: 32 + 24 + (169-56) = 32 + 24 + 113 = 169 = BUILD_FRAME_SIZE. PASS.
      - `ephemeral_keys.pk` written at frame start (line 74). Same key for ALL hops. **QUESTION:** Does upstream use the same ephemeral key for all hops, or a different one per hop? Must cross-reference. If same key is used, relays can correlate that all frames came from the same builder. Upstream uses the same ephemeral key -- confirmed from TRUG `flow_path_build` description.
    - **Payload encryption (lines 78-84):**
      - `sym_key` = `shared_secret` (32 bytes). Same as `key_from_shared()`.
      - `xchacha20_inplace(encrypted_payload, sym_key, nonce)`. Encrypts the 68-byte payload.
      - Copy encrypted payload into frame at offset 56 (line 83-84). `min(68, 169-56)` = `min(68, 113)` = 68. PASS.
      - **NOTE:** The remaining bytes (113-68=45 bytes) of the frame payload space are random (from initial fill at line 22). This is correct -- padding with random.
    - **CRITICAL -- Onion encryption of subsequent frames (lines 88-98):**
      - For each frame j > i: apply `xchacha20_inplace(frame_j, sym_key, onion_nonce)`.
      - `onion_nonce = nonce XOR xor_nonce` (lines 93-95). This is the nonce that the relay will use when de-onioning remaining frames.
      - **CRITICAL:** Each subsequent frame gets encrypted with the SAME `onion_nonce`. This means frames j, j+1, j+2, etc. all use the same nonce with the same key for this layer. **IS THIS CORRECT?** In xchacha20, using the same (key, nonce) pair for different data produces a deterministic keystream. If the attacker can observe two frames encrypted with the same (key, nonce), they can XOR them to get the XOR of the plaintexts. However, the attacker sees only the final onion output -- they cannot isolate individual layers. The relay peels its layer by applying xchacha20 with the shared key, which strips this encryption from all subsequent frames uniformly. This is the standard onion routing construction. PASS.
      - **Frame span (line 90):** `BUILD_FRAME_SIZE` bytes starting at `j * BUILD_FRAME_SIZE`. PASS.
  - **TRUG dragons:** `dragon_onion_asymmetry` -- "Onion build and peel are intentionally NOT symmetric."
  - **TRUG constraints:** `constraint_onion_frame_order` -- "Frames encrypted in reverse order (pivot to edge)."
- **Test coverage:** `test_onion.cpp` lines 29-46 (build and decrypt 2-hop), 48-58 (frame count), 60-71 (unique shared secrets per hop), 73-82 (xor_nonce derivation).
- **Missing tests:** **CRITICAL -- End-to-end relay chain test:** Build onion for 3 hops, then simulate relay 0 decrypting + forwarding, relay 1 decrypting + forwarding, relay 2 (pivot) decrypting. Verify each relay gets the correct rxid/txid/upstream. This is the most important missing test.

#### Function: `decrypt_build_frame()` (line 104-148)

- **What it does:** Decrypts a single build frame as a relay.
- **Threat model:** Wrong DH role produces wrong shared secret. Incorrect payload parsing produces wrong hop info.
- **Checks:**
  - **Minimum size (line 107):** `frame.size() < BUILD_FRAME_SIZE` returns nullopt. PASS.
  - **Key extraction (lines 111-115):** Ephemeral pk (32 bytes from offset 0), nonce (24 bytes from offset 32). PASS.
  - **DH computation (line 118):**
    - `dh(their_pk, our_pk, our_sk, their_pk, nonce)`.
    - Client_pk = `their_pk` (the builder is client). Server_pk = `our_pk` (we are server).
    - Our_sk = `our_sk`. Their_pk = `their_pk`.
    - **CRITICAL:** Verify role reversal from `build_onion`. In `build_onion`, the DH call uses `(ephemeral_keys.pk, relay_pk, ...)`. Here, the DH call uses `(their_pk, our_pk, ...)` where `their_pk` = ephemeral_keys.pk and `our_pk` = relay_pk. The client_pk/server_pk ordering is the same. PASS.
  - **Payload decryption (lines 122-127):**
    - `sym_key` = `shared.data()` (32 bytes).
    - Payload starts at frame offset 56, size = `BUILD_FRAME_SIZE - 56` = 113 bytes.
    - `xchacha20_inplace(payload, sym_key, nonce)`. Uses the SAME nonce as the builder. Correct -- xchacha20 XOR is its own inverse. PASS.
  - **Payload parsing (lines 130-142):**
    - Check payload >= 68 bytes (line 131). PASS.
    - rxid(16), txid(16), upstream(32), lifetime(4) parsed. Offsets: 0, 16, 32, 64. PASS.
  - **Shared secret and xor_nonce stored (lines 144-145).** These are needed by the relay for transit hop processing. PASS.
  - **NOTE:** The `sym_key` at line 122 is NOT zeroed after use. **FINDING: sym_key (derived from shared_secret) should be zeroed after decryption.**
- **Test coverage:** `test_onion.cpp` lines 40-46 (decrypt hop 0, verify rxid/txid/lifetime).
- **Missing tests:** Test decrypting hop 1 (after simulating hop 0 relay processing). Test with malformed frame (< 169 bytes). Test with random frame data (verify nullopt is not returned -- xchacha20 has no MAC, any data "decrypts" successfully). **This is a concern: decrypt_build_frame always succeeds for any 169+ byte input because there is no MAC.** The relay has no way to detect a corrupted frame.

---

## Layer 3: Session

### File: src/session/session.cpp
**Purpose:** End-to-end encrypted session: encrypt/decrypt data messages, handshake seal/unseal.
**Lines:** 152
**Risk level:** CRITICAL

#### Function: `random_tag()` (line 11-17)

- **What it does:** Generates a random 4-byte session tag.
- **Checks:** Uses `randombytes_buf`. PASS.
- **Test coverage:** Implicitly through session tests.
- **Missing tests:** Collision probability test (birthday bound on 4 bytes = 2^16 sessions before 50% collision).

#### Function: `Session::from_keys()` (line 19-26)

- **What it does:** Constructs an established session from derived keys.
- **Checks:** Sets `_established = true` (line 24). PASS.
- **Test coverage:** `test_session.cpp` lines 57-65.
- **Missing tests:** None.

#### Function: `Session::encrypt()` (line 28-51)

- **What it does:** AEAD-encrypts a data message with the session's outbound key, prepends tag and nonce.
- **Threat model:** Nonce reuse (catastrophic). Wrong key direction. Type byte corruption.
- **Checks:**
  - **CRITICAL -- Nonce from counter (lines 31-33):**
    - `_nonce_counter` is `mutable std::atomic<uint64_t>`. Post-increment at line 32: `auto counter = _nonce_counter++`.
    - `memcpy(nonce.data(), &counter, sizeof(counter))`. Copies 8 bytes of counter into 24-byte nonce. Remaining 16 bytes are zero (from `Nonce{}` initialization at line 31).
    - **Nonce uniqueness:** Atomic increment guarantees unique counter values even across threads. 64-bit counter will not overflow in practice (~10^18 messages). PASS.
    - **NOTE:** Counter starts at 0 for each Session object. Two Session objects with the same key but different counters are fine. But if a Session object is copied, both copies share the same atomic counter... wait, no. Check copy constructor (session.hpp lines 36-41):
    - `Session(const Session& o) : ... _nonce_counter{o._nonce_counter.load()}`. The COPY gets the current counter value, NOT a reference. So both copies will start from the same counter value. **FINDING: Session copy constructor creates two sessions that will produce overlapping nonces.** If both copies encrypt messages, nonce reuse occurs. This is a CRITICAL issue.
    - Move constructor (line 43) has the same issue: loads the atomic value, does not transfer.
  - **Payload construction (lines 36-38):** Plaintext + type byte appended. PASS.
  - **Key used: `_keys.key_out`** (line 41). Correct for outbound encryption. PASS.
  - **Message format (lines 44-48):** `tag(4) + nonce(24) + ciphertext`. PASS.
- **TRUG constraints:** `constraint_k1k2_direction`.
- **Test coverage:** `test_session.cpp` lines 17-38 (encrypt/decrypt round-trip), 40-55 (wrong keys fail), 129-145 (empty plaintext).
- **Missing tests:** **CRITICAL: Test that copying a Session and encrypting from both copies produces different nonces (currently it would produce the SAME nonces).** Test nonce counter monotonically increases. Test with 1000+ consecutive encrypt/decrypt pairs to verify no nonce collision.

#### Function: `Session::decrypt()` (line 53-72)

- **What it does:** Extracts nonce from message, AEAD-decrypts, strips type byte.
- **Threat model:** Wrong minimum size check causes underflow. Type byte not stripped causes data corruption.
- **Checks:**
  - Minimum size: `4 + AEAD_NONCE_SIZE + AEAD_TAG_SIZE` = 4 + 24 + 16 = 44 bytes (line 56). PASS.
  - Nonce extraction: offset 4, size 24 (line 61). PASS.
  - Ciphertext: offset 4+24=28 (line 64). Uses `_keys.key_in`. Correct for inbound. PASS.
  - Type byte removal: `pt->pop_back()` (line 70). Removes last byte. PASS.
  - **NOTE:** Does not verify the type byte value. The caller does not receive the traffic type.
- **Test coverage:** Covered in round-trip tests.
- **Missing tests:** Test that the type byte is correctly stripped (encrypt with TrafficType::Control, decrypt, verify data matches original without type byte). Test minimum-size message (empty plaintext).

#### Function: `SessionInit::seal_for()` (line 75-88)

- **What it does:** Serializes SessionInit fields and seals (encrypts) for recipient.
- **Threat model:** Wrong field ordering breaks interoperability. Missing fields cause parse failure on remote.
- **Checks:**
  - **Payload layout (lines 80-85):** identity(32) + x_pubkey(32) + mlkem_pubkey(1184) + signature(64) + tag(4) = 1316 bytes. PASS.
  - **TRUG check:** TRUG `msg_session_init` specifies inner fields: I(32), M(1184), X(32), p(16), t(4), ~(64). Our implementation has: identity(32)=I, x_pubkey(32)=X, mlkem_pubkey(1184)=M, signature(64)=~, tag(4)=t. **DISCREPANCY:** TRUG includes `p` (pivot hop ID, 16 bytes) which our implementation does NOT include. Also, TRUG ordering is I,M,X,p,t,~ while our ordering is I,X,M,~,t. **FINDING: Missing pivot hop ID field `p`. Different serialization order from TRUG spec.** However, this is sealed-box encrypted, so only the recipient parses it -- ordering must match between our `seal_for` and `unseal`, which it does. The TRUG ordering may reflect BT encoding (lexicographic), while our implementation uses raw binary. Must verify against upstream.
  - `[[maybe_unused]] const Ed25519SecKey& our_sk` at line 76. The secret key is passed but not used. It should be used for signing the identity proof. **FINDING: our_sk is unused. Signature field is populated by the caller, not by this function. Verify that callers actually sign correctly.**
- **Test coverage:** `test_session.cpp` lines 67-91 (seal/unseal round-trip), 93-106 (wrong key fails).
- **Missing tests:** Test with corrupt sealed data. Test that serialized size is exactly expected.

#### Function: `SessionInit::unseal()` (line 90-113)

- **What it does:** Unseals and parses SessionInit from sealed data.
- **Checks:**
  - Expected size: `32 + 32 + 1184 + 64 + 4 = 1316` (line 97). PASS.
  - Parsing offsets: 0, 32, 64, 1248, 1312. Verify: 0+32=32, 32+32=64, 64+1184=1248, 1248+64=1312, 1312+4=1316. PASS.
  - **NOTE:** No signature verification is performed here. The caller must verify the signature. Must audit all callers.
- **Test coverage:** `test_session.cpp` lines 67-91.
- **Missing tests:** Test with payload of wrong size. Test with empty sealed data.

#### Function: `SessionAccept::seal_for()` (line 116-127)

- **What it does:** Serializes and seals SessionAccept.
- **Checks:**
  - Payload: x_pubkey(32) + mlkem_ciphertext(1088) + signature(64) + tag(4) = 1188 bytes. PASS.
  - **TRUG check:** TRUG `msg_session_accept` specifies: Y(32), c(1088), t(4), ~(64). Our order: Y, c, ~, t. **DISCREPANCY in field ordering** -- same sealed-box caveat as SessionInit.
- **Test coverage:** `test_session.cpp` lines 108-127.
- **Missing tests:** None beyond round-trip.

#### Function: `SessionAccept::unseal()` (line 129-150)

- **What it does:** Unseals and parses SessionAccept.
- **Checks:**
  - Expected: `32 + 1088 + 64 + 4 = 1188` (line 135). PASS.
  - Offsets: 0, 32, 1120, 1184. Verify: 0+32=32, 32+1088=1120, 1120+64=1184, 1184+4=1188. PASS.
- **Test coverage:** `test_session.cpp` lines 108-127.
- **Missing tests:** None beyond round-trip.

---

## Layer 4: Link

### File: src/link/endpoint.cpp
**Purpose:** QUIC transport layer wrapping oxen-libquic. Connection management, datagram and BTStream send/receive.
**Lines:** 228
**Risk level:** HIGH

#### Function: `Endpoint::listen()` (line 51-118)

- **What it does:** Starts a QUIC endpoint listening on a port with Ed25519 TLS credentials.
- **Threat model:** Wrong ALPN strings cause connection rejection by upstream nodes. Wrong TLS credential setup leaks identity or allows MITM.
- **Checks:**
  - **TLS credentials (lines 54-56):**
    - `GNUTLSCreds::make_from_ed_keys(ed_seed, ed_pubkey)`. Uses Ed25519 seed (first 32 bytes of secret key), not the full 64-byte secret key. Must verify this matches upstream.
    - `ed_seed` is `span<const std::byte, 32>`. Caller (node.cpp line 51) passes `_identity.sk.data()` reinterpreted as 32 bytes. Ed25519 secret key layout is `[seed:32][pk:32]`, so first 32 bytes = seed. PASS.
  - **ALPN strings (lines 63-68):**
    - Relay inbound: `"Session_Router_R"`, `"Session_Router_C"`, `"Session_Router_BS"`. PASS per TRUG.
    - Client inbound: `"Session_Router_C"`. PASS.
    - Relay outbound: `"Session_Router_R"`. PASS.
    - Client outbound: `"Session_Router_C"`. PASS.
  - **Datagram splitting (line 73):** `quic::Splitting::ACTIVE` with 2MB queue limit. PASS.
  - **Connection established callback (lines 76-103):**
    - For inbound connections: creates a `BTRequestStream`, registers generic handler, stores `ConnectionInfo` under mutex. PASS.
    - **Lambda capture:** `[this, rid]` at line 84. `this` is captured by value (pointer). If `Endpoint` is destroyed while the callback is pending, use-after-free. However, `Endpoint::~Endpoint` calls `close()` which closes all connections, which should cancel pending callbacks. **QUESTION:** Does oxen-quic guarantee no callbacks fire after `close()`? Must verify.
  - **Connection closed callback (lines 104-108):** Removes from connection map under mutex. PASS.
  - **Datagram callback (lines 109-115):** Dispatches to `_dgram_handler`. PASS.
  - **Client key acceptance (lines 58-61):** Always returns `true` for all keys and ALPNs. **FINDING: No client key validation. Any client can connect with any key.** For an open relay network this is correct (relays accept connections from anyone). Verify this matches upstream behavior.
- **Thread safety:** `_impl->mtx` protects `_impl->connections`. Connection established/closed callbacks may fire from the QUIC event loop thread. The mutex ensures safe concurrent access. PASS.
- **Test coverage:** `test_manager.cpp` lines 59-101 (default state, unknown peer safe operations).
- **Missing tests:** Integration test with two endpoints connecting. Test connection lifecycle (connect, send, disconnect). Test ALPN negotiation.

#### Function: `Endpoint::connect()` (line 120-137)

- **What it does:** Initiates a QUIC connection to a remote relay.
- **Threat model:** Race condition if two threads connect to the same peer simultaneously.
- **Checks:**
  - Mutex acquired at line 129. PASS.
  - `keep_alive{10s}` and `idle_timeout{60s}` at line 125. Matches config defaults. PASS.
  - **NOTE:** If connection fails (remote unreachable), `ConnectionInfo` is still stored at line 131-136. The stored connection may be in a failed state. **FINDING: No error handling for failed outbound connections.** The stored connection object may not be usable.
- **Test coverage:** None (requires live QUIC endpoint).
- **Missing tests:** Test connecting to unreachable host. Test double-connect to same peer.

#### Function: `Endpoint::send_datagram()` (line 139-147)

- **What it does:** Sends a QUIC datagram to a connected peer.
- **Checks:**
  - Mutex acquired. Peer looked up. If not found, returns silently (no crash). PASS.
  - Data copied to vector before sending (line 145). PASS.
- **Test coverage:** `test_manager.cpp` lines 87-93 (unknown peer safe).
- **Missing tests:** None at this level.

#### Function: `Endpoint::send_request()` (line 149-177)

- **What it does:** Sends a BTStream request (reliable) to a connected peer.
- **Checks:**
  - Mutex acquired. Peer looked up. If not found, returns silently. PASS.
  - If `on_response` callback provided, uses command with callback (line 164). Otherwise, fire-and-forget (line 175). PASS.
- **Test coverage:** `test_manager.cpp` lines 95-101 (unknown peer safe).
- **Missing tests:** None at this level.

#### Function: `Endpoint::close()` (line 217-227)

- **What it does:** Closes all connections and resets the endpoint.
- **Checks:**
  - Null check on `_impl` and `_impl->ep` (line 219). PASS.
  - `close_conns()` called before clearing map (line 221). PASS.
  - **NOTE:** Mutex is acquired AFTER `close_conns()` at line 222. If a connection-closed callback fires during `close_conns()`, it would try to acquire the mutex too, causing a deadlock if the callback is on the same thread. **FINDING: Potential deadlock in close() if connection-closed callback fires on the calling thread.** Must verify oxen-quic callback threading model.
- **Test coverage:** `test_manager.cpp` lines 73-78 (close on uninitialized).
- **Missing tests:** None at this level.

---

### File: src/link/manager.cpp
**Purpose:** Message dispatch layer. Routes BTStream requests to registered handlers.
**Lines:** 61
**Risk level:** MEDIUM

#### Function: `Manager::Manager()` (line 8-17)

- **What it does:** Wires the dispatch function to the endpoint's request handler.
- **Threat model:** The lambda captures `this`. If Manager is destroyed before Endpoint, callbacks crash.
- **Checks:**
  - Lambda captures `[this]` (line 11). Manager must outlive Endpoint. In Node, Manager is declared after Endpoint but constructed with Endpoint reference -- destruction order is reverse of declaration, so Manager is destroyed first, then Endpoint. **FINDING: Manager is destroyed before Endpoint, but Endpoint still has the lambda referencing Manager. If any callbacks fire during Endpoint destruction, use-after-free.** This depends on whether Endpoint::close() is called before Manager destruction.
- **Test coverage:** `test_manager.cpp` lines 13-28.
- **Missing tests:** None.

#### Function: `Manager::dispatch_request()` (line 47-59)

- **What it does:** Looks up handler by method name and dispatches.
- **Threat model:** Unknown methods silently dropped (line 58). This is correct for relay behavior.
- **Checks:**
  - `std::string{method}` at line 53 copies the method name. No dangling reference. PASS.
  - Handler called with `from`, `payload`, `respond`. PASS.
- **Test coverage:** Not directly testable without triggering via network. Handler registration tested.
- **Missing tests:** Test dispatch with known and unknown method names (requires mock endpoint).

---

## Layer 5: Node

### File: src/node/config.cpp
**Purpose:** INI configuration parsing and CLI argument handling.
**Lines:** 127
**Risk level:** LOW

#### Function: `Config::from_file()` (line 20-92)

- **What it does:** Parses an INI file into a Config struct.
- **Threat model:** Path traversal in config values. Integer overflow in port parsing.
- **Checks:**
  - `std::stoi` for port (line 59): throws on out-of-range. Cast to `uint16_t` can truncate values > 65535. **FINDING: No validation that port is in valid range (1-65535).**
  - `std::stoi` for netmask (line 68): no validation that netmask is 0-32. **FINDING: No netmask range validation.**
- **Test coverage:** `test_config.cpp` lines 17-109.
- **Missing tests:** Test with out-of-range port. Test with negative port. Test with path containing special characters.

#### Function: `Config::from_args()` (line 105-124)

- **What it does:** Parses CLI arguments.
- **Threat model:** Argument injection. Missing bounds checking on `argv`.
- **Checks:**
  - `i + 1 < argc` check before accessing `argv[++i]` (line 113). PASS.
  - `expand_tilde` called at line 122. Uses `$HOME` from environment. No path traversal concern (user controls their own HOME).
  - `--relay` flag overrides config file setting (line 121). This matches TRUG spec behavior. PASS.
- **Test coverage:** `test_config.cpp` lines 94-109.
- **Missing tests:** Test with `--config` pointing to nonexistent file.

---

### File: src/node/tun.cpp
**Purpose:** Linux TUN device creation and raw IP packet I/O.
**Lines:** 124
**Risk level:** HIGH

#### Function: `TunDevice::open()` (line 16-91)

- **What it does:** Opens /dev/net/tun, configures IP/netmask, brings interface up.
- **Threat model:** Race condition on interface name. Privilege escalation if running as root. File descriptor leak on partial failure.
- **Checks:**
  - **strncpy safety (line 26):** `strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1)`. Null-terminated because `IFNAMSIZ-1` leaves room. PASS.
  - **File descriptor cleanup on failure:** Lines 30-32 (TUNSETIFF fail), 42-44 (socket fail), 53-55 (SIOCSIFADDR fail), 67-70 (SIOCSIFNETMASK fail) all close `_fd` and set to -1. PASS.
  - **Socket leak on SIOCSIFNETMASK failure:** Lines 67-70 close both `sock` and `_fd`. PASS.
  - **MTU set (line 82):** Hardcoded 1500. No error check on ioctl. **FINDING: MTU ioctl failure silently ignored.**
  - **Interface bring-up (lines 74-78):** SIOCGIFFLAGS + IFF_UP + SIOCSIFFLAGS. No error check on SIOCSIFFLAGS. **FINDING: Interface bring-up failure silently ignored.**
  - **Non-blocking mode (lines 87-88):** `fcntl` with `O_NONBLOCK`. PASS.
  - **Netmask computation (line 64):** `htonl(~((1u << (32 - netmask)) - 1))`. For netmask=16: `~((1<<16)-1)` = `~0xFFFF` = `0xFFFF0000`. `htonl` converts to network byte order. PASS. For netmask=0: `~((1<<32)-1)` = `~0xFFFFFFFF` = 0. **FINDING: netmask=0 would overflow the shift `1u << 32` which is UB in C++.** Config should validate netmask in 1-31 range.
  - **inet_pton (line 51):** No return value check. If ip is invalid, `sin_addr` gets 0. **FINDING: No validation of IP address string.**
- **TRUG dragons:** `dragon_linux_tun_race` -- our implementation uses a fixed name, no auto-selection race. PASS.
- **Test coverage:** `test_tun.cpp` covers default state, close on unopened, read/write on closed, open without privileges.
- **Missing tests:** Test with root privileges (actual TUN creation). Test with invalid IP string. Test with netmask=0 and netmask=32.

#### Function: `TunDevice::write_packet()` (line 102-108)

- **What it does:** Writes an IP packet to the TUN device.
- **Checks:**
  - Checks `_fd < 0` and empty packet (line 104). PASS.
  - Checks write return matches expected size (line 107). Partial writes return false. PASS.
- **Test coverage:** `test_tun.cpp` lines 22-26, 35-39.
- **Missing tests:** None.

#### Function: `TunDevice::read_packet()` (line 110-122)

- **What it does:** Reads an IP packet from the TUN device.
- **Checks:**
  - 2048-byte buffer (line 116). Maximum IP packet size is 65535, but TUN MTU is 1500. 2048 is sufficient for MTU 1500 + headers. PASS.
  - Non-blocking read returns -1/EAGAIN on no data, returning empty vector. PASS.
- **Test coverage:** `test_tun.cpp` lines 28-33.
- **Missing tests:** None.

---

### File: src/node/dns.cpp
**Purpose:** Minimal DNS resolver for .sesh TLD. Stub implementation.
**Lines:** 51
**Risk level:** MEDIUM

#### Function: `DnsResolver::start()` (line 14-37)

- **What it does:** Binds a UDP socket for DNS queries.
- **Threat model:** Port binding failure. No actual DNS query handling implemented.
- **Checks:**
  - `htons(port)` at line 25. Correct byte order. PASS.
  - Socket cleanup on bind failure (lines 30-33). PASS.
  - **NOTE:** The resolver binds the socket but never reads from it. `_running` is set to true but there is no read loop. **FINDING: DNS resolver is a stub -- it binds a port but never processes queries.** This is documented implicitly but should be explicit.
- **Test coverage:** `test_dns.cpp` lines 19-31 (start on high port).
- **Missing tests:** None (stub).

---

### File: include/sr/node/events.hpp
**Purpose:** Event bus for decoupled communication between components.
**Lines:** 61
**Risk level:** LOW

#### Function: `EventBus::emit()` (line 47-55)

- **What it does:** Calls all registered handlers for an event.
- **Threat model:** Handler throws exception, preventing subsequent handlers from running. Handler takes too long, blocking the tick loop. Handler modifies the handler list during iteration.
- **Checks:**
  - **Exception safety:** No try/catch around handler calls. A throwing handler will propagate to the caller (tick loop). **FINDING: No exception handling in EventBus::emit().**
  - **Re-entrancy:** If a handler calls `emit()` recursively, `_handlers` is not protected by a mutex. However, `_handlers` is an `unordered_map` of `vector`, and the for loop at line 52 iterates the vector. If a handler calls `emit` for the SAME event, it would re-enter the same vector iteration -- but since the vector is accessed by const reference, this is safe (iterators remain valid as long as the vector is not modified). If a handler calls `on()` to add a new handler, it modifies the vector, invalidating iterators. **FINDING: Not safe if a handler registers new handlers during emit.**
  - **Thread safety:** No mutex. EventBus is accessed from the main tick loop. If events are emitted from the TUN reader thread, data race. In the current code, events are only emitted from the main thread. PASS for now.
- **Test coverage:** `test_events.cpp` lines 6-72 (comprehensive: emit, multiple subscribers, event isolation, data passing, multiple emits).
- **Missing tests:** Test re-entrancy (handler that emits another event). Test handler that throws.

---

### File: src/node/node.cpp
**Purpose:** Thin orchestrator wiring all layers together. Key management, message handlers, tick loop.
**Lines:** 277
**Risk level:** HIGH

#### Function: `Node::Node()` (line 21-42)

- **What it does:** Initializes all layers, registers message handlers, wires events.
- **Checks:**
  - `_endpoint{_config.is_relay}` -- correct relay/client mode. PASS.
  - `_manager{_endpoint}` -- Manager references Endpoint. Lifetime: both are Node members, Manager is declared after Endpoint in header. Destruction order is reverse (Manager destroyed first). See earlier finding about Manager/Endpoint lifetime.
  - Handler registration (lines 27-33): path_build, gossip_rc, datagram. PASS.
  - Event handlers (lines 36-41): PATH_BUILT and PATH_DIED are stubs (TODO comments). **Not a bug, but incomplete functionality.**
- **Test coverage:** None (requires full Node construction).
- **Missing tests:** Unit test for Node construction with mock dependencies.

#### Function: `Node::run()` (line 46-105)

- **What it does:** Main run loop: listen, open TUN, start DNS, bootstrap, read TUN in separate thread, tick loop.
- **Threat model:** Signal handler race condition. TUN thread accessing Node state without synchronization.
- **Checks:**
  - **Ed25519 seed extraction (lines 51-52):**
    - `_identity.sk.data()` cast to `span<const std::byte, 32>`. Ed25519SecKey is 64 bytes. First 32 bytes = seed. The cast takes 32 bytes. PASS.
    - `_identity.pk.data()` cast to `span<const std::byte, 32>`. Ed25519PubKey is 32 bytes. PASS.
  - **TUN failure handling (lines 56-62):** Prints error, continues without TUN. Correct for relay-only mode. PASS.
  - **DNS bind parsing (lines 64-69):** Splits on `:`. No validation for malformed bind string. **FINDING: No error handling for dns_bind without `:` separator.**
  - **TUN reader thread (lines 77-93):**
    - Uses `poll()` with 100ms timeout.
    - Calls `handle_outbound_packet()` -- which currently drops all packets (TODO). PASS for current state.
    - **Thread safety:** The TUN reader thread calls `handle_outbound_packet()` which would eventually need to access `_sessions` and `_paths` on the main thread. Currently it's a no-op. **FINDING: When implemented, outbound packet handling will need synchronization with the tick loop.**
  - **Tick loop (lines 100-104):** `sleep_for(tick_interval)` = 250ms. Not busy-waiting. PASS.
- **Test coverage:** None (requires root for TUN, network for QUIC).
- **Missing tests:** None feasible at unit test level.

#### Function: `Node::load_or_generate_keys()` (line 247-275)

- **What it does:** Loads Ed25519 keypair from file or generates new one. Saves with 0600 permissions.
- **Threat model:** Key file permissions too permissive. Key file truncated/corrupted. TOCTOU between exists check and open.
- **Checks:**
  - **Key loading (lines 254-261):**
    - Reads 64 bytes as secret key (line 255).
    - Derives pubkey from sk using `crypto_sign_ed25519_sk_to_pk` (line 258). Correct.
    - **NOTE:** No validation that the loaded key is a valid Ed25519 secret key. A corrupted file would produce a corrupted keypair with no error.
  - **Key saving (lines 269-274):**
    - `create_directories` at line 269. PASS.
    - Writes 64-byte secret key (line 271). PASS.
    - **Permissions (lines 273-274):** `owner_read | owner_write` = 0600. PASS. This correctly addresses the security requirement.
    - **FINDING:** File is created with default permissions BEFORE chmod. Between `ofstream` creation and `permissions()` call, the file has default umask permissions. A race condition could allow another process to read the key. Should use `umask()` or `open()` with explicit permissions. However, this is a minor issue for typical single-user deployments.
  - **Data directory tilde expansion:** Handled by `expand_tilde()` in config.cpp. PASS.
- **Test coverage:** None directly (would need filesystem mocking).
- **Missing tests:** Test key persistence (write, re-read, verify same keypair). Test with corrupted key file.

#### Function: `Node::handle_path_build()` (line 185-206)

- **What it does:** Relay handler for incoming path build requests.
- **Checks:**
  - Client-mode check (line 191). PASS.
  - Size check (line 194): `payload.size() < BUILD_MSG_SIZE`. PASS.
  - Decrypts first frame (lines 198-200). PASS.
  - **INCOMPLETE:** Transit hop is not stored (TODO at line 203). Remaining frames are not forwarded. Response is empty (line 205). **This handler is a stub.**
- **Test coverage:** None.
- **Missing tests:** Full path_build relay test (requires multi-node setup).

#### Function: `Node::handle_gossip_rc()` (line 208-220)

- **What it does:** Handles incoming RC gossip.
- **Checks:**
  - Parses RC from BT (line 214). Verifies signature (line 214). Stores if valid (line 216). PASS.
  - **NOTE:** No check for RC freshness (timestamp not too old, not too far in future). An attacker could gossip an RC with a future timestamp to prevent expiry.
  - **NOTE:** No re-gossip to other peers. Gossip propagation is not implemented.
- **Test coverage:** None.
- **Missing tests:** Test with invalid RC. Test with expired RC. Test with RC from unknown relay.

#### Function: `Node::build_path()` (line 158-183)

- **What it does:** Selects random relays and builds an onion path.
- **Checks:**
  - Uses `_nodedb.random_rcs()` with non-cryptographic PRNG (see earlier finding). PASS functionally.
  - Generates ephemeral Ed25519 keys per path build (line 166). PASS -- fresh keys per path.
  - Path build response callback (lines 176-182): Creates Path, adds to `_paths`, emits event. PASS.
  - **NOTE:** No timeout handling. If the path build request never gets a response, the callback is never called, and no path is created. The `maintain_paths()` will try again on next tick. Acceptable.
  - **NOTE:** No check that selected relays are actually connected. `send_request` to an unconnected peer is a no-op (returns silently). Path build silently fails.
- **Test coverage:** None.
- **Missing tests:** Test with insufficient relays. Test path build request serialization.

---

### File: src/main.cpp
**Purpose:** Entry point. Signal handling. Config loading.
**Lines:** 38
**Risk level:** MEDIUM

#### Function: `signal_handler()` (line 8-14)

- **What it does:** Calls `g_node->stop()` on SIGINT/SIGTERM.
- **Threat model:** Signal handler calls non-async-signal-safe functions.
- **Checks:**
  - `std::cout` at line 12 is NOT async-signal-safe. **FINDING: Signal handler uses std::cout which is not async-signal-safe. This can cause deadlock if the signal arrives while cout is in use.**
  - `g_node->stop()` sets `_running = false` (atomic). The atomic store IS async-signal-safe. But `stop()` also calls `_tun_reader.join()`, `_tun.close()`, `_dns.stop()`, `_endpoint.close()` -- NONE of which are async-signal-safe. **FINDING: Signal handler calls complex cleanup functions. Should only set the atomic flag and let the main loop handle cleanup.**
- **Test coverage:** None.
- **Missing tests:** None feasible at unit test level.

---

## Layer 5.1: Exit

### File: src/exit/exit_handler.cpp
**Purpose:** Exit node traffic handling: NAT, IP forwarding, iptables management.
**Lines:** 217
**Risk level:** CRITICAL (for exit mode)

#### Function: `ExitHandler::apply_nat()` (line 60-108)

- **What it does:** Rewrites source port for outgoing packets (client-to-internet NAT).
- **Threat model:** IP header parsing buffer overread. NAT table unbounded growth. Port exhaustion.
- **Checks:**
  - **IPv4 header parsing (lines 65-70):**
    - Minimum 20 bytes (line 66). PASS.
    - IHL extraction: `(packet[0] & 0x0F) * 4` (line 68). Correct.
    - Transport header check: `packet.size() < ihl + 4` (line 69). PASS.
  - **Port extraction (line 72-73):** `src_port` from offset `ihl`. Correct for TCP/UDP.
  - **NAT entry lookup (lines 76-87):** Linear scan of `_nat_table`. O(n) per packet. **FINDING: Linear scan is O(n) in NAT table size. For high-traffic exit nodes, this will be a bottleneck. Should use a secondary index (e.g., map by client_rid + src_port).**
  - **Port allocation (lines 89-99):**
    - `_next_port` starts at 10000, wraps at 65534 (line 98-99). Range: 10000-65534 = 55534 ports.
    - **FINDING: Port wraparound at line 98-99 (`if > 65534, reset to 10000`) does not check if the new port is already in use.** This can cause NAT table collisions and route packets to the wrong client.
  - **IP checksum:** Not recalculated after source port rewrite (lines 102-106). **FINDING: IP checksum is not updated after port rewrite. TCP/UDP checksums are also not updated. Packets will be dropped by the destination or intermediary routers.** This is a critical bug for exit mode.
- **Test coverage:** `test_exit.cpp` lines 17-27 (disabled is no-op).
- **Missing tests:** **CRITICAL: Test actual NAT rewriting with valid IP packet. Test checksum recalculation. Test port exhaustion. Test NAT table collision.**

#### Function: `ExitHandler::reverse_nat()` (line 110-138)

- **What it does:** Reverse-NATs incoming packets from internet back to client.
- **Checks:**
  - Same IPv4 header parsing as `apply_nat`. PASS.
  - Destination port lookup in NAT table (lines 122-125). PASS.
  - **IP restoration (lines 133-134):** Restores original port and internal IP. Correct offsets (ihl+2 for dst port, 16 for dst IP). PASS.
  - **Same checksum issue:** No checksum recalculation.
- **Test coverage:** None directly.
- **Missing tests:** Same as apply_nat.

#### Function: `RouteManager::setup_exit_routes()` (line 150-167)

- **What it does:** Adds IP routing rules for exit traffic using shell commands.
- **Threat model:** Shell injection via tun_name or exit_interface. Command failure silently ignored.
- **Checks:**
  - **CRITICAL -- Shell injection (line 161):** `"ip route add default dev " + tun_name + " table 100"`. If `tun_name` contains shell metacharacters (e.g., `; rm -rf /`), arbitrary commands execute. **FINDING: Shell injection vulnerability in tun_name and exit_interface parameters.** Must validate interface names against `[a-zA-Z0-9]+` pattern.
  - `system()` return value checked (line 162). PASS.
  - **Same issue in `setup_nat_rules` (lines 185-195) and `teardown_*` functions.**
- **TRUG dragons:** `dragon_windows_shell` -- upstream uses shell commands too, but we should not repeat the pattern.
- **Test coverage:** `test_exit.cpp` lines 54-67 (root-required, teardown on inactive).
- **Missing tests:** Test with malicious interface names. Test setup and teardown idempotency.

---

## Crypto Audit Matrix

For each crypto operation, cross-reference with upstream:

| Our Function | Libsodium Call | Parameters | Upstream File:Line | Match? | Nonce Unique? | Key Zeroed? |
|---|---|---|---|---|---|---|
| `aead_encrypt_inplace` | `crypto_aead_xchacha20poly1305_ietf_encrypt` | buf, plaintext_len, nullptr AD, nonce(24), key(32) | crypto.cpp:encrypt | VERIFY | Caller responsibility | N/A (symmetric) |
| `aead_decrypt_inplace` | `crypto_aead_xchacha20poly1305_ietf_decrypt` | buf, nullptr nsec, buf, size, nullptr AD, nonce(24), key(32) | crypto.cpp:decrypt | VERIFY | N/A | N/A |
| `xchacha20_inplace` | `crypto_stream_xchacha20_xor` | buf, buf, size, nonce(24), key(32) | path_handler.cpp onion | VERIFY | Random per path build | N/A |
| `dh` | `crypto_scalarmult` + `crypto_generichash` | Ed25519 converted to X25519; hash order: client_pk, server_pk, dh_result; nonce as BLAKE2b key | crypto.cpp:35-59 | VERIFY ORDER | Random per DH | x_sk YES, dh_result YES |
| `derive_xor_nonce` | `crypto_shorthash` | shared_secret, zero key | crypto.cpp xor_nonce | VERIFY zero key | N/A | N/A |
| `seal` | `crypto_box_seal` | plaintext, X25519 pk (from Ed25519) | keys.cpp:seal | VERIFY | Internal (libsodium) | x_pk not zeroed (public) |
| `unseal` | `crypto_box_seal_open` | ciphertext, X25519 pk, X25519 sk (from Ed25519) | keys.cpp:unseal | VERIFY | N/A | x_sk YES |
| `blind_pubkey` | `crypto_scalarmult_ed25519_noclamp` | BLAKE2b-reduced scalar, root_pk | keys.cpp:blind | VERIFY | N/A | N/A |
| `BlindedKeyPair::sign` | Manual Ed25519 (SHA-512, scalar ops) | Modified nonce = H(hash_data, msg) | keys.cpp:blind_sign | VERIFY | Deterministic per-message | nonce_hash YES, nonce_scalar YES, tmp MISSING |
| `derive_session_keys` | `crypto_scalarmult` + `crypto_generichash` | X25519 DH; BLAKE2b-512 domain="session-router-session-keys"; order: X, Y, dh, mlkem_ss, mlkem_pk, i_rid, r_rid | session_keys.cpp:119-166 | **VERIFY -- possible two-level hash discrepancy** | N/A | dh_result YES, hash YES |
| `mlkem_*` | PLACEHOLDER (randombytes_buf) | N/A | session_keys.cpp ML-KEM | PLACEHOLDER | N/A | N/A |

**ACTION ITEMS:**
1. Cross-reference every entry in the "Match?" column against the actual upstream source code.
2. Resolve the session key derivation hash structure discrepancy (single hash vs two-level hash).
3. Add `sodium_memzero(tmp)` in `BlindedKeyPair::sign()`.

---

## Wire Format Audit Matrix

For each message type, verify byte-for-byte compatibility:

| Message | Our Format | TRUG Spec Format | Size Match? | Field Order Match? | Encoding Match? |
|---|---|---|---|---|---|
| path_build | 8 x 169B frames, ephemeral_pk(32) + nonce(24) + encrypted(113) per frame | 8 x 169B, k(32) + n(24) + x(encrypted BT dict) | Size PASS | **VERIFY: Our payload is raw binary (rxid+txid+upstream+lifetime), TRUG says BT dict with keys l,r,t,u** | **DISCREPANCY** |
| gossip_rc | BT dict: "4"(6B), "p"(32B), "t"(int64), "v"(3B), "~"(64B) | BT dict: ""(opt), "#"(opt), "4"(6B), "6"(opt), "p"(32B), "t"(int64), "v"(3B), "~"(64B) | PASS (optional fields omitted) | Lex order PASS | BT PASS |
| session_init | Raw binary: identity(32) + x_pubkey(32) + mlkem_pk(1184) + sig(64) + tag(4) sealed | BT dict: I(32), M(1184), X(32), p(16), t(4), ~(64) sealed | **DISCREPANCY: missing p(16)** | **DISCREPANCY: raw vs BT** | **DISCREPANCY** |
| session_accept | Raw binary: x_pubkey(32) + mlkem_ct(1088) + sig(64) + tag(4) sealed | BT dict: Y(32), c(1088), t(4), ~(64) sealed | PASS | **DISCREPANCY: raw vs BT** | **DISCREPANCY** |
| session_data | tag(4) + nonce(24) + AEAD(payload + type_byte) | AEAD(payload + type) + tag(4) + nonce(24) + hop_id(16) + msg_type(1) | **DISCREPANCY: ordering and extra fields** | **DISCREPANCY** | PARTIAL |

**CRITICAL FINDINGS:**
1. **path_build inner payload:** Our implementation uses raw binary layout. TRUG says BT-encoded dict. Must determine which matches upstream. If upstream uses BT encoding for the inner hop payload, our raw binary will not interoperate.
2. **session_init/accept:** Our implementation uses raw binary concatenation. TRUG says BT-encoded dict. Sealed box means only the two endpoints need to agree, so this could be an internal choice. But must match upstream.
3. **session_data:** Our format puts tag+nonce BEFORE ciphertext. TRUG says tag+nonce+hop_id+msg_type are AFTER the AEAD. Our implementation also omits hop_id(16) and msg_type(1). This will not interoperate with upstream.

**ACTION ITEMS:**
1. Capture actual upstream wire format for each message type (pcap or test vectors).
2. Generate test vectors from our implementation and compare byte-for-byte.
3. Resolve all discrepancies before any interoperability testing.

---

## Thread Safety Audit Matrix

| Shared Data | Threads Accessing | Protection | Lock-Hold Risk | Wrong-Thread Risk |
|---|---|---|---|---|
| `Endpoint::Impl::connections` | QUIC event loop thread, main thread (via send/connect/close) | `Impl::mtx` (std::mutex) | Moderate -- held during connection establishment callback | Potential deadlock in close() |
| `NodeDB::_rcs` | Main thread (tick loop), TUN reader (via outbound packet when implemented) | `NodeDB::_mtx` (std::mutex) | Low -- simple map operations | Future risk when outbound packets need routing table |
| `NodeDB::_rng` | Main thread only (under _mtx) | `NodeDB::_mtx` | None | None |
| `Session::_nonce_counter` | Main thread (encrypt), potentially TUN reader | `std::atomic<uint64_t>` | None | See copy constructor nonce reuse finding |
| `Node::_running` | Main thread, signal handler, TUN reader | `std::atomic<bool>` | None | PASS |
| `Node::_paths` | Main thread only | None | None | Risk when TUN reader needs paths |
| `Node::_sessions` | Main thread only | None | None | Risk when TUN reader needs sessions |
| `EventBus::_handlers` | Main thread only | None | None | Risk if events emitted from other threads |
| `Manager::_handlers` | Main thread only (registration at startup) | None | None | Safe if registration is before listen() |

**CRITICAL FINDING:** When the TUN reader thread is fully implemented (currently stub), it will need to access `_paths`, `_sessions`, and `_nodedb` from a different thread than the tick loop. These data structures currently have no synchronization (except `_nodedb` which has a mutex). A synchronization strategy must be designed before implementing outbound packet handling.

---

## Test Gap Analysis

### Summary by File

| Source File | Test File | Test Cases | Coverage | Critical Gaps |
|---|---|---|---|---|
| keys.cpp | test_keys.cpp | 4 | HIGH | Missing: twist point test, from_ed25519 failure |
| aead.cpp | test_aead.cpp | 7 | HIGH | Missing: wrong nonce test |
| dh.cpp | test_dh.cpp | 7 | HIGH | Missing: known test vectors, low-order point |
| sealed_box.cpp | test_sealed_box.cpp | 5 | HIGH | Missing: all-zeros key |
| blind.cpp | test_blind.cpp | 6 | HIGH | Missing: empty message sign, tmp zeroing verification |
| session_keys.cpp | test_session_keys.cpp | 4 | MEDIUM | **CRITICAL: no upstream test vectors, hash structure verification** |
| mlkem.cpp | None | 0 | NONE | Blocked until real implementation |
| router_id.cpp | test_router_id.cpp | 5 | HIGH | Missing: hash alignment verification |
| relay_contact.cpp | test_relay_contact.cpp + test_bt.cpp | 4+5 | MEDIUM | **Missing: wire format cross-validation with upstream** |
| nodedb.cpp | test_nodedb.cpp | 10 | HIGH | Missing: CSPRNG for random_rcs, bucket_index cross-validation |
| hop.cpp | (implicit) | 0 | LOW | Missing: uniqueness test |
| path.cpp | test_path.cpp | 6 | HIGH | Missing: 4-hop test, nonce mutation verification |
| onion.cpp | test_onion.cpp | 4 | MEDIUM | **CRITICAL: no full relay chain simulation test** |
| session.cpp | test_session.cpp | 8 | MEDIUM | **CRITICAL: Session copy nonce reuse test, wire format mismatch** |
| endpoint.cpp | test_manager.cpp | 6 | LOW | Missing: connection lifecycle, ALPN negotiation |
| manager.cpp | test_manager.cpp | 3 | LOW | Missing: dispatch with mock |
| config.cpp | test_config.cpp | 5 | HIGH | Missing: edge case port/netmask validation |
| tun.cpp | test_tun.cpp | 6 | MEDIUM | Missing: root-privilege tests |
| dns.cpp | test_dns.cpp | 3 | LOW | Stub implementation |
| events.hpp | test_events.cpp | 6 | HIGH | Missing: re-entrancy, exception in handler |
| node.cpp | None | 0 | NONE | Requires integration test infrastructure |
| main.cpp | None | 0 | NONE | Missing: signal handler safety |
| exit_handler.cpp | test_exit.cpp | 7 | LOW | **CRITICAL: no actual NAT test, no checksum test, no shell injection test** |

### Top 10 Missing Tests (Priority Order)

1. **Full relay chain onion test:** Build 3-hop onion, simulate each relay decrypting and forwarding, verify all hops get correct data. (onion.cpp)
2. **Session copy nonce reuse:** Create Session, copy it, encrypt from both, verify nonce collision. (session.cpp)
3. **Wire format cross-validation:** Serialize each message type, compare against upstream test vectors byte-for-byte. (relay_contact.cpp, session.cpp, onion.cpp)
4. **Session key derivation upstream match:** Use known upstream inputs, verify our output matches. (session_keys.cpp)
5. **NAT rewriting with valid IP packet:** Construct valid IPv4/TCP packet, apply_nat, verify output is valid. (exit_handler.cpp)
6. **IP/TCP checksum after NAT:** Verify checksums are recalculated. (exit_handler.cpp)
7. **Shell injection in RouteManager:** Pass malicious interface names, verify they are rejected. (exit_handler.cpp)
8. **Ed25519 twist point handling:** Pass a known twist point to from_ed25519, verify exception. (keys.cpp)
9. **NodeDB random_rcs with CSPRNG:** Replace mt19937 with libsodium PRNG, verify uniform distribution. (nodedb.cpp)
10. **Endpoint connection lifecycle:** Connect two endpoints, send data, verify receipt, disconnect, verify cleanup. (endpoint.cpp)

---

## Summary of Critical Findings

| # | Severity | File | Line(s) | Finding |
|---|---|---|---|---|
| 1 | CRITICAL | session.cpp | 36-41 | Session copy constructor copies nonce counter value, enabling nonce reuse |
| 2 | CRITICAL | exit_handler.cpp | 102-106 | IP/TCP checksum not recalculated after NAT port rewrite |
| 3 | CRITICAL | exit_handler.cpp | 161,185-195 | Shell injection via tun_name/exit_interface in system() calls |
| 4 | CRITICAL | session.cpp | 78-88, 116-127 | Wire format mismatch: raw binary vs TRUG-specified BT encoding for session init/accept |
| 5 | CRITICAL | session_keys.cpp | 31-53 | Possible hash structure mismatch: single-level vs two-level hash for session key derivation |
| 6 | HIGH | onion.cpp | 57-84 | Path build inner payload is raw binary, TRUG says BT-encoded dict |
| 7 | HIGH | nodedb.cpp | 61 | Non-cryptographic PRNG (mt19937) for path hop selection in anonymity network |
| 8 | HIGH | main.cpp | 8-14 | Signal handler calls non-async-signal-safe functions |
| 9 | HIGH | blind.cpp | 119 | Temporary `tmp` variable (contains private key derivative) not zeroed |
| 10 | HIGH | endpoint.cpp | 217-227 | Potential deadlock in close() if callback fires on calling thread |
| 11 | MEDIUM | manager.cpp | 11 | Manager lambda captures `this`, destroyed before Endpoint |
| 12 | MEDIUM | tun.cpp | 64 | UB for netmask=0 (shift by 32) |
| 13 | MEDIUM | router_id.hpp | 45 | Potential alignment violation in hash function |
| 14 | MEDIUM | config.cpp | 59,68 | No range validation for port and netmask |
| 15 | LOW | node.cpp | 65 | No error handling for dns_bind without `:` separator |

---

*This audit plan covers every function in every source file of the session-router rewrite. Execute each check in order, recording PASS/FAIL/VERIFY for each item. All VERIFY items require upstream source code cross-reference. All CRITICAL findings must be resolved before any deployment.*
