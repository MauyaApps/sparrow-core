# Sparrow transfer protocol v1

One device sends data (the **host**, shows a QR or a 7-digit code), the other receives it (the **guest**, scans or types).
A relay forwards opaque binary frames between them. It never sees keys or plaintext.
Data sent is the vault that is already encrypted with the master password. This protocol is a second layer.

## 1. Relay rules (see the relay repo, docs/protocol.md)
- `wss://<relay>/v1/session/<id>?role=host|guest` for QR sessions, `/v1/code/<NNN>?role=...` for code sessions.
- Relay text frames: `peer-joined`, `peer-left`, `session-ended`. Clients send binary frames only.
- A session lives up to 2 minutes. The guest has 3 connection attempts. Max message 2 MiB.

## 2. QR variant
1. Host creates `id` (16 random bytes) and `k` (32 random bytes), connects as host to `/v1/session/<base64url id>`.
2. QR text: `sparrow://t/1/<base64url id>/<base64url k>?r=<relay url>&r=<relay url>`.
   The client tries the relays in order.
3. Guest scans, connects as guest. Host receives `peer-joined`.
4. `ikm = k`, `sid = id` (16 bytes). Go to section 4.

## 3. Code variant (7 digits `NNNSSSS`)
1. Host picks a random 3-digit `NNN` and connects to `/v1/code/<NNN>` as host. If refused (in use), it picks another one.
   It picks a random 4-digit `SSSS` and shows `NNNSSSS`.
2. Guest types the code and connects to `/v1/code/<NNN>` as guest. Host receives `peer-joined`.
3. CPace, group ristretto255, hash SHA-512 (draft-irtf-cfrg-cpace):
   - `PRS` = ASCII `SSSS`, `sid` = ASCII `NNN`
   - `CI` = lv_cat("sparrow/v1", "host", "guest"), `ADa` = `ADb` = empty
   - Host is the initiator and sends first. Guest answers.
   - PAKE frame: `0x01 0x10 || Y` (Y = 32 bytes). Anything else is rejected.
   - Result `ISK` (64 bytes). `ikm = ISK`, `sid = ASCII NNN`. Go to section 4.
4. If the guest used a wrong code, the keys differ, the host cannot open HELLO, and the host closes the session.
   An attacker therefore gets one guess per session.

## 4. Keys and frames
`HKDF-SHA256(ikm, salt = sid, info, length)`:
- `info = "sparrow/v1/h2g"` (32 bytes): key for host to guest
- `info = "sparrow/v1/g2h"` (32 bytes): key for guest to host
- `info = "sparrow/v1/sas"` (4 bytes): check string = `u32be mod 10000`, 4 digits with leading zeros

Frame: `version (0x01) | type | nonce (24 random bytes) | XChaCha20-Poly1305(ciphertext + 16-byte tag)`
- Plaintext: `seq (u32 big endian) | body`. AAD: `version | type | sid`.
- `seq` starts at 0 in each direction. A receiver only accepts a `seq` larger than the last one.

## 5. Message flow
| step | from | type | body |
|---|---|---|---|
| 1 | guest | HELLO `0x01` | empty |
| 2 | host | READY `0x02` | empty |
| 3 | both | (optional) show the check string, user confirms; if not, send ERROR `0x05` and close |
| 4 | host | DATA `0x03` | `flags (1 byte, bit 0 = last) | chunk (max 256 KiB)`, repeated |
| 5 | guest | ACK `0x04` | empty, after the last chunk |

Then both close. Any decryption failure ends the session, with no silent retry.
An empty payload is one DATA frame with the last flag and an empty chunk.

## 6. Notes for other implementations (Kotlin, etc.)
- CPace `element_derivation` is the ristretto255 one-way map of 64 bytes (RFC 9496). In libsodium this is `crypto_core_ristretto255_from_hash`.
- Check your CPace against the official test vectors first (`test/cpace.test.ts` lists them).
- Scalars: 32 random bytes, top 4 bits of the last byte cleared, little endian.
- Never accept a peer share that fails to decode or is the identity element.

## 7. Limits
- The 7-digit code is weak by nature (10 000 values). It only holds because each session allows one guess and the relay limits requests per IP. Prefer the QR variant.
- The check string is a convenience. It does not replace the code or the QR key.
- Not audited. Have an expert review this before shipping to real users.
