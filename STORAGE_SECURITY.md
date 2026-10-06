# Storage Security — encryption at rest

Status: **implemented and device-verified.** The at-rest stack described here is
built — the keystore bootblock, settingsblock, contactsblock, and logbook over a
raw-flash HAL (LittleFS retired), host-tested (valgrind-clean) and verified by an
RP2350 cold-boot decrypt; the 8-word disk-key wizard + cold-boot unlock and the
burner/duress code are shipped (remaining: the short session PIN and the idle
auto-evict). This is the authoritative spec for how Xyfr protects on-device data
at rest. It is split into **Part I — Policy** (the threat-driven decisions and
the "why") and **Part II — Implementation** (the key schedule, on-flash layout,
code paths, and primitives). The threat-model entries in `THREAT_MODEL.md` (§6.9,
§9.1, §9.3, §10.2) summarise the threat posture and point here for the design.

Companion docs: `THREAT_MODEL.md` (adversaries + residual risk), `docs/protocol/backup.md`
(today's **plaintext** serial dump/restore — superseded by the encrypted-blob
backup sketched in §II.9 when it lands).

---

# Part I — Policy

## 1. What this protects, and the persona it protects for

Xyfr is a hardware secure terminal for non-technical users — a business
person, a field operator, a government officer — who need strong security with
minimal ritual. Two user-experience constraints are first-class design inputs,
not afterthoughts:

- **(A) Few things to remember.** A secret so painful that the user abandons the
  device has negative security value. The design must minimise *daily* secret
  entry.
- **(B) Felt security.** The user needs perceptible affirmation that the system
  is genuine and secure — but every such ritual must map to a *real* property,
  never theatre (see §I.7).

The protected assets at rest are: the device's wg **private key** (identity),
the **per-contact keys**, the **contact list / social graph** (names, endpoints),
and the **message history**.

## 2. The three threats and the chosen posture

| # | Threat | Posture |
|---|---|---|
| 1 | **Stolen device, attacker guesses the unlock secret** | Rate-limit the *online* path; lean on secret entropy for the *offline* path. Without a hardware rate-limiter the counter is only advisory (see §2.1). |
| 2 | **Flash extraction** — desolder/dump the chip, read on another host | Closed by encryption-at-rest: a dump yields only ciphertext + public params. This is the *foundational* threat — #1's lockout counter is only robust if #2 is closed. |
| 3 | **Coercion** — user forced to disclose the secret | Cryptography cannot prevent disclosure. Mitigated, not solved: **duress-wipe** + **aggressive retention** (less on the device to surrender). Deniable decoy volume is a documented non-goal for v1 (§I.9). |

### 2.1 The hardware reality (decides everything)

The RP2350 gives us a TRNG and a SHA-256 accelerator but **no usable hardware
secret anchor for our workflow**: the OTP anchor that would make a short PIN safe
against offline attack requires secure-boot + locked debug + **disabled BOOTSEL**,
which is irreversible per unit and kills our UF2 drag-flash dev cycle — and the
RP2350 OTP has documented lab fault-injection extraction anyway. We also have
only ~520 KB SRAM, which rules out a *strongly* memory-hard KDF.

**Consequence:** with no hardware rate-limiter, there is nothing to throttle an
attacker who has dumped the flash, so **the unlock secret's own entropy is the
only wall**. That forces **one high-entropy secret per power-on** (the disk
passphrase). A short PIN can only be a *session* gate, never the at-rest key.

## 3. The Path A decision (auditability over a black box)

We considered three ways to make a short *daily* secret safe at rest:

- **OTP / secure-boot** — irreversible, kills BOOTSEL dev flow. Rejected for v1.
- **Secure-element chip (e.g. ATECC608)** — gives hardware PIN rate-limiting and
  non-extractable storage *without* OTP's irreversibility, soldered (no token to
  carry). But it is **proprietary, closed silicon — the audit dead-ends at the
  chip**, which is contrary to this project's auditable-security ethos (cf. the
  `wg.c`/`crypto.c` "verified, do-not-edit" discipline). Rejected for v1.
- **Removable physical token (USB/CIK)** — a bare USB stick is *cloneable* and
  *self-defeating* (users leave it in the slot); a targeted thief takes it along
  with the phone. Rejected.

**Decision — Path A:** v1 carries the at-rest guarantee in **auditable software +
a high-entropy disk passphrase**, end to end, no opaque hardware in the trust
path. We accept the UX cost (the passphrase at each power-on) honestly, and
mitigate it by making power-ons rare and the *daily* secret a short PIN
(§I.5/§I.6).

**Bounded future options (documented, not built):** if the convenient-PIN tier
is later wanted, add a secure element **defensively** — split-secret so its
worst-case failure degrades to the Path A baseline, never below it (the Coldcard
pattern: the chip never holds a usable secret alone, its RNG is XOR-mixed with
our TRNG, the I²C protocol is auditable). Or adopt an **open** secure element
(TROPIC01 / OpenTitan class) when mature. The one hard line, any path: **no black
box is ever the sole gate.**

## 4. Storage tiers — what lives where

Two tiers, split by mutability and erasability:

- **The bootblock** — a small, fixed **raw-flash region outside LittleFS**,
  managed with `flash_range_erase/program` so it supports *deterministic
  in-place erase* (LittleFS, being copy-on-write + wear-levelled, cannot). Holds
  **only the fixed key schedule** (per-device salts, KDF params, the wrapped
  volume key (EDEK), and the wrapped wg private key) — a single sector, never
  grown. (The per-contact keys *used* to live here as a wrapped slab; as of the
  2026-06-21 refactor they moved into each contact's record in the contact ring —
  see Part III §2 — so the keystore image shrank to ~216 B and stays well inside
  one sector.) Near-static, so wear is a non-issue (centuries of margin — see
  §II.2). The deterministic erase is what makes crypto-erase and wipe work at all.
- **LittleFS (encrypted)** — all bulk + churny data, encrypted under the volume
  key: contact **names**, **endpoints** (learned from msg5/msg7), `last_seq`, the
  **message logs**, and Wi-Fi credentials. Contact names/endpoints are encrypted
  because the social graph is as sensitive as message bodies under threat #2.

Rule: **only near-immutable secrets go in the bootblock; anything that changes
often lives in the encrypted bulk store.** This keeps the bootblock near-static
(its wear margin and its role as the deterministic-erase anchor both depend on it).

> **Evolution (see Part III).** The "bulk" tier started as *encrypted LittleFS*.
> It has since moved to a **purpose-built, log-structured store over raw flash**
> (LittleFS retired, along with the already-unused arduino EEPROM library). The
> wg **private key moves out of `block` into the bootblock** (it is cleartext in
> `/block.bin` today — a real fix), and `block` (Wi-Fi, endpoints, calibration)
> becomes an encrypted record. Part III is authoritative for everything bulk:
> contacts, the message log, retention, and the device/CLI-shared raw-sector HAL.

## 5. The secret inventory (and what is *not* a secret you remember)

| Secret | Form | Where it lives | Frequency | Role |
|---|---|---|---|---|
| **Recovery seed** | BIP39 words (12–24) | **Written down, in a safe** — not memorised | Rare (restore / migrate) | The wg private key rendered as words; identity backup. **Doubles as the backup secret.** |
| **Disk passphrase** | ~5–6 words (~65 bits) | **Memorised** | Each cold power-on | Derives the KEK that unwraps the volume key → at-rest wall. |
| **Session PIN** | case-insensitive alnum, **min 6 (8 recommended)** | **Memorised** (verifier/wrap on flash, never the PIN) | Each screen-timeout | Powered-on session gate only. |

Crucial correction baked in: **the user does not memorise their private key.** It
is TRNG-random, stored encrypted, and the *arrow points secret → key* — never
derive the passphrase from the key (circular: a stored key-slice would sit
readable on the extractable flash and void the encryption) and never derive the
identity key from the passphrase (would cap identity security at passphrase
entropy and make a guessed passphrase a permanent network-identity compromise).
Keep unlock and identity **independent**; get "fewer secrets" from keyslots
(§II.3), not from coupling key material.

## 6. The PIN: a 36-key keyboard buys real entropy

The physical keyboard has 36 keys, so the PIN can be **case-insensitive
alphanumeric** (36 symbols), not just digits:

| PIN | Combinations | Entropy |
|---|---|---|
| 4-digit | 10⁴ | ~13 bits |
| 6-digit | 10⁶ | ~20 bits |
| **6-char alnum** | 36⁶ ≈ 2.2×10⁹ | **~31 bits** |
| **8-char alnum** | 36⁸ ≈ 2.8×10¹² | **~41 bits** |

That is a large jump over a digit PIN (8-char alnum ≈ 280 million× a 4-digit
PIN). **But entropy only matters relative to the guessing rate:**

- The PIN faces only the **online** path (it gates the already-decrypted volume
  key in RAM; see §II.5). There, **rate-limiting is the wall** and even a 6-char
  alnum PIN is unbreakable. The extra entropy is defense-in-depth (survives a
  mis-configured lockout), not load-bearing.
- The PIN must **never** be the at-rest key: 31–41 bits is far below the
  offline-safe threshold on anchor-less hardware. The passphrase keeps that job.

The realised entropy is a *ceiling* — only if the PIN is uniformly random.
Human-chosen 8-char strings land nearer 20–30 bits, so either **system-generate**
it or **model the real distribution** in the strength meter.

## 7. Honesty rules (felt security that is real)

- **The lock indicator must reflect real state.** While encryption is not yet
  enabled (DEK still plaintext, §II.4 step 2), the UI must say so plainly — no
  reassuring padlock over an unencrypted device. This doubles as motivation to
  finish setup.
- **The strength meter models the *attacker*, not the device.** "This device
  would take 4,000 years" is a lie (the attacker uses GPUs/ASICs against our
  KDF). Estimate offline guessing against the real KDF; it reads scarier and lets
  the user make a real choice.
- **Affirmation rituals must map to real properties** (these are roadmap, not v1
  blockers): a *personalised boot mark* (device shows the user's own chosen
  image/phrase before accepting the PIN → anti-evil-maid, only genuine firmware
  knows it); a *per-conversation safety word* (a short string derived from the
  session keys, matched out-of-band → real MITM detection, à la STU-III's
  identity display / Signal safety numbers).

## 8. Retention as a coercion reducer

Disappearing / expiring messages mean there is simply less on the device to
extract (#2) or be coerced into revealing (#3). This is often the most effective
real-world coercion defense and folds into the log pruning we already do. Detail
deferred; noted here as policy.

## 9. Non-goals and residual risks (v1)

- **#2 *and* #3 together** — an attacker who has imaged your flash *and* can
  coerce you — is not fully closed by any system. We mitigate (retention +
  duress-wipe), we do not claim to solve it.
- **Deniable decoy volume** (VeraCrypt-style hidden volume) — the strong answer
  to #3, but it needs a custom encrypted container (LittleFS's structure betrays
  a hidden volume) and is a later, scoped project. **Non-goal for v1.**
- **Weak passphrase** — on Path A the user owns this dial; we warn honestly
  (§I.7) and move on. The OTP/SE rate-limiter would be the eventual safety net
  for weak secrets.
- **Lab-class hardware attack on the live device** (RAM probe of a powered-on
  unlocked unit, glitching) — out of scope; mitigated only by the session
  eviction policy (§II.5) shrinking the window.

---

# Part II — Implementation

## 1. Primitives — reuse `crypto.c`, no new dependencies, no edits

All needed primitives are already exported by the public `wg.h` API. **No edit to
`wg.c`/`crypto.c`** — the key-schedule code lives in our own file and *calls* the
public API (the project rule: helpers that need wg internals live in caller code).

- **KDF (passphrase → KEK):** keyed **BLAKE2s** (`blake2s(out,32,key,keylen,
  in,inlen)`), iterated PBKDF2-style. BLAKE2s is a native keyed PRF, so no HMAC
  wrapper is needed. **CPU-hard only, not memory-hard** — accepted, because the
  RP2350 can't do strong memory-hardness anyway and entropy (not the KDF) is the
  at-rest wall on Path A; the KDF only sets the per-guess constant. Tune the
  iteration count to ~0.5–1 s on-device.
- **Wrapping (EDEK, per-slot, logs):** **`xchacha20poly1305_encrypt/decrypt`**
  (192-bit nonce) for anything with a *random* nonce — the 24-byte nonce makes
  random-nonce collisions a non-issue. The Poly1305 tag is the integrity +
  wrong-key check (no separate verifier).
- **Hygiene:** `crypto_zero` to wipe DEK/KEK/passphrase/PIN buffers from RAM;
  `crypto_equal` for constant-time comparison.

(The RP2350 SHA-256 accelerator could drive the KDF, but that would be platform
HAL code, not `crypto.c` reuse, and you tune to a wall-clock target either way —
so software BLAKE2s is the cleaner choice and keeps the audit surface to one
file.)

## 2. The bootblock — raw-flash A/B keystore

A small single-sector region carved **outside** the `_FS_start.._FS_end`
LittleFS partition, **not** the 4 KB EEPROM-lib sector. Erase/program via
`flash_range_erase/program`. It holds **only the fixed key schedule** (~216 B
as of the 2026-06-21 refactor), so it never needs to grow.

Layout (conceptual):

```
[ HEADER  (plaintext — none secret) ]
    magic · version · per-device salt (TRNG) · KDF params (iterations)
    EDEK = xwrap(KEK, volume_key)            ← the wrapped volume key
    PIN verifier  (see §II.5)
[ WRAPPED KEYS  (AEAD-wrapped under volume_key) ]
    wg private key   (nonce(24, random) · ciphertext · tag)
```

- The **per-contact keys are no longer here.** They originally lived as a wrapped
  slab of per-contact slots in this image, but the 2026-06-21 refactor moved each
  `contact_key` into its own contact record in the **contact ring** (Part III §2),
  encrypted under the volume key alongside the rest of the record. The keystore is
  now just the fixed schedule above. (Per-contact *update* and *crypto-erase* are
  the ring's job — see §II.6 and Part III §2.)
- **A/B redundancy** for power-loss atomicity: two sectors per region, each with
  seq# + checksum; write+verify the inactive copy *before* invalidating the old;
  never erase the only valid copy. This is the lesson from the lost-key incident
  (a truncating in-place write left a 0-byte block).
- **Counter sector is separate** from the key sectors (the attempt counter
  changes on every failed unlock; co-locating it would wear and endanger the keys
  on every miss).
- **Wear:** the keystore now rewrites only on registration / passphrase / private-key
  change (contact churn moved to the contact ring), so on QSPI NOR (~100k
  cycles/sector) it has centuries of margin — effectively a non-issue.
- **Concurrency:** the recent **single-core merge** (UI time-sliced inside
  `loop()` on core 0) removes the cross-core flash hazard that caused the earlier
  LittleFS deadlock — raw-flash erase/program needs only the `noInterrupts` +
  XIP-off dance, no `idleOtherCore`. Audio ISRs are RAM-resident
  (`__not_in_flash_func`), so they survive the XIP-off window. Keep all flash
  access on core 0.

## 3. Key hierarchy (two-level, LUKS-style)

```
disk passphrase + salt ──PBKDF2/BLAKE2s──► KEK ──xunwrap──► volume_key (DEK)
                                                              │  (random, NEVER changes)
                                                              ▼
                          decrypts: keystore wrapped private key
                                  + fixed block (settings)
                                  + contact ring records
                                  + logbook framing
```

- `volume_key` (= DEK) is random, generated once, **never changes**. A passphrase
  change re-wraps only this one tiny key (no data re-encryption). The same
  pattern lets a second **keyslot** (a second EDEK) be wrapped under the
  **recovery seed**, so the volume key has two independent unwrap paths
  (daily passphrase + drawer seed), each revocable — "one secret to recall, one
  in safekeeping," identity uncoupled from both.
- Forward-compat for the SE/OTP future: `KEK = KDF(optional_anchor, passphrase,
  salt)` with `optional_anchor` absent today — adding it later changes
  provisioning, not the data format.

## 4. Provisioning flow (the user narrative, corrected)

Steps 3–4 are **deferred and re-prompted** ("secure your phone") — the user can
skip them, but the UI shows encryption-OFF honestly (§I.7) until done.

1. **Registration.** Blank device, bootblock all-zero. TRNG generates the wg
   private key; user accepts + activates; commit to the bootblock.
2. **Pre-encrypt under a random DEK.** Generate `volume_key` from TRNG; encrypt
   the bulk store (fixed block, contact ring, logbook) and the keystore's
   wrapped private key under it. The DEK is
   stored **plaintext** for now (encryption effectively OFF — say so in the UI).
   *Why up front:* because data is already under a stable random key, enabling a
   passphrase later (and every future passphrase change) only re-wraps the DEK —
   never re-encrypts the disk. (The DEK encrypts the payload slots, **not** the
   header field that stores the DEK itself — that would be circular.)
3. **Enable the passphrase.** Prompt for the phrase. `KEK = KDF(phrase, salt)`;
   `EDEK = xwrap(KEK, DEK)`; **write EDEK to flash**; then **securely erase the
   plaintext DEK** (the bootblock deterministic erase) — *this* is the moment
   encryption turns on. The Poly1305 tag on the EDEK is the wrong-passphrase
   check.
4. **Set the session PIN** (min 6, §I.6). Store a **verifier**, never the PIN
   (§II.5).

### The corrected DEK/EDEK lifecycle (the load-bearing fix)

The **EDEK (ciphertext) is persisted on flash**; the **decrypted DEK lives only
in RAM** and dies on power-off, re-created each boot from the passphrase. (The
earlier narration had this inverted — EDEK-only-in-RAM would make the disk
permanently undecryptable after power-off.)

```
AT REST (off), on flash:  salt · KDF params · EDEK=xwrap(KEK,DEK) · PIN verifier
                          (NO plaintext DEK, NO plaintext PIN)

BOOT:        phrase → KDF → KEK → xunwrap EDEK → DEK in RAM → decrypt disk
SCREEN-LOCK: re-wrap DEK under a PIN-key (RAM only), crypto_zero the plaintext DEK
UNLOCK:      PIN → unwrap → DEK back in RAM
POWER-OFF:   RAM cleared → DEK gone; EDEK survives on flash for next boot
```

Mental model: **persist the locked box (EDEK), throw away the open key (plaintext
DEK); the passphrase re-opens the box every boot.**

## 5. The PIN session model (why a short PIN is safe here)

The PIN gates the **powered-on session**, not the at-rest disk:

- **On screen-lock:** `pin_key = KDF(PIN, salt)`; re-wrap the in-RAM DEK as a
  blob held **in RAM only**; `crypto_zero` the plaintext DEK.
- **On unlock:** `PIN → pin_key → unwrap` the RAM blob → DEK back.
- **Verifier:** the AEAD tag on the PIN-wrapped blob *is* the check — wrong PIN ⇒
  tag fails. (If a standalone verifier is ever wanted, store
  `blake2s(salt, PIN)` and compare with `crypto_equal` — never the PIN itself.)

Because the PIN-wrapped blob is **RAM-only and dies on power-off**, there is no
*offline* attack on it: a full reboot forces the real passphrase. That is exactly
what lets a 6–8 char PIN be both convenient and honest. A powered-on-but-locked
device holds no usable key (a RAM probe yields only a PIN-wrapped blob).

**Auto-evict policy** (the powered-on-theft knob): after N minutes idle (or
end-of-day, or a trigger), `crypto_zero` the DEK and the PIN blob → next use
forces a full passphrase cold-unlock. Short timeout = smaller theft window, more
friction; long = the reverse. Make it the one tunable that trades convenience vs.
the powered-on window.

## 6. Erase, wipe, and duress

- **Crypto-erase is the wipe primitive.** Destroying the small wrapped key turns
  the data it protects into undecryptable noise — no need to scrub gigabytes.
  - *Delete a contact:* **blank that contact's ring record** — a NOR program to
    `0x00` (no sector erase) over its 256-byte page. That destroys the encrypted
    `contact_key` (which now lives *inside* the record), so the contact's logbook
    payloads (encrypted under that key) become permanent noise, and the contact's
    own identity (name, key, endpoint) goes with it. Surgical and immediate; the
    ring's update path already blanks every superseded copy, so no stale
    recoverable copy of the key lingers.
  - *Full wipe / duress:* destroy the EDEK (the wrapped volume key) → the entire
    store (fixed block, contact ring, logbook) becomes noise instantly, without
    rewriting any of it.
- **Duress secret → silent, selective wipe** (v1 coercion mitigation, delivered
  as the **burner code**, `74f6fb2`; UI device-verify pending): a second
  lock-screen PIN that crypto-erases every `CONTACT_BURNER`-flagged contact and
  its logbook history (the per-contact blank primitive above, applied to the
  flagged set), then re-locks as an ordinary PIN so nothing reveals two codes
  existed. This shipped in place of the full-EDEK erase sketched just above (that
  remains an available design capability, not the delivered flow). Honest caveat:
  moot if the attacker imaged the flash first, and a visible wipe can escalate
  risk — surface this in the UX copy. (Decoy volume is the stronger answer;
  non-goal v1, §I.9.)
- **Lockout (advisory on Path A):** N wrong attempts → escalating delay → wipe.
  Counter lives in its own sector. Without OTP it is rollback-able by a flash
  imager, so it is a UX courtesy against #1, not a hard wall — the passphrase
  entropy is the real defense.

## 7. Atomicity and reconstruction

- **No cross-store two-phase commit.** Compose three cheaper pieces:
  1. *Per-store atomic primitive* — bootblock A/B (§II.2); LittleFS **never
     truncate-in-place** (temp file → fsync → atomic `rename`; in-place slot
     seeks rely on LittleFS's own block commit, corruption bounded to one slot
     and caught by its AEAD tag).
  2. *Key write/erase = the single commit point* — **Add:** bootblock slot first,
     then metadata (crash between ⇒ keys-without-metadata ⇒ defaulted on boot, add
     survives). **Delete:** destroy the key first (the erase *is* the atomic
     commit; leftovers are undecryptable orphans). **Message:** append log, then
     bump `last_seq` (crash between ⇒ stale seq, reconciled from the log tail).
  3. *Boot reconcile* (a "contacts-fsck").
- **Reconstruction tiers:** bootblock = hard, authoritative, A/B-redundant
  survivor (identity + keys). LittleFS metadata = soft, re-learned (name over the
  handshake, endpoint from msg5/msg7, `last_seq` from the log tail). Logs = the one
  genuinely losable thing.
  - *Partial-op* ⇒ boot fsck: every bootblock contact gets a metadata slot
    (default if missing); orphan metadata/logs (no bootblock slot) are GC'd.
  - *Catastrophic FS loss* ⇒ reformat + rebuild metadata from the bootblock;
    **message history is the irreducible loss** (no server-side copy — state it
    plainly to the user). Identity + contacts survive because they are in the
    bootblock.
- The bootblock is the **single point of total failure** (lose it ⇒ private key
  gone ⇒ everything undecryptable + identity lost). Hence its A/B redundancy is
  the highest priority, and it justifies an explicit, user-initiated key backup.

## 8. Module plan (new code; core 0 only)

- `bootblock.c/.h` — the raw-flash A/B keystore: region carve, `flash_range_*`
  erase/program with the XIP-off dance, A/B seq+checksum, slot read/write/erase,
  counter sector. Pure C, core 0.
- `keystore.c/.h` — the key schedule on top: `kek_derive` (PBKDF2/BLAKE2s),
  `volume_unwrap/rewrap`, `lock/unlock/evict` state machine, the wrapped wg
  private key, crypto-erase + duress. Calls only `wg.h` public API + `bootblock`.
  (The per-contact key slab + `ks_*_contact_key` API that originally lived here
  were removed in the 2026-06-21 refactor — `KS_IMAGE_VERSION` bumped 1→2;
  per-contact keys now live in the contact ring.)
- `contactsblock.c/.h` — the per-contact record store: a page-slotted wrap-around
  ring in its own raw-flash region (Part III §2). Each contact record (key,
  name, endpoint, `contact_key`, psk, …) is AEAD-wrapped under the volume key in
  one 256-byte flash page; add/update/delete and GC live here.
- Wiring: provisioning prompts (registration + the deferred nags) on the UI;
  unlock/lock screen; the auto-evict tick in the core-0 pump. `contacts.c` /
  `storage.c` gain an encrypt/decrypt seam (volume key) but keep their file
  layout. `wg.c`/`crypto.c` **untouched**.

## 9. Backup / restore (design sketch — later slice)

Every store is already encrypted at rest, so a backup ships **already-encrypted
blobs + an outer AEAD**: `[magic][version][bootblock image][metadata][logs][tag]`.
The PC backup target can't read it.

- **Encrypt under a high-entropy secret, not the daily PIN.** A backup is
  inherently offline-attackable (it must restore to a *replacement* device, so no
  hardware anchor can follow it). On Path A the disk passphrase is already
  high-entropy, so it (or the recovery seed) is the backup key; the **recovery
  seed doubles here**.
- **Restore = migration, not multi-device sync.** A backup + its key is a full
  identity clone; two *live* instances of one wg identity collide
  (`sending_counter` ⇒ relay route ping-pong). Restoring retires the old device.
- **Quiesce writes** during the snapshot (trivial on single core). "Quick backup"
  defaults to bootblock + metadata (the recovery-critical core); logs are
  optional/incremental.
- Transport can be dumb (the blob self-protects); cleanest is a `BACKUP`/`FILE`
  app over a TICP stream to the PC-as-peer. **This supersedes the plaintext
  serial `dump`/`restore` in `docs/protocol/backup.md`** — keep that for dev until this lands.

---

# Part III — Message storage and retention

This part is the authoritative design for the **bulk** tier (contacts + message
history + `block`). It supersedes "encrypted LittleFS" in §I.4. Part II (the
bootblock + key schedule) is unchanged and underpins it.

## 1. The decision: a purpose-built store, not LittleFS

We replace LittleFS for contacts, messages, and `block` with a **custom,
log-structured store over raw flash**, behind the same `flash_range_*`
mechanism the bootblock uses. Reasons:

- LittleFS is copy-on-write + wear-levelled, which **fights deterministic
  crypto-erase** (no in-place erase) and gives no clean block hook for
  transparent encryption.
- **Append-only is power-safe by construction** — a torn append loses only the
  last partial record; everything before is intact. No COW, no FTL.
- **Full auditability** — a small store we own end-to-end, consistent with the
  Path A "no black box in the security path" stance (§I.3). LittleFS is itself a
  complex dependency in the security path.
- The arduino **EEPROM library is already unused** (block is a file today); both
  it and LittleFS retire.

The cost we accept: we own garbage collection, crash recovery, and the boot
mount. The crypto/key schedule (Part II) is unchanged.

## 2. The stores (four flash tenants + a RAM lane)

> **Refactor (2026-06-21).** Contacts moved **out** of the fixed block into a
> dedicated **contact ring**, and the per-contact keys moved out of the keystore
> into each contact's record. The region now has **four** tenants in order —
> `[keystore bootblock][settings fixed block (A/B)][contact ring][logbook]` —
> where it previously had three (the fixed block carried settings + contacts).

- **Keystore bootblock (A/B redundant).** The fixed key schedule only — salt,
  KDF params, EDEK, wrapped wg private key — single-sector (§II.2).
- **Settings fixed block (A/B redundant).** The `struct saved` settings (Wi-Fi
  APs, endpoints, calibration) **only** — no longer the contact table. Multi-sector
  A/B opaque image (`settingsblock.c`), encrypted under the volume key, rewritten only
  on settings change (rare). Base sector `STORE_FB_BASE_SECTOR`.
- **The contact ring.** A page-slotted wrap-around ring in its own raw-flash
  region (`CONTACT_RING_BASE_SECTOR`, `CONTACT_RING_SECTORS = 40`), one
  256-byte record per flash page (16/sector). Each record: a cleartext 16-byte
  header (magic `0xFF`=free / `0xC0`=live / `0x00`=dead-blanked; version; a
  monotonic 64-bit `record_id` used as the AEAD nonce source) + a 224-byte
  XChaCha20-Poly1305 payload (the `struct contact_record`, zero-padded, AAD = the
  header) + 16-byte tag. **Only magic/version/record_id are cleartext at rest;
  everything identifying — name, key, endpoint, `contact_key`, psk — is inside
  the AEAD.** RAM holds only a userid→slot directory, rebuilt by scanning at
  init. Lifecycle: *add* → write a free (`0xFF`) slot; *update* → write-and-verify
  a new slot, flip the directory, **then** blank the old (crash-safe), with
  compare-before-write skipping no-op saves; *delete* → blank (crypto-erase);
  *GC* → copy-forward live records (a byte-copy, since `record_id` is the nonce)
  and erase all-dead sectors. 500 live-contact cap (device). Because `record_id`
  is the nonce, copy-forward and update never reuse a nonce.
- **The message log.** One **device-level, append-only *linear* log** holding all
  *persisted* messages (everyone's, interleaved in time order). It is **not a
  ring** — it fills toward the end, and a user-triggered in-place **compaction**
  (§III.4) reclaims space by keeping starred records and dropping the rest. ~2 MB
  on the 4 MB part.
- **RAM ephemeral queue.** 007 messages only — never touches flash (§III.8).

Flash layout of the internal-storage region (one rawflash device):

```
 sector:  0..        STORE_FB_  CONTACT_RING_   STORE_MSG_
                     BASE_SECTOR BASE_SECTOR     BASE_SECTOR ........ N-1
        +-----------+-----------+---------------+----------------------+
        | keystore  | settings  | contact ring  | message log (the logbook append-layer:|
        | bootblock | fixed blk |  (page-slotted |  tight, byte-        |
        |  (A/B)    |   (A/B)   |   records)     |  addressed records)  |
        +-----------+-----------+---------------+----------------------+
         \_ZEROBLOCK_/ \_ A/B __/ \_ CONTACT_RING \____ logbook _______/
          SECTORS       settings    _SECTORS = 40
              (key schedule)        (per-contact records)

 one log record (tight-packed; byte-addressed; may span pages, not sectors):
        +------------- cleartext -------------+----- volume key ----+- contact key -+
        | magic | payload_len | record_id u64 | framing_ct (10+16)  | payload_ct(+16)|
        +-------------------------------------+---------------------+---------------+
        framing = contact_id u32 · timestamp u32 · star u8 · kind u8
```

`the logbook append-layer` seals all page/sector handling; the record layer addresses the log by
flat byte offset. `kind` (msg-in / msg-out-pending / msg-out-delivered / call-in/
out-missed/answered) lets the timeline render calls and messages.

## 3. Retention is a per-contact setting

Each contact carries a retention setting that picks the **default `star` bit** on
its messages. `star` = "survive GC" (§III.4). The settings, in user words:

| Setting | Default star | Lives in | Behaviour |
|---|---|---|---|
| **Store nothing** (007) | — | RAM queue | never flash; read-and-burn; queue-full ⇒ reject (§III.8) |
| **Store rolling** (beer-chum, **default**) | unstarred | log | aged out oldest-first by GC; user can `star` individual messages to keep |
| **Store only starred** | unstarred | log (transient) | nothing kept unless explicitly starred |
| **Store everything** (boss/spouse) | starred | log | every message auto-starred ⇒ never reclaimed (the verified transcript, §III.9) |

So "store everything" is just "auto-star everything"; the messy KEEP-vs-ROLL
partitioning disappears — starred and rolling messages share one log and the
ratio floats. `star`/unstar and promotion ("mark this 007 / beer-chum message to
keep") are the only user verbs.

## 4. The log: append, star, and compaction

- **Append** new records at the head; the log grows toward the end. No wrap.
- **`star` bit per record** = survives compaction; everything else is reclaimable.
- **Compaction is a deliberate, user-triggered event** (not a background ring
  wrap) — prompted near capacity (`msgstore_usage_pct`), run charged/plugged.
  It walks the log front-to-back, **copies each *starred* record to the front
  (tight), drops the rest**, and frees the tail. In-place; not crash-safe (see
  §III, the in-place-vs-two-space decision: an interruption is bounded loss,
  resync recovers the intact remainder). The on-flash format is identical to a
  future two-space compactor, so going lossless is a firmware swap.

Two honest watch-points (fine at this device's ~50 msg/day, but real):

1. **Compaction cost scales with the *surviving* (starred) fraction.** Mostly-
   disposable chatter ⇒ each pass frees a lot, cheap. Mostly-starred ⇒ each pass
   copies almost everything forward to free a little (classic log-GC write
   amplification).
2. **Starred data is un-reclaimable**, so the log can fill with stars — at which
   point compaction frees nothing ("archive full"). It self-balances first (stars
   crowd out the rolling window, so beer-chum history visibly shortens), but we
   must **warn as starred volume approaches capacity** (prune/export). The log
   does not escape "permanent data grows forever"; it just houses it gracefully.

## 5. Record format + two-tier per-record encryption

```
record = [ len            cleartext (walk boundaries) ]
         [ framing         AEAD/stream under the VOLUME key:
                           partkey · prev-ptr · timestamp · star · record-id ]
         [ payload         under the PER-CONTACT key: the message body ]
```

- **Nonce = a monotonic `record-id`** that travels with the record, **not** the
  flash offset. So GC copy-forward is a **pure byte-copy** (no decrypt /
  re-encrypt), and the id never repeats — avoiding the nonce-reuse-on-move break
  that `nonce = offset` would cause after compaction.
- **Framing under the volume key** ⇒ the log is walkable / crash-recoverable
  whenever the device is unlocked, it **survives a per-contact key wipe** (so GC
  can still reclaim a wiped contact's records), and a **flash dump leaks no
  metadata** (no passphrase ⇒ no volume key ⇒ partkeys/timestamps/graph are all
  ciphertext). *This is why the partkey need not be plaintext.*
- **Payload under the per-contact key** ⇒ destroying that key turns its message
  bodies into permanent noise; the framing remains so GC reclaims the husks
  lazily. The per-contact key (`contact_key`) lives in that contact's **contact
  ring** record (Part III §2), not in the keystore — so *crypto-erasing a contact*
  is **blanking its ring record** (§II.6), which destroys the `contact_key`
  ciphertext and renders every message under it unrecoverable in one NOR write.
- The `star` bit lives in the encrypted framing (no "which messages matter" leak;
  GC decrypts one small header per record to decide — negligible at our volumes).
- *Option:* **fixed-size records** (e.g. 96 B; long messages chain across
  several) hide message sizes from a flash dump and simplify the walk to
  seek-by-index, at some waste on short messages.

## 6. Per-contact reads = back-link chain

Each record stores the flash pointer of the **previous record for the same
contact**. The contact's **chain head** (newest record) is held in its contact
ring record (Part III §2 — formerly the fixed-block contact entry, before
contacts moved to the ring). Reading a conversation follows the back-links
newest-first —
O(messages in the conversation), not O(log). Time-interleaving in the log costs
nothing for reads.

## 7. Boot mount

Once per boot, **post-unlock**, scan the log forward, decrypt each record's
framing (volume key) to rebuild every contact's chain head and the tail/head
free-space pointers, and discard a torn tail. ~1–3 s on a full 2 MB log (cost is
the per-record framing decrypt). The home screen's conversation list waits on the
mount.

## 8. The 007 RAM lane

"Store nothing" never touches flash: messages are held in a RAM queue, shown,
and burned a few hours after reading (and unconditionally on power-off — the
ultimate burn, and a security plus: nothing survives extraction).

- **Backpressure reuses the transport we already built.** A full queue makes
  `msg_on_open` return `TICP_REJECT`; the reliable-datagram ack is gated on
  acceptance, so the sender's TICP simply doesn't get acked and retries. No new
  machinery (the `ma 0/1` reject path).
- **Decision — retry horizon:** TICP retries for ~seconds, not hours. So reject
  cleanly handles momentary congestion; "away for an hour with a full queue"
  yields a **delivery-failed** to the sender (fail-fast-and-notify) unless we
  give 007 a longer retry budget. *Default: fail-fast-and-notify* (matches a full
  dead-drop), revisit if users want patient retry.

## 9. Authentication tiers (the "verified transcript")

- **Starred / store-everything** records are **hash-chained** (each carries the
  hash of the previous record in that contact's chain) ⇒ **tamper-evident**: the
  stored transcript can't be silently altered or have a message removed. Combined
  with the wg-authenticated channel (the sender's verified key), that's a solid
  "this is the real, unaltered transcript."
- **True non-repudiation** (a record a third party accepts as proof the other
  party said X) needs **per-message digital signatures**, which the transport
  does not produce today (it authenticates the channel, not each message).
  **Deferred** — current "verified" = tamper-evident local copy, not
  court-admissible. Revisit if a legal-record use case is in scope.
- **Rolling / unstarred** records: confidentiality only, no integrity tag needed.

## 10. Capacity — bounded by construction

At ~64 B/message, 50 msg/day = **1.168 MB/year** raw; with per-record overhead
(keep the nonce derived, not stored) ~**1.5–1.75 MB/year**. But the retention
model makes total flash **bounded and predictable**:

- 007 → **0 bytes** of flash.
- rolling → **bounded** — disposable records are dropped at each compaction, so
  the rolling history is a window, not unbounded growth.
- starred / store-everything → the only unbounded contributor, but **low-volume
  by design** (a few contacts + a few starred messages) ⇒ tens of KB/year.

So **4 MB is comfortably enough**; the 16 MB **W25Q128 (WinBond)** is headroom,
not a requirement, and a rolling-retention window makes any size last
indefinitely. The chip stops being a forcing function.

## 11. One store, two backends — device and CLI share it

The store (fixed block, log, compaction, mount, chains) is **portable C over a
3-function raw-sector HAL** — `zbflash_read / _erase / _program` (already in
`bootblock.h`). Two backends:

- **Device:** `flash_range_*` (`zbflash_arduino.cpp`).
- **Host CLI:** a single **~2.2 MB file as flash** (`secserver/zbflash_posix.c`,
  already prototyped for the bootblock), carved into 4 KB logical sectors.

Payoffs: the CLI becomes a **full persistent peer**, and — crucially — **GC
crash-safety is testable on the host** via the existing fault injector
(`zbflash_test_truncate_next` = write-N-then-power-loss): inject a torn write
mid-compaction, assert the log recovers with no lost/duplicated starred records,
under gdb/valgrind/ASan, deterministically. The scariest part validates
off-device.

Fidelity rules for the file-as-flash to stay honest:
- model **erase → all-`0xFF`** and **program flips `1→0` only** (`dst &= src`), so
  "programmed without erasing first" fails on host too;
- it **cannot** model wear/endurance (a capacity concern, not correctness) or real
  erase timing (µs on host vs tens-hundreds of ms on flash) — those numbers come
  only from the device.

Side benefit: this **shrinks the platform HAL** — contacts/messages/`block` leave
the dozen-function `fs_*` HAL for the 3-function raw-sector HAL, moving the
complex logic into shared portable C. The `fs_*` HAL largely retires.

---

## 12. Open items / sequencing

Part II status: the **at-rest stack is built, host-tested, and device-verified**.
Host suites after the 2026-06-21 refactor: `contact_ring_test` 31/31,
`keystore_test` 44/44 (was 51/51 — the 7 per-contact-key checks were removed when
that API left the keystore), `store_test` 32/32, `msgstore_test` 62/62,
`fixedblock_test` 24/24, all valgrind-clean; device-verified on real RP2350
(provision → AEAD write → reboot → ring mount-from-flash → decrypt; keystore
cold-boot unlock across reboot). Remaining:

1. **Zeroblock on device:** carve the region from the linker/partition map (reuse
   the ex-EEPROM top sector + one below it; trial on device), add `#pragma
   pack(1)` + `static_assert` to the persisted structs, move the 8 KB stack
   buffers in `zb_load`/`zb_save` to `static`, fix the `change_passphrase`
   stale-slot scrub (double-write, like `enable_passphrase`). *(Done.)*
2. **Settings fixed block** is multi-sector A/B holding only `struct saved`
   (Wi-Fi/endpoints/calibration); the private key moved into the keystore and the
   contact table moved into the **contact ring** (its own raw-flash region,
   `CONTACT_RING_SECTORS = 40`, per-contact keys in-record). *(Done.)*
3. **Default PIN `"12345678"`** + arm at provision + the post-cold-unlock PIN
   prompt (§II.5 / review).
4. **The message store (Part III):** record format + two-tier encryption, the
   log, scan-based reads, the boot mount, and the **RAM 007 lane**.
   Build on host first over the file-as-flash.
5. **GC / compaction** (copy-starred-forward) with the **host crash-safety test
   harness** (fault injection mid-GC) — the hard, isolated slice.
6. **Retire `fs_*` / LittleFS / EEPROM:** move `contacts.c`, `storage.c`, and
   `test_contacts` onto the store.
7. Provisioning UI + deferred nags + honest encryption-state indicator; lock/
   unlock screen + auto-evict; duress-wipe + lockout counter.
8. **Verified transcript:** hash-chain starred records (per-message signatures
   deferred).
9. Encrypted-blob backup (supersede `docs/protocol/backup.md`).
10. Rituals (personalised boot mark, per-conversation safety word) — roadmap.
11. Future, bounded: defensive secure element; open SE; decoy volume; 16 MB
    `W25Q128` for guaranteed multi-year full history.
