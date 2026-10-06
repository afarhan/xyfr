# Xyfr Threat Model

> Draft 2026-05-25; revised 2026-07-08 and 2026-07-21 (see git history for
> those notes). **Revised 2026-09-01 against the source:** the four "planned
> upgrades" that used to fill §10 are all delivered or were never gaps, so
> their effects now live in §6–§9 and §10 is a pointer; storage names follow
> the code (`secure_store.c`, `filesystem.c` — one file per contact or channel,
> `contactsblock`/`logbook` are gone); the key-verification gate (§9.5) and the
> constant-rate voice finding (§9.6) are recorded; §12 statuses re-checked.
> The system described here is the one implemented in this repo (see
> `docs/protocol/transport.md`, `docs/protocol/storage.md` and
> `docs/protocol/relay-and-directory.md`); anything still
> aspirational is flagged as such.

## 1. What Xyfr is

Xyfr is a hand-held voice and text terminal built from a Raspberry
Pi Pico 2W (RP2350), a small TFT, a matrix keyboard, a microphone and
a speaker. It does one job: carry conversations between two known
parties, end-to-end encrypted, over the public internet, without
giving up any more metadata to the network or to the operator of the
service than is strictly required to route a packet.

The device is *not* a smartphone. It does not run a general-purpose
operating system, does not execute third-party code, has no browser,
no camera, no microphone unless the user is in a call, no app store,
no notifications, no advertising identifier, and no telemetry. Every
byte that leaves the device leaves because the user pressed a key.

The transport is a stripped-down WireGuard derivative: Noise
IKpsk2 with the canonical msg1 / msg2 / msg3 / msg4 frames, the
upstream constants, and the upstream cookie/MAC structure. Voice and
text ride inside the encrypted msg4 payload as a tiny
`[transport][port][len][payload][random-pad]` frame (`struct data_hdr`,
`peer_data.h`; every layout is in `docs/protocol/transport.md`).

This document describes the adversaries the system is designed to
resist, the assets it is designed to protect, the trust boundaries it
draws around those assets, and the threats it deliberately does *not*
attempt to defeat.

## 2. Assets

The assets being protected, ranked roughly by severity of compromise:

1. **Conversation content** — the audio of a call and the text of a
   message, both in transit and at rest on the device.
2. **The social graph** — who talks to whom, when, how often, for how
   long. In the practitioners' threat models this is frequently more
   sensitive than the content itself.
3. **Long-term identity keys** — the Curve25519 static private key on
   each device. Loss of this key compromises every past *and* future
   session that uses it. (Forward secrecy is preserved within a
   session; see §6.1.)
4. **Per-session ephemeral keys** — short-lived, but their compromise
   exposes one session's content if recorded.
5. **Stored contact list** — the user's address book lives on flash as
   one **file per contact** in the encrypted filesystem (`filesystem.c`;
   layout in `docs/protocol/storage.md`). The file header is the contact's
   name, public key, relay endpoint and per-contact pre-shared key,
   sealed under that file's own data key, which is itself wrapped under
   the volume key. The names and public keys form an off-line snapshot
   of part of the social graph.
6. **Stored message log** — each contact file's append-only log of
   entries: its messages (and, for a channel file, its lines). Entry
   framing is under the volume key, bodies under the file's data key.
   The MSG engine appends every inbound and outbound message, so the
   running build persists message history on flash, encrypted (see
   §9.3). Deleting the contact destroys the data key and takes the
   whole thread with it.
7. **Device location** — the IP address the device is currently
   reachable from, and by inference the geographic location of the
   user.

## 3. Adversaries

The threat model considers four classes of adversary, with the
specific capabilities each is assumed to have. The design choices are
explained against this fixed list — readers should not assume
protection against an adversary outside it.

### 3.1 The passive network observer

A party who can see traffic on the network between the device and the
internet, or between the device and a relay, but cannot inject or
modify packets. Examples: a coffee-shop Wi-Fi neighbour running
tcpdump, an ISP doing bulk metadata collection, a passive nation-state
collection programme. Volume of observation can be arbitrarily large.

### 3.2 The active network attacker

A party who can drop, replay, reorder, modify, and inject UDP packets
between the device and any other system endpoint. Includes a hostile
Wi-Fi access point, a man-in-the-middle on an upstream link, and a
party who has taken transient control of a relay's network path.

### 3.3 A compromised relay operator

Xyfr routes peer-to-peer traffic through one of many community-run
relays (the design target is on the order of one hundred relays,
discoverable through a DNS TXT record on the service domain). A compromised relay is one that is fully
controlled by the adversary: it can read every packet that crosses
it, drop it, log it, log its source/destination IPs and timing, and
share that log with other parties.

The relay is **not** trusted with any cryptographic key material
belonging to the conversation. The threat model takes the worst case:
the adversary owns whichever relay the user has selected.

### 3.4 A compromised central server operator

The central server (`secserver/server.c`) is the registration and
directory endpoint: it issues activation, holds the
public-key-to-userid registry, and tells contact lookups where a peer
was last seen. It does **not** carry conversation traffic. It does
**not** see peer-to-peer handshakes (those go A → relay → B).

A compromised server is assumed to: enumerate the registered user
base, learn the public-relay endpoint each user currently uses, and
falsify the contact-lookup response to any client that asks.

### 3.5 Out of scope

The model deliberately does *not* address:

- **A physically captured device** in possession of an attacker
  with hardware probes, decapping equipment, or a JTAG cable. RP2350
  has a secure-boot story, but the current build does not use it; if
  the adversary has the device and time, the long-term key is
  recoverable. (See §9.1.)
- **A supply-chain compromise of the firmware image** that survives
  a user-initiated reflash. The entire sketch is open-source and the
  RP2350's BOOTSEL bootloader is hardware-pinned: holding BOOTSEL at
  power-on exposes a USB mass-storage volume that any user — not
  just a technical one — can drag-and-drop a `.uf2` onto. Combined
  with a published, checksum-verified release `.uf2`, this resets
  the device to a known image. The residual concern is trust in the
  publisher of that `.uf2` + checksum, and in the build toolchain
  itself (see §9.4).
- **Coercion of the user** to unlock the device or to read a message
  aloud.
- **Compromise of the WireGuard / Noise / Curve25519 primitives
  themselves.** The design pins this to the upstream constants and
  inherits both their strengths and their assumptions; a fundamental
  break in Curve25519 or ChaCha20-Poly1305 breaks Xyfr too.
- **Denial of service on the public internet** that prevents packets
  reaching any relay at all. Availability under DoS is a service
  problem, not a confidentiality or integrity problem.

## 4. Trust boundaries

Five concentric trust regions, from innermost to outermost:

1. **The device hardware and firmware.** Trusted absolutely with all
   conversation content and key material when in use. Compromise here
   is total compromise.
2. **The peer device on the other end of a conversation.** Trusted
   to receive cleartext, but not trusted with the user's other peers'
   keys (each peer relationship is independent).
3. **The relay network.** Trusted with *routing* — it sees ciphertext
   envelopes and the source/destination IPs and ports of those
   envelopes, and it must not be able to do more than that.
4. **The central server.** Trusted with the user's public key (the
   user voluntarily registered it), with an activation receipt, and
   with the relay endpoint the user is currently homing onto. Not
   trusted with conversation content or any long-term linkage between
   identity and conversation activity.
5. **The public internet.** Untrusted in full — every adversary in
   §3.1 and §3.2 lives here.

Conversation cleartext crosses boundary 1 → 2 only. Identity keys
never leave boundary 1. The central server learns boundary-4
information about each user, but has no privileged window into
boundaries 1–3.

## 5. The high-level mitigations

Five architectural decisions carry most of the security weight. Each
is restated here so a reader can see, at a glance, what the design
relies on before §6 walks through specific threats.

1. **End-to-end Noise IKpsk2 between peers.** Voice and text ride
   inside encrypted `msg4` payloads. Neither the relay nor the
   central server holds the session keys.
2. **Relay-only data plane.** The central server is a registration
   and directory service; it never sees conversation handshakes or
   conversation traffic. The relay sees ciphertext and routing
   indices but not plaintext.
3. **Dedicated hardware with a tiny attack surface.** No general OS,
   no browser, no third-party code. The firmware is a single sketch
   compiled from a small set of source files. The "side channels"
   that haunt smartphone messengers (background apps, push services,
   notifications, screenshots, cloud backups) simply do not exist.
4. **Local-only storage.** The contact list and the message log live
   in on-device flash. The server holds no message backup, no
   conversation index, no "cloud history." When the device dies, the
   logs die with it (this is a deliberate trade-off — see §9.3).
5. **Identifier minimisation.** The transmitted short identifier is a
   32-bit `part_key`, the first four bytes of the user's public key.
   This is what the relay uses for routing. The full 32-byte key
   never appears in unencrypted form after the
   handshake.

## 6. Threats and the design responses

This section walks through specific threats by adversary class and
describes the design feature that mitigates each one. Where a
mitigation is partial, that is called out.

### 6.1 Recording a call for later decryption (T-PASSIVE-1)

*Adversary:* §3.1, indefinitely well-resourced.

*Threat:* Adversary archives the ciphertext of a call today, hoping
to obtain the long-term key in the future (by subpoena, theft, or
cryptographic break) and decrypt it retrospectively.

*Mitigation:* The Noise IKpsk2 handshake produces ephemeral
session keys via an ECDH between fresh per-session keypairs. The
long-term static key is used only to authenticate the handshake;
session keys do not derive from it alone. Future compromise of the
static key does not expose past session content, provided the
ephemeral private keys were genuinely deleted after the session
ended.

The ephemeral private key sits on the slot's `struct peer` and is
never persisted to flash. On slot eviction the memory is reused; on power loss
it is gone.

*Residual risk:* If the device is captured *during* a call, the
session keys for that call are recoverable from RAM. Forward secrecy
is a property of *retired* sessions, not live ones.

### 6.2 Bulk metadata harvest (T-PASSIVE-2)

*Adversary:* §3.1.

*Threat:* "We don't care what they said, we care that A talked to B
on Tuesday at 14:32 for nine minutes."

*Mitigation:* Partial, with honesty about what is left.

- The payload type (voice vs text vs call-ended) is encrypted under
  AEAD, so an observer outside the relay cannot tell call from text
  from teardown.
- Voice frames are random-padded to a 32-byte boundary inside the
  encrypted payload, so the original payload length is mildly
  obscured. (32 bytes is small; this is *not* a meaningful traffic-
  analysis countermeasure on voice, which has a recognisable
  ~25-frame-per-second cadence.)
- The observable 32-bit `part_key` on a relay-routed frame is the
  *peer's* identifier, not the user's. An observer who can see only
  the link between the device and the relay sees one part_key at a
  time and cannot tell which user is initiating.

*Residual risk:* The 25-fps voice cadence is a strong fingerprint;
a passive observer of a single link can reliably tell that a voice
call is in progress and roughly how long it lasts. Padding does not
hide this. *We do not claim traffic-analysis resistance against an
observer who can watch a single link continuously.* A user whose
threat model includes that adversary must use additional cover
traffic, an anonymity overlay, or a different system.

### 6.3 Modification, replay, downgrade (T-ACTIVE-1)

*Adversary:* §3.2.

*Threat:* Modifying packets in flight; replaying old packets; trying
to downgrade the handshake to a weaker primitive.

*Mitigation:* Inherited directly from WireGuard / Noise IKpsk2.
ChaCha20-Poly1305 AEAD detects modification. Per-packet monotonic
counters and the AEAD nonce defeat replay. There is no algorithm
negotiation — the construction string `CONSTRUCTION` and the
identifier string `IDENTIFIER` are pinned, and a peer that does not
agree to them does not handshake. (See `crypto.c` and the
`CONSTRUCTION`/`IDENTIFIER` constants in `wg.h`.)

### 6.4 Off-path injection / spoofing (T-ACTIVE-2)

*Adversary:* §3.2, no on-path access — only the ability to send
forged UDP from a guessed address.

*Threat:* Spam the device with packets pretending to be a peer, to
exhaust CPU, to trigger spurious rings, to extract information from
error responses.

*Mitigation:* `msg1` MAC1 over the responder's pubkey rejects
forgeries from anyone who doesn't already know the responder's
public key. Under load the responder issues a `msg3` cookie reply
and requires `MAC2` proof of round-trip from any new initiator,
which converts the spoofing attack into a bandwidth-limited PoW.
The `session_id` is a random 64-bit token minted by the initiator and
the `call_id` a random-start 16-bit counter per peer, so a blind
off-path attacker cannot guess either with useful probability.

The call protocol's stale window (`CALL_ID_STALE_WINDOW` = 5,
`peer_data.h`) answers a straggler from a finished call with
`VOICE_SUB_CALL_ENDED` and never disturbs a live one.

**Who may handshake at all is the user's setting**, enforced in
`policy.c admit_handshake` (the wg `validate_public_key` hook):
presence Offline rejects everyone; a contact flagged Blocked is
refused; a non-contact is refused under EVERY allow policy — under
"Requests" it is recorded as a knock for the user to review, never
given a session. The old bench override that accepted every
handshake is gone.

### 6.5 Relay can read content (T-RELAY-1)

*Adversary:* §3.3.

*Threat:* The relay sees every packet that crosses it. If the relay
could decrypt them, peer-to-peer conversations would be wide open to
whichever relay operator the user happens to be using.

*Mitigation:* The relay holds *no* cryptographic key material for
the peer-to-peer session. Peer-to-peer `msg1` and `msg2` traverse
the relay as opaque bytes; the relay's routing decisions key off the
unencrypted `sender_index` / `receiver_index` (the 32-bit
`part_key`) in the WireGuard envelope, not off the payload (the relay dispatches msg2 by
`pr->dest_key`). The relay can confirm that A and B are
exchanging packets but cannot read what they exchange.

*Residual risk:* The relay learns the metadata graph. This is
explicitly accepted; see §6.6.

### 6.6 Relay learns who-talks-to-whom (T-RELAY-2)

*Adversary:* §3.3.

*Threat:* Even without content, a relay that logs every
`(src_partkey, dst_partkey, timestamp)` tuple has the social graph
of every user it serves.

*Mitigation:* Partial — diluted, not eliminated.

- The design targets a *multi-relay* topology:
  the active relay list is published in a DNS TXT record, the client
  picks one, and falls back to a different relay on timeout. A single
  rogue relay sees only its own subset of traffic.
- A user can configure their own relay manually — operators who do
  not trust the public relay pool can run their own and use only
  that.
- The relay never receives the user's *full* public key on the data
  path; it works in terms of the 32-bit `part_key`. (Note: this
  reduces *immediate* identifiability on a packet capture, but does
  not stop a relay that already knows the registry from correlating
  part_keys to public keys.)
- On the OUTBOUND path the relay never learns the *initiator's*
  identity at all: `msg1.sender_index` carries only B's (the
  destination's) part_key (`wg.c` sets it from `remote_static_public`),
  A's static key rides in encrypted `enc_static`, and every link we
  originate — and the directory query — leaves on netif's **anonymous
  socket** (`INTERFACE_ANON`, an ephemeral source port registered
  nowhere), while the login and inbound links stay on the identity
  socket. The relay sees `(A's transient src_ip:port, B's part_key)` —
  A is re-identifiable only by cross-referencing that src_IP against
  A's login (same device, same public IP).

*Residual risk:* A user who routes through a compromised relay
*persistently* leaks their interaction graph — via the **src-IP**
correlation above, no longer via a stable initiator identity — for the
duration of that routing. Rotating relays helps but does not erase what the old
relay already logged. *Xyfr does not claim relay-side metadata
privacy at the level of an anonymity network.* Users for whom that
property is critical should run their own relay or layer a Tor-class
overlay underneath.

### 6.7 Server learns the user base (T-SERVER-1)

*Adversary:* §3.4.

*Threat:* The central server holds the public-key registry
(`users.public_key`, `users.partkey`, `users.expires_on`). A compromised server enumerates every
registered user.

*Mitigation:* Accepted. The server *must* hold the public-key
registry — that is its job. The defence is the boundary, not the
content: the server holds only the public side of the long-term key,
the activation expiry, and the last-seen relay endpoint. It does
*not* hold conversation history, contact lists, or messages.

The activation table is deliberately scrubbed of identity linkage: the
`activation.request_id` column must never carry the activator's
public key or partkey. The relationship "who bought activation code
X" → "who activated code X" is unrecoverable from the database
alone.

Contact lookups do not feed this adversary either: the lookup is
**anonymous**. A `msg7` query (`wg.c peer_query_generate`) carries a
fresh ephemeral keypair and the 4-byte queried partkey and nothing
else — no `enc_static`, no querier field, no signature — so the
directory answers *what* is being asked without learning *who* is
asking. The relay tunnels it inside its own server session
(`secserver/relay_tunnel.h`), so the server sees the relay's address,
not the device's; the relay sees the device but only ciphertext.
Neither holds both halves of `(querier, queried)`. `handle_lookup` is
a pure read that logs nothing. The device also sends a **cover query** to a
random contact every `lookup_query_min_ms`..`_max_ms` (15–20 min,
`contacts.c`), so a real lookup carries no timing signal.

*Residual:* an observer who can see both the querier's uplink and the
server can still correlate by timing; a rate-limit on lookups, if one
is ever added, must key on the transport source, never a user id.

### 6.8 Server returns a forged contact endpoint (T-SERVER-2)

*Adversary:* §3.4.

*Threat:* When a client looks up a contact's last-known relay
endpoint, a compromised server returns the adversary's endpoint
instead, attempting to MITM the resulting handshake.

*Mitigation:* The contact's *public key* is held on the *user's*
device (in the encrypted filesystem), and the handshake is
authenticated against it. The server can lie about *where* to send
the handshake, but an adversary at the falsified endpoint cannot
complete the Noise IKpsk2 handshake without the contact's private key.

The worst the server can achieve is to point handshakes into a
black hole (denial of service). It cannot convert that into
content access.

*Caveat — the directory supplies the key's tail.* A user types only
the 8-hex partkey; `msg7` returns the other 28 bytes. A compromised
directory could answer with an impostor's key that shares those
first four bytes (a grindable 32-bit collision). That is what the
verify gate in §9.5 exists for: the user confirms the WHOLE resolved
key out of band, once, before the first Text/Call/Talk/Terminal, and
the contact stays marked unverified until then.

### 6.9 Lost or stolen device, casual (T-DEVICE-1)

*Adversary:* a pickpocket; a child; an airport-security inspection.

*Threat:* The contact list and message log can be read off the
device by whoever holds it.

*Mitigation:* There is no general-purpose OS to extract files
through, no USB mass-storage mode, no on-screen "export" button. A
casual taker who tries the obvious user interactions sees the same
screens the user did — behind the UI PIN, if one is set — and a
reflash preserves nothing they can read. At rest, contacts,
settings, message log and the wg private key are AEAD-encrypted
(`STORAGE_SECURITY.md`, §9.3): a raw flash dump yields ciphertext plus
public KDF parameters.

*Residual risk:* two, both in §9.3. A device whose user never set the
8-word disk key still wraps its volume key under the public default
passphrase, so an *informed* taker with the source can derive it from
a dump. And a *powered-on* device holds the volume key in SRAM whether
the screen is locked or not — the UI PIN gates the screen, not the
key (the keystore's own session PIN is built and not wired). Casual
theft: closed. Informed flash extraction: closed per device once its
disk phrase is set.

## 7. Properties the system intentionally provides

To make the contract concrete, here are the security properties the
design claims to deliver against the adversaries above:

- **Content confidentiality, peer-to-peer.** Against §3.1, §3.2,
  §3.3, §3.4: every byte of voice or text payload is encrypted under
  ephemeral session keys derived per-call and never seen by the
  relay or the server.
- **Content integrity.** Against §3.2: AEAD detects any modification.
- **Forward secrecy of completed sessions.** Against future
  compromise of long-term keys: completed sessions remain
  unrecoverable.
- **Replay resistance.** Against §3.2: monotonic send counters + AEAD
  nonces on the handshake, plus a per-keypair sliding-window anti-replay
  check on every msg4 data frame (`peer_check_replay`, J-2), so a captured
  voice/text frame cannot be re-injected.
- **Identity authentication.** A peer cannot impersonate another
  peer without the impersonated peer's private key, given the
  recipient holds the impersonated peer's correct public key.
- **No content backup off-device.** The server holds no
  conversation data; there is nothing to subpoena.
- **No identity-to-activation linkage at rest.** The activation
  database holds opaque session_ids on consumed codes, not partkeys.
- **Anonymous contact lookup.** Against §3.3, §3.4: resolving a userid to
  its current endpoint carries no querier identity (a fresh ephemeral
  keypair per `msg7`, relay-tunnelled to the server), so neither the relay
  nor the directory can build a (who-asked, who-was-asked) graph (§6.7).
- **Initiator anonymity from the relay.** Against §3.3: the relay never
  receives a peer's static key (it routes by opaque `session_id` /
  `part_key`), and each call or message a device originates leaves on a
  per-session ephemeral source port registered nowhere — so the relay
  learns *that* a device gets a call/message, not the peer's identity.
  Residual: a device's flows share one public src-IP (§6.6, §9.2).
- **Encryption at rest.** Against §3.5 (device theft, non-hardware): the wg
  private key, contacts, contact log, and message log are AEAD-encrypted on
  flash; the volume key lives in RAM only and is re-derived each boot. Holds
  once the user sets their 8-word disk phrase — the disk key is not stored
  on the device — while a device left on the public default passphrase stays
  readable to an informed attacker (§9.3).
- **No always-on microphone.** The microphone is sampled by an ADC
  callback that runs only when a call is open; outside of calls
  there is no audio path.

## 8. Properties the system does *not* claim

These are stated as explicitly as the §7 list, because under-claiming
beats over-promising:

- **Full anonymity from the relay.** The relay learns an *endpoint*-level
  timing graph (which endpoints trade traffic, when) — but never peer
  identities or static keys, and origination ports are ephemeral and
  registered nowhere, so it cannot attribute an outbound call to a stable
  identity (§9.2).
- **Anonymity from the central server.** The server learns the user
  base, when each user is online, and which relay they currently
  use.
- **Anonymity from a passive observer of the user's own link.** The
  voice cadence is a strong fingerprint of an in-progress call.
- **Cover traffic for conversations.** There is none. A device that is
  not in a call emits only the login's NAT keep-alive
  (`netif_keepalive_ms`, 20 s), a route-refresh frame on a warm peer
  link at the same pace, and the directory's cover query (§6.7). The
  cover query hides *when* a lookup happened; nothing hides that a call
  or a message happened.
- **Resistance to a coerced user.** No deniable-messaging features. A
  duress/burner code *is* built (`74f6fb2`; UI not yet device-verified) —
  a second lock-screen PIN that selectively wipes burner-flagged contacts
  and their history and re-locks silently as an ordinary PIN — but that is
  a targeted panic-wipe, not general coercion resistance.
- **Resistance to a hardware-equipped attacker in possession of the
  device.** See §9.1 — narrowed to a powered-on/unlocked RAM-probe residual
  once the user sets the disk phrase (the wg private key and all at-rest
  data are then ciphertext-only, and the disk key is not stored on the
  device), but not eliminated, and still open on a device left on the
  public default passphrase.
- **Verified provenance of the firmware image for a user who does
  not reflash.** Anyone can drag a checksum-verified `.uf2` onto
  the BOOTSEL volume — the skill barrier is not the issue. A user
  who simply turns on a handed-over device and uses it as-is
  trusts whoever handed it to them. See §9.4.
- **An at-rest trust root that is armed *by default*.** The at-rest
  encryption mechanism is built and device-verified (contacts, settings,
  message log, private key — §9.3), and the 8-word disk-key UI exists to arm
  it — but out of the box the volume key is wrapped under a public default
  passphrase, and stays that way until the user sets their disk phrase.
  (The duress/wipe code once listed as missing here is now built as the
  burner code — see the coerced-user item above.) See §9.3.

## 9. Residual risks and explicit non-goals

This section is the most important one. The compact summary: every
property the system *does* provide is purchased at a cost, and the
costs are listed here so future design discussions can decide which
to pay down and which to keep.

### 9.1 Device-physical attack

A device in the hands of an adversary with hardware tools. Encryption
at rest (§9.3, `STORAGE_SECURITY.md`) reduces a flash dump to
ciphertext, so the residual hardware-class risk narrows to a
**powered-on** device (RAM probe / glitch) — and today "powered on"
means "unlocked": the UI PIN (`registeration.cpp`) gates the screen
while the volume key stays live in SRAM. The keystore's session PIN
(`ks_set_pin` / `ks_lock_session` / `ks_unlock_pin`, `keystore.c`),
which would re-wrap the in-RAM key and zero the plaintext, is built,
host-tested and has no firmware caller; an idle auto-evict is not
built either. Two further caveats: the volume key stays wrapped under
the public default passphrase until the user runs the 8-word disk-key
flow (Security > Change Disk Key), and the build deliberately does
**not** use the RP2350 OTP/secure-boot anchor (irreversible, and it
kills the BOOTSEL dev/reset path) nor a proprietary secure element
(the audit dead-ends at the chip). A defensively-split or *open*
secure element is a documented future option, never the sole gate.
`ota.cpp`'s staging region was carved with a future secure-update path
in mind; nothing verifies a signature today.

### 9.2 Relay-graph metadata

A persistent, compromised relay sees *endpoint-level* traffic for as long
as the user homes onto it — which endpoints exchange packets, and when —
but never the identities behind them. *Mitigations in design:* multi-relay
rotation, manual relay choice. *Mitigations in the code:* the relay never
receives a peer's static key — it routes by opaque `session_id` /
`part_key`, and `msg1.sender_index` names the destination, not the
initiator — and every link a device *originates* leaves on netif's
anonymous socket (§6.6), an ephemeral source port registered nowhere.
So on the receiving side the relay learns only *that* you got a call or
a message; the originating endpoint is attributable to no registered
identity. *Residual (inherent):* the relay forwards both legs of a live
call, so it sees two endpoints trading traffic through it, and all of a
device's flows share one public **src-IP** — a relay that also watches
that IP log in can re-link by address (same device, same IP), never by a
stable initiator identity. Under NAT/CGNAT the port split also breaks
the trivial port correlation a global relay-log harvester would use; on
a dedicated public IP it does not. *Not in scope:* an anonymity-network
overlay or cover traffic that would also hide the src-IP.

### 9.3 Cleartext-at-rest

Historically the contact records, message-log entries, keys, and Wi-Fi creds sat
in cleartext (the old `/c/<userid>.bin` files + the EEPROM block). Anyone who
could read the flash could read everything the user had stored.

*Mitigation — built and device-verified (`STORAGE_SECURITY.md`,
`docs/protocol/storage.md`).* Two-tier encryption at rest, all on auditable software
using `crypto.c` primitives only (no `wg.c`/`crypto.c` edit):

- A raw-flash **bootblock** (`bootblock.c` + `keystore.c`) holds the wg
  private key (AEAD-wrapped) and the wrapped **volume key**. A purpose-built
  raw-flash store outside LittleFS holds the bulk: the **settingsblock**
  (`struct device_record` — Wi-Fi creds and settings, encrypted whole under
  the volume key) and the **filesystem** (`filesystem.c`) — one file per
  contact or channel, whose header (the contact record) and log entries are
  sealed under that file's OWN data key, that key being wrapped under the
  volume key. Destroying the file blanks the key wrap: one write is the delete
  and the crypto-erase.
- Key schedule: `passphrase → keyed-BLAKE2s PBKDF2 → KEK → unwrap volume key →
  decrypt data`. The decrypted volume key lives in RAM only and is re-derived
  each boot.
- Verified: the host storage suite passes (valgrind-clean), plus device tests
  on real RP2350 flash across a power cycle. A flash dump yields AEAD
  ciphertext + public KDF params, not plaintext; a wrong volume key shows up
  as named files that will not open, not as an empty store.

**The trust root is armable, and three honest gaps remain:**

1. **It is not armed *by default*.** Out of the box the volume key is wrapped
   under a *public hardcoded default* passphrase (`STORE_DEFAULT_PASSPHRASE`,
   `secure_store.c`), so `store_boot_unlock()` opens the store with no user
   secret — anyone who reads this open-source repo can derive the KEK from a
   flash dump of such a device. The **disk-key UI exists** (`diskkey.c` /
   `bip39.c`, Security > Change Disk Key): a system-generated **8-word BIP-39
   phrase** (~88 bits), a confirm step, a cold-boot unlock prompt, and
   `kdf_iters` = 16384 (≈1–2 s KDF); it has been exercised on hardware. The
   at-rest guarantee is therefore real **per device, once its user sets the
   phrase** — a device left on the default stays open to an informed attacker.
2. **No failed-unlock backoff.** `ks_fail_count()` counts wrong passphrases
   and nothing reads it; the PIN screen re-prompts at once; nothing persists a
   count across reboots. Without a hardware anchor a counter is advisory
   anyway, but the delay it would buy is not there.
3. **Duress/burner code — built, UI device-verify pending.** The duress idea
   shipped as the **burner code** (`registeration.cpp burner_*`, Security >
   Set Burner Code): a second lock-screen PIN that crypto-erases every
   `CONTACT_BURNER`-flagged contact and its thread, promotes itself to the
   normal PIN and erases its own slot, leaving no trace that two codes exist —
   a *targeted* wipe, not the full volume-key erase originally sketched. The
   PIN screens cannot be driven over serial, so no end-to-end test record
   exists.

**On a device whose user has not set the disk phrase, treat device loss as
conversation-content loss against an informed attacker** — the encryption is
structurally in place, but its key on that device is public. A backup file
(`docs/protocol/storage.md`, the backup section) is exactly as private as that
phrase: its outer layer is integrity only.

### 9.4 Firmware provenance

The entire sketch is open-source in this repository, and the
reset path is accessible to every user — not just technical ones.
The RP2350's BOOTSEL mode is hardware-pinned: holding BOOTSEL at
power-on exposes a USB mass-storage volume that accepts a `.uf2`
by drag-and-drop, with no co-operation from whatever firmware is
currently resident. A software-resident attacker cannot block
that reset path.

This gives two practical attestation routes:

- A technical user rebuilds from source via the Arduino IDE (or
  `tools/build.sh`) and flashes the result.
- Any user drops a checksum-verified `.uf2` published alongside a
  release.

What this defeats: a device handed to *any* user with backdoored
firmware on it. The reflash is trivially performable, so the
"shipped with a backdoor" attack is recoverable by the recipient
without involving anyone else.

What this does *not* defeat:

- A user who does not reflash. The shipped image is what they run
  and the device has no built-in way to attest it without external
  comparison.
- Trust in the publisher of the release `.uf2` and its checksum.
  The reflash route shifts trust from "whoever handed me the
  device" to "whoever publishes the canonical image" — a meaningful
  improvement, but not zero-trust.
- A compromise of the build toolchain itself — the Arduino IDE,
  the `arduino-pico` core, the bundled libraries (`PWMAudio`,
  `ADCInput`, `WiFi`, `EEPROM`; `Adafruit_GFX` on the Sharp path), or the host
  compiler — under which "rebuild from source" still produces a
  compromised binary.
- Hardware-level implants (a modified RP2350 or an added chip on
  the board). Out of scope per §3.5 / §9.1.

*Pending work:* a reproducible build recipe pinning every toolchain
version (`tools/build.sh setup` pins none today), and a published
per-release `.uf2` checksum hosted where a verifying third party can
witness it. **Verification must be OFF-device**: software cannot attest
its own integrity, since a tampered image computes nothing and shows
whatever hash it likes. So there will be no "About screen hash" as a
tamper check — hash the release file on a trusted computer before
flashing, or read the flash back over SWD/picotool and hash it there.
The BLAKE2s the firmware updater computes over a staged image
(`ota.cpp`, shown in About) is a transfer check against the uploader's
own checksum, not provenance.

### 9.5 Key-verification ceremony

The handshake authenticates against the public key the user holds
for a contact, and *how* the user got that key matters. A user types
an 8-hex partkey; the directory (§6.8) supplies the remaining 28
bytes. The threat is therefore a lying directory, not an on-path MITM
(traffic is end-to-end, and the server reads nothing) — so the
mitigation is a **full-key visual compare, not an SAS over a session
transcript**, built (`commands.cpp vgate_*`): before the first
Text/Call/Talk/Terminal to a resolved-but-unverified contact, the
device shows the whole 64-hex key and asks the user to read it aloud
with the peer. *Confirmed* sets `CONTACT_VERIFIED` in
`contact.settings` (a green home dot; orange is usable-but-unverified,
hollow is still resolving); *Delete* removes the contact; *Proceed*
runs the action once and leaves it unverified. An SAS is worth
revisiting only if an on-path MITM distinct from a lying directory
enters scope.

*Open:* there is no UI action to re-open the gate for an
already-verified contact (only the bench verb `contact-flag <uid> 8 c`
clears the bit), and the flow has no recorded device test of its own.

### 9.6 Voice-cadence traffic analysis

An observer of the user's link can tell that a voice call is in
progress: an active call is a ~25-frame-per-second flow through AEAD.
What the observer can NOT learn is who is speaking or when, because
**transmission is never gated on speech** — there is no VAD and no
silence suppression; `app_call.c` streams a 320-sample frame every 40
ms for the whole call, and a gap means a dead peer
(`call_voice_timeout_ms`), not a pause. The constant-rate cover
traffic that cadence analysis would otherwise demand is therefore the
design as it stands. *Residual (inherent to any real-time link):* the
existence, start, stop and duration of a call are visible as a flow;
hiding that needs an anonymity overlay or inter-call cover traffic,
both out of scope.

## 10. Upgrades once planned here — all delivered, folded into §6–§9

This section used to hold four planned upgrades. All four are in the code
(or were never gaps), so their effects were merged into the sections they
change on 2026-09-01. The number is kept so external references stay valid.

| Was | Now |
| --- | --- |
| 10.1 Anonymous initiator on `msg1` — never a gap: `sender_index` is the responder's partkey | §6.6, §9.2 |
| 10.2 Encrypted local storage; the duress code shipped as the burner code | §6.9, §9.1, §9.3, §8 |
| 10.3 Anonymous contact lookup (`msg7`/`msg8`, relay-tunnelled) | §6.7, §7 |
| 10.4 Split identity / anonymous sockets (`netif.c INTERFACE_ANON`) | §6.6, §9.2 |

The adversary that 10.4 introduced — **the global relay-log harvester**, a
party reading every relay's routing logs at once — is resisted only in part:
the port split breaks the trivial correlation under NAT/CGNAT, and the shared
public src-IP remains a handle on a dedicated address (§9.2). What remains
open across all four is recorded in §12.

## 11. Summary

Xyfr protects the *content* of voice and text conversations
absolutely (against the adversaries it claims to resist), protects
the user's *interaction graph* against everyone except the relay
the user has selected, and protects the user's *identity registry*
behind a deliberately narrow central-server contract. It does this
by being a single-purpose hardware device with a tiny attack
surface, by reusing the well-studied WireGuard handshake instead of
inventing a new one, and by drawing a sharp boundary between the
relay (a routing function) and the server (a directory function),
each of which is restricted to the minimum knowledge it needs.

The system makes no claim to network-layer anonymity, to defeat
traffic analysis on a watched link, to survive a hardware-equipped
adversary in possession of the device, or to deliver verified
firmware provenance. Those are real properties, real users want
them, and §9 records each as a known gap with a sketched mitigation.

A user evaluating Xyfr should compare §7 (what is provided) and
§8 (what is not) against their own threat model, not against the
marketing of a class of product. The honest claim is the one this
document is built to support: *the content of your call is yours
and your peer's; the fact that you placed it is visible to your
chosen relay; the fact that you exist is visible to the directory.*

---

## 12. Implementation-level findings (code audit, 2026-06-12)

Everything above is an *architecture*-level model: it reasons about
adversaries, boundaries, and protocol design. This section is the
complement — a line-by-line audit of the code that actually parses
hostile bytes (`wg.c`, `crypto.c`, `secserver/relay.c`,
`secserver/server.c`, `secserver/route_pool.c`, the firmware's
inbound-UDP path, and the contact-log parser). The architecture can
be sound while the implementation has a buffer underflow that hands an
attacker the very property §7 promised.

Findings are split on the axis requested for triage:

- **Major** — protocol- or design-level defects: a missing security
  property of the protocol itself (replay, key generation,
  authentication of a routing decision). Fixing these is a *design*
  change, not a one-liner, and several invalidate a specific claim
  in §6/§7 above until closed.
- **Minor** — local implementation defects (bounds checks, integer
  handling, hygiene). Individually a one- or few-line fix, but a
  couple are remotely reachable and rate a HIGH severity despite
  being "minor" in the design sense.

Each finding carries an independent **severity** (CRITICAL/HIGH/
MEDIUM/LOW) so the major/minor *class* and the *urgency* don't get
conflated — e.g. a "minor" memory bug (M-1) is reachable remotely and
ranks HIGH, while a "major" design gap (J-6) is only a slow DoS and
ranks MEDIUM.

> **Re-verified + partly remediated 2026-07-08.** Every finding below
> was re-checked against the code and carries a **Status** line.
> Already-closed before this pass: J-1 (host RNG now `hal_rand`,
> `keygen` rewritten) and M-8 (legacy `contacts.cpp` parser deleted in
> the logbook cutover). **Fixed in the 2026-07-08 remediation pass:**
> M-1 (rx_data length floor + server case-4 gate), M-3 (server case-1
> gate), M-4 (constant-time mac1 at both sites), M-7 (relay `&&`→`||`),
> and the fd-0-sentinel + MD5-scrub parts of M-9; M-2's OOB trigger is
> closed (uninit-peer residue downgraded to latent). The wg.c edits
> (M-1 floor, M-4) were made under a user-authorized scoped extension
> of the J-1 exception. **Fixed 2026-07-09:** J-2 (per-keypair msg4
> anti-replay window, `ae99b35`, wg.c/wg.h under the same scoped
> extension). **Still OPEN:** J-3 (the msg1 timestamp half of the
> anti-replay pair), the relay cluster (J-4/J-5/J-6/J-7), M-5, M-6, and
> the relay metadata-logging part of M-9. M-9's "predictable wg indices"
> is N/A — those variables are dead code.

> **Re-checked 2026-09-01.** J-3 and M-6 are still open in the code
> (`wg.c:598` still reads `//check the timestamp to avoid replay attacks
> TBD`; `tx_data`/`rx_data` still pass `NULL, 0` as associated data at
> `wg.c:816`/`:830`). J-8's three controls are all in the tree
> (`secserver/term_host.c` default-deny `allow_terminal`, the separate
> `xyfr-termd` binary, `secserver/packaging/install-termd.sh` + the
> systemd unit). M-9's relay logging is gated by `relay_log_verbose`.
> The relay half of J-7 (a global activation rate-limit) is still not
> built.

> **Scope note.** `wg.c`/`wg.h`/`crypto.c` are do-not-edit
> security-critical files; this section *documents* defects in them
> but proposes no edits there without explicit sign-off. The crypto **primitives** in `crypto.c`
> (Curve25519-donna scalar clamping, ChaCha20-Poly1305 per RFC 8439,
> BLAKE2s bounds, constant-time tag compare, `crypto_zero` via
> `volatile`) were reviewed and found correct — the defects are in
> the framing/state layer around them, and on the hosts that link
> them.

### 12.1 Major (protocol / design-level)

#### J-1. Host daemons run the CSPRNG unseeded — all host key material is predictable (CRITICAL)

`wg.c:54-58` (`fill_random`) fills key material byte-by-byte from
libc `rand()`. The **firmware** overrides `rand()` with the RP2350
hardware RNG (`ui.cpp:27`), so the device is fine. But the **host
binaries** — `relay`, `server`, `client` — never call `srand()` and
do not override `rand()`, so libc behaves as if `srand(1)` were
called: the output stream is identical on every run. Everything
security-critical on the host flows through `fill_random`: ephemeral
private keys (`wg.c:369,386,622,898`), the 64-bit `session_id`
(`wg.c:855`), and the relay's `device_cookie_secret` (`wg.c:316`).

Worse, `keygen.c:17` mints **long-term identity** private keys from
`srand((unsigned)time(NULL))` + `rand()` — the user's Curve25519
private key has only ~seconds-of-creation worth of entropy and is
brute-forceable offline by anyone who knows roughly when it was
made. (`dbadmin.c` correctly uses `/dev/urandom` for activation
codes — the good pattern exists in-tree, it just wasn't applied to
`keygen` or the daemons.)

*Invalidates:* §6.1 (forward secrecy), §6.4 (cookie PoW), §7
(content confidentiality / identity auth) **for any peer using a
host-generated key or talking through a host relay**. The phone↔phone
case is unaffected.

*Fix (host only, not wg.c):* seed from `getrandom(2)`/`/dev/urandom`
at daemon start; rewrite `keygen` to read 32 bytes of OS entropy
directly for the private key. **Rotate every host key minted by the
current `keygen`/daemons.**

*Status (2026-07-08):* **FIXED.** `wg.c`'s `fill_random` now calls
`hal_rand()` — the platform CSPRNG (kernel `getrandom` on host,
hardware RNG on device) — under a user-authorized one-time exception
to the wg.c do-not-edit rule (2026-06-17), and `keygen.c` was
rewritten to draw its key bytes from `hal_rand()` directly. Key
rotation was assessed as N/A: the keys minted by the old `keygen`
(`test_keys.txt`) are dev-only, non-production identities.

#### J-2. msg4 (DATA) has no anti-replay window — captured voice/text frames replay forever (HIGH)

The RFC-6479 sliding-window check exists but is **commented out**
(`wg.c:265-307`) and never wired in. `rx_data` (`wg.c:800-808`) takes
the attacker-supplied counter straight out of the packet as the AEAD nonce
and returns success on anything that authenticates, with no
freshness check and no `REJECT_AFTER_MESSAGES` ceiling. An on-path
attacker (§3.2) can re-inject a captured DATA frame indefinitely; the
firmware re-enqueues replayed audio / re-processes replayed text.
Confidentiality of *new* traffic is intact (the sender increments its
own counter, so no nonce reuse) — the loss is replay/integrity.

*Invalidates:* the "replay resistance" clause of §6.3 and §7 for the
data plane specifically (the handshake is separate — see J-3).

*Fix:* re-enable a per-keypair replay window in `rx_data`, keyed on
the decrypted counter; reject counters at/below the window or ≥
`REJECT_AFTER_MESSAGES`.

*Status (2026-07-09):* **FIXED** (commit `ae99b35`). `struct peer`
gains `replay_counter` + a 32-frame `replay_bitmap`; `peer_check_replay`
(wg.c:277, RFC-2401 sliding window) is called in `rx_data` **only after
the AEAD tag verifies**, so the counter it records is authentic. The
window is empty (`replay_bitmap==0`) at seed, so a keypair's first frame
(counter 0 included) is always accepted; it is reset to empty at both
`sending_counter=0` (rekey) sites so a rekey's counter-restart is not
mistaken for a replay. wg.c/wg.h edits authorized as a scoped extension
of the J-1 exception. Verified: host+device build green; standalone
window unit test passes; device msg4 both directions store cleanly with
zero replay-rejects on valid traffic, held across 7 live mid-call rekeys.

#### J-3. msg1 handshake has no timestamp anti-replay (HIGH)

`wg.c:578` is a literal `//check the timestamp to avoid replay
attacks TBD`. The TAI64N timestamp is decrypted
(`wg.c:572-577`) but never compared against the last-seen value for
that static key, as stock WireGuard requires. A captured valid msg1
replays: each replay passes mac1/mac2/AEAD, drives a full
`peer_handshake_request_process` (two Curve25519 DH + KDFs), and
`crypto_zero`s existing peer state (`wg.c:583`) — so an attacker
replaying an old msg1 for an *active* peer both burns CPU and clobbers
the live session slot. Because mac1 keys on the responder's **public**
key (not secret), the attacker doesn't even need a captured packet to
reach the DH; the missing timestamp check just makes captured-packet
replay trivial. This overlaps the known inbound-call instability.

*Fix:* persist last-accepted TAI64N per remote static key; reject
msg1 whose timestamp is not strictly greater.

*Status (2026-07-08):* **OPEN.** The `//check the timestamp to avoid
replay attacks TBD` comment is still in place; no comparison exists.

#### J-4. Relay peer→peer path forwards unauthenticated msg1 to any logged-in victim and seeds a route on an attacker-chosen session_id (HIGH)

`on_msg1_to_client` (`relay.c:215-267`) deliberately performs **no
mac2/cookie PoW** (the comment at `:229-237` explains why: the cookie
AEAD would have to be keyed under B's static pubkey, which the relay
doesn't hold). Consequence: any internet host that knows a target's
32-bit `part_key` (public-ish — first 4 bytes of the pubkey) can make
the relay (a) forward an attacker-crafted msg1 to victim B's real
endpoint — which the relay looks up server-side, so the attacker
needn't even know B's address — and (b) install a route entry keyed
by an **attacker-chosen 64-bit `session_id`** (`:240-258`) that then
relays the whole msg2/msg4 stream. The end-to-end Noise handshake
still fails for a caller lacking the right keys, so this is **not a
content break** — it is unauthenticated reflected-packet injection
toward arbitrary logged-in victims plus route-table seeding, and the
substrate for J-5/J-6.

This is the already-acknowledged "relay skips cookie PoW" deferral — recorded here with its full consequence
chain. *Note J-1 makes it worse on a compromised/honest-but-buggy
host:* with a predictable `device_cookie_secret`, even adding the
cookie wouldn't help until J-1 is fixed.

*Fix:* require a round-trip proof from the caller's source address
before forwarding to B (a relay-keyed cookie the caller *can*
validate, or at minimum a stateless source-address cookie); rate-limit
per source IP and per target part_key.

*Status (2026-07-20):* **FIXED.** The peer path now runs a
return-routability cookie, WITHOUT the relay authenticating the caller
(so initiator anonymity is preserved). The server appends B's full
static pubkey to B's login reply over the relay<->server tunnel (an
application field after the msg2, not inside any handshake struct), and
the relay caches it on B's login route (`org_pubkey`). On a peer msg1
with no mac2, the relay issues `peer_create_cookie_reply` keyed under
B's pubkey — which A's existing wg layer decrypts (its mac1 was already
against B's pubkey), so A retries with a valid mac2 and NO firmware
change. The relay validates the echo with `check_mac2` and only then
forwards / seeds a route. A spoofed source never receives the cookie,
so it can neither reflect toward B nor seed a route. The per-dest rate
limit relaxes to a backstop for real-source floods. No wg.c/crypto.c
change; the cookie/mac2 math needs only the relay's own secret + the
caller's source address, never B's pubkey (that is used solely to
ENCRYPT the cookie so A's unchanged decrypt accepts it). Session-layer
correction shipped alongside: a call's msg1 retry now REUSES its
session_id while a live cookie is held (converges to one session per
peer, J-4's cookie needs a stable id) but still RE-MINTS on a plain
timeout (escapes a session_id collision at the relay's endpoint pin).
Verified end-to-end on a local server+relay+two-phones harness: one
challenge, one forward, one session to ALIVE.

#### J-5. Attacker-chosen, unauthenticated session_id enables route squatting (HIGH)

All relay routes are keyed by the sender-controlled, never-validated
64-bit `m1->session_id`; `route_pool_alloc` is first-come idempotent
(`route_pool.c:150-152`), and a second claimant from a different
endpoint is rejected (`relay.c:242`). So an attacker can **pre-claim**
session_ids (predictable/low values, or a sniffed one) to block a
legitimate call from ever establishing its route, or to grab the
session ahead of the real initiator. No per-source cap bounds how many
a single host claims.

*Fix:* bind route ownership to a validated round-trip before
committing the slot; cap outstanding claims per source IP.

*Status (2026-07-20):* **MOSTLY FIXED** by the J-4 return-routability
cookie. Every route-creating relay path now requires a proven
round-trip (a valid mac2) before `route_ingress` — peer calls
(`on_msg1_to_client`, J-4, new), logins (`on_msg1_to_server`) and
lookups (`msg7`) all cookie-challenge first. Combined with 64-bit
random `session_id`s (unpredictable — the "predictable/low values"
worry does not hold for `get_fresh_sessionid`) and the endpoint pin, a
spoofed host can neither pre-claim nor squat a session_id on any of
those paths. The per-source-IP cap in the original fix is deliberately
NOT taken — it would key on the initiator's endpoint, the A->B
metadata the relay is designed not to hold. *Residual:* the ACTIVATION
path (`msg5`) is the one route-seeder still ungated — its mac2 carries
the 16-byte activation code, not a cookie, so it cannot cookie-
challenge. That residual is exactly J-7; closing J-7 closes this.

#### J-6. Relay route table is exhaustible — global denial of new calls/logins (MEDIUM)

The route pool is 8192 slots with **expired-only** eviction (a live
route is never sacrificed — `route_pool.c:154-160`); new peer/activation
routes get a 10 s TTL. There is **no per-source-IP limit** on route
creation, and `on_msg1_to_client` (J-4) needs no prior relationship.
~8192 distinct session_ids within 10 s (≈ 820 pps, trivial) keeps the
table saturated; every subsequent legitimate `route_pool_alloc`
returns NULL and the call/login is dropped (`relay.c:182,248,291`).

*Fix:* cap concurrent routes per source IP; reserve headroom so a
peer/query flood can't starve LOGIN routes.

*Status (2026-07-20):* **MOSTLY FIXED.** Two of the three exhaustion
vectors are closed: (1) the trivial spoofed peer-route flood — the
"~820 pps of distinct session_ids" — is now REFUSED at the J-4 cookie
gate before any `route_pool_alloc`, since a spoofed source never
produces a valid mac2; and (2) LOGIN starvation is closed by the
`route_login_reserve` (1024 slots kept back; peer/activation allocs are
non-high-prio and cannot dip below it). The per-source-IP cap in the
original fix is NOT taken — it would capture the initiator metadata the
relay must not hold. *Residual:* a flood of ungated ACTIVATION msg1s
(see the J-5 residual) can still fill the ~7168 non-reserved slots with
short-TTL query routes, denying new PEER CALLS (not logins). That is
the J-7 vector; closing J-7 closes this too.

#### J-7. Relay activation proxy is an unauthenticated amplifier toward the server (HIGH)

`on_msg_activate_to_server` (`relay.c:279-302`) forwards a client's
activation msg1 **verbatim** to the central server for any sender
whose `sender_index == server_part_key` (a public constant), with no
cookie/PoW. This turns the relay into an anonymous proxy that lets
internet hosts hammer the server's activation/DB write path from
behind the relay's IP, defeating any per-source rate limiting the
server applies, and allocating a route per attempt (feeds J-6).

*Fix:* rate-limit activation forwarding per source IP; require a PoW
before forwarding even though `mac2` carries the activation code.

*Status (2026-07-08):* **OPEN.**

*Update (2026-07-20):* J-7 is now the LINCHPIN of the relay-perimeter
cluster. After the J-4 cookie, activation is the ONLY route-creating
path not gated by a proven round-trip (its mac2 carries the activation
code, not a cookie), so it is the sole residual of J-5 and J-6 as well
— closing J-7 closes all three. Because activation cannot use the
cookie, the anonymity-preserving levers are: a GLOBAL activation
rate-limit at the relay (activations are genuinely rare — one per user
ever — so a low global cap costs legitimate users nothing while
bounding both the route flood and the server's DH burn), plus M-5's
mac1 gate at the server (a cheap MAC before the expensive DH). Neither
keys on the caller, so initiator anonymity is preserved.

*Update (2026-07-20, later):* **MOSTLY FIXED — the server half is
done.** Rather than M-5's mac1 gate (weak: mac1 is keyed on the
server's public key, so it is forgeable) the server now does a cheap
pre-DH `db_code_valid` probe (see M-5). That defangs the AMPLIFIER:
a bogus activation forwarded through the relay now costs the server one
indexed DB read, not a Curve25519 DH, so there is nothing left to
amplify. The probe rejects not just unknown codes but SPENT ones, so a
replayed already-used code (bought, or sniffed off the network) grants no
DH either: a DH runs only for an *unused* code, and that activation
consumes it. The amplification factor is therefore 1:1 — one DH per
paid, single-use code — which is a sale, not an attack. *Residual (the
relay half):* the relay still forwards each activation msg1 and seeds a
short-TTL QUERY route per attempt (the J-6 slot-consumption facet).
That is bounded — `route_login_reserve` keeps logins safe and the 10 s
TTL ages the routes out fast — but not yet gated. Closing it is the
optional GLOBAL activation rate-limit at the relay above; with the
server cost already cheap, it is now a low-severity slot-hygiene item,
not a CPU-amplification one.

#### J-8. The desktop terminal grants an unauthenticated-by-policy shell — full host compromise (CRITICAL)

`secserver/term_host.c` (`term_on_open` / `termg_on_open`) forks a PTY
running the user's login shell for **any peer that completes a wg
handshake**. The peer's identity is fetched and *printed* —
`printf("termg: shell pid %d for peer %08x ...", pid, conn_partkey(c))`
— and then never consulted. There is no allow-list, no path
restriction, and no command restriction.

The shell runs as the **desktop user**, so an admitted peer has
exactly the privileges of the person sitting at the machine: their
documents, their SSH keys, their browser profile, their `~/.xyfr`
private key and `client.conf`. This is a full host compromise, and it
also loops back into the messaging system — the attacker can read the
private key that authenticates that desktop and impersonate it.

wg authentication is not the missing piece and does not save us here:
it proves *which* key is connecting, not that its owner should get a
shell. Any key ever added as a peer, any key recovered from a lost or
stolen handheld, and any key minted by a compromised host `keygen`
(see J-1) reaches the desktop with equal authority. The blast radius
of a stolen device therefore extends from "read that device's
messages" to "own the owner's computer".

*Invalidates:* §7 (content confidentiality and identity auth) for the
desktop and for every peer that trusts it, and undermines §9.1
(device-physical attack) — a stolen device becomes a desktop
compromise rather than a contained one.

*Fix (host only, no format or protocol change):* a three-part perimeter —
  1. **Default deny** with an explicit allow-list keyed on partkey;
     an unknown peer is `TICP_REJECT`ed and queued for the desktop
     owner to approve locally (TOFU), never allowed to prompt for its
     own admission.
  2. **A dedicated OS account** (`xyfr`, no login, no password) that
     terminal sessions run as, following the web-server model —
     privileged start, drop before serving. This is what makes the
     folder boundary REAL: it becomes filesystem ownership enforced by
     the kernel, not a string in a config file that a shell can `cd`
     straight out of.
  3. **Launcher mode** for peers that should not have a shell at all,
     where only listed programs are ever `exec`'d.

*Status (2026-07-20, final):* **FIXED.** The three pieces are in place:
(1) default-deny `allow_terminal` gate; (2) the terminal server is a SEPARATE
binary `xyfr-termd` with its OWN key (`phone` serves no terminal at all); and
(3) the shipped deployment path -- `packaging/install-termd.sh` + the systemd
unit -- creates a dedicated login-less `xyfr` user and runs the daemon AS that
user, so a forked shell is `xyfr`, cannot read your messaging key (different
file, different owner), and is further boxed by `ProtectHome`/`ProtectSystem`/
`NoNewPrivileges` etc. Host-verified functionally; the unit passes
`systemd-analyze verify`. *Residual (operator misuse, not a design gap):*
running the raw `./xyfr-termd` binary by hand as your own login user bypasses
the service and re-opens the exposure -- the same way running any daemon as
root by hand would. The documented, packaged path is safe by construction.
Prior status below.*

*(2026-07-20, later):* **MOSTLY FIXED.** The terminal server is now a
SEPARATE binary, `xyfr-termd`, with its OWN wg key, split out of `phone`
(`phone` no longer registers the terminal app at all -- verified). This is the
containment step: a shell it forks is a child of `xyfr-termd`, so running that
daemon as a dedicated unprivileged user (e.g. `xyfr`) means the shell runs as
that user with no `setuid` anywhere, and CANNOT read the messaging client's
private key -- that key is in `phone`'s config, a different file owned by a
different user. Host-verified: `xyfr-termd` serving on its own key, an allowed
peer gets a shell through it, `phone` serves nothing. What REMAINS for a clean
close: the packaging that actually creates the `xyfr` account and runs the
daemon as it (systemd unit / installer) -- until an operator does that, the
daemon runs as whoever launches it, so the isolation is available but not
enforced by default. Prior status below.*

*(2026-07-20):* **PARTIALLY FIXED.** Control (1), the default-deny
allow list, is IMPLEMENTED and host-verified: `allow_terminal=<8hex>` lines in
client.conf gate both `TERM` and `TERMG` opens; an unlisted peer is
`TICP_REJECT`ed (tested both directions). This closes the worst of it -- a
random authenticated peer can no longer get a shell. Still OPEN: the shell runs
as the DESKTOP USER, so an *allowed* peer is still a full-privilege guest. The
dedicated `xyfr` OS account (2) and launcher mode (3) remain designed only, so
'allow' currently means 'trust this peer with my machine'. Prior text:*

*(2026-07-19):* **OPEN — designed, not implemented.** The
terminal ships in this state today. Until (1) and (2) exist, treat
`./phone` with the terminal enabled as granting every contact a login
on that machine, and do not run it on a host holding anything you
would not hand to the far end.

### 12.2 Minor (implementation / memory-safety)

#### M-1. `rx_data` integer underflow on a short msg4 → multi-GB OOB read (HIGH)

`rx_data` (`wg.c:800-807`) computes `msg4_length - sizeof(struct
msg4)` with **no check** that `msg4_length >= sizeof(struct msg4) +
AUTHTAG_LEN` (24 + 16). A DATA datagram shorter than 24 bytes makes
the subtraction underflow `size_t` to ~`SIZE_MAX`, which is passed as
the ciphertext length into `wireguard_aead_decrypt` → Poly1305, which
then reads ~4 GB past `m4->enc_packet` (the OOB Poly1305 pass happens
regardless of MAC result) → crash/DoS. The firmware's inbound path
length-gates before calling `rx_data`, but **`server.c` case 4 does
not** (see M-2), so this is reachable on the server today.

*Fix:* one line at the top of `rx_data` —
`if (msg4_length < sizeof(struct msg4) + AUTHTAG_LEN) return -1;`
(in wg.c — needs sign-off), *and* length-gate at every caller.

*Status (2026-07-08):* **FIXED.** `rx_data` now returns `-1` on any
`msg4_length < sizeof(struct msg4) + AUTHTAG_LEN` (wg.c, authorized
one-line floor), and `server.c` case 4 length-gates before calling it
— so the underflow is closed at both the caller and the callee.

#### M-2. `server.c` case 4 decrypts attacker data against an uninitialized peer, with no length check (MEDIUM)

`server.c` declares one loop-scope `struct peer a;` (`server.c:97`,
uninitialized) and reuses it across packets. Case 4
(`server.c:219-227`) calls `rx_data(.., &a, m4, r)` with no `r >=
sizeof(struct msg4)` guard (cases 5 and 7 *do* guard) and `a` holding
whatever the last msg1 left — running ChaCha20-Poly1305 over undefined
key state with attacker ciphertext/length. The result is discarded
today (`(void)l`), so it's wasted work + the M-1 trigger rather than a
disclosure — but it's a footgun the moment someone wires up the
output.

*Fix:* check `r` before `rx_data`; track per-session `struct peer` by
`receiver_index` (or drop case 4 until real per-peer state exists).

*Status (2026-07-08):* **PARTIALLY FIXED.** Case 4 now length-gates
(`r < sizeof(struct msg4) + AUTHTAG_LEN` → break) before `rx_data`,
which removes the M-1 trigger and the OOB read. The deeper footgun —
decrypting against the loop-scope uninitialized `a` — is unchanged;
it's harmless today (result discarded) but a caller wiring up the
output would still run AEAD over stale key state. Downgraded from
MEDIUM to LOW/latent.

#### M-3. `server.c` case 1 (msg1) has no length validation (MEDIUM)

`server.c:114-118` casts `buff_in` to `struct msg1` and runs the
handshake with no `r != sizeof(struct msg1)` check (cases 5/7 have
it). A 1-byte datagram is processed over stale bytes of the non-zeroed
1200-byte receive buffer. No overflow (buffer ≫ struct), but wasted
DH and a robustness gap; consistency with the guarded cases is the fix.

*Fix:* `if (r != sizeof(struct msg1)) break;` at the top of case 1.

*Status (2026-07-08):* **FIXED.** Case 1 now opens with
`if (r != sizeof(struct msg1)) break;`, matching cases 5 and 7.

#### M-4. mac1 verified with non-constant-time `memcmp` on the handshake path (MEDIUM)

`peer_handshake_request_process` (`wg.c:540`) and
`peer_response_process` (`wg.c:711`) compare mac1 with `memcmp`, which
short-circuits. The codebase has and uses a constant-time
`crypto_equal` elsewhere (mac2 at `wg.c:360`, Poly1305 tag at
`crypto.c:864`, mac1 in `peer_query_process` at `wg.c:988,1021`) — so
this is an inconsistent, avoidable timing side channel. Low practical
value (mac1 keys on a public value and is forgeable anyway), but it's
free to fix.

*Fix:* use `crypto_equal(mac1, m1->mac1, COOKIE_LEN)` at both sites.

*Status (2026-07-08):* **FIXED.** Both sites now use
`if (!crypto_equal(mac1, …->mac1, COOKIE_LEN))` (wg.c, authorized) —
the constant-time helper already used on the query path.

#### M-5. `peer_handshake_extract_static` runs a full DH per inbound activation msg1 with no mac1 gate (MEDIUM)

`wg.c:480-506` performs a Curve25519 DH + KDF + AEAD-decrypt straight
from packet fields with mac1/mac2 explicitly *not* validated (it runs
before the user is known, on the activation path). An attacker can
flood msg1 with random ephemerals and force one scalar-mult per packet
— a CPU-amplification DoS with no cookie throttle in front. The AEAD
fails (no forged `enc_static`), so no state is created; the expensive
DH already ran. Compounds J-7.

*Fix:* gate behind mac1 (cheap, keyed on the public responder pubkey)
before the DH, or rate-limit activation msg1s.

*Status (2026-07-20):* **FIXED** for the amplification concern.
`handle_activation` (server.c) now grades the code with a cheap pre-DH
probe — `db_code_valid`, a single indexed primary-key lookup on the
plaintext activation code (it sits in `mac2`, readable with zero
crypto) — BEFORE `peer_handshake_extract_static`. A malformed, unknown,
or SPENT code is rejected with no Curve25519 DH, so:

- a random-code flood costs one B-tree lookup per packet, not a
  scalar-mult; and
- a REPLAYED already-used code (bought, or sniffed off the network, where
  `mac2` is plaintext) grants no DH either — a used code past the
  retransmit window grades `used` and is refused pre-DH.

So the DH runs **only for an unused code, and that activation consumes
it**: the amplification factor is 1:1, one DH per single-use $-code,
which is a paid sale rather than an attack. The one carve-out is the
`ACTIVATION_RETRANSMIT_WINDOW_SECONDS` (60 s) grace: a just-used code
still passes so the firmware's lost-reply retry (`regen_activation`
re-sends the same code) reaches the DH and `db_activate_user`'s
idempotency check completes it — a bounded 60 s window that matches the
pre-existing idempotency exposure, not a new one.

The mac1 gate the original fix proposed is deliberately NOT taken: mac1
is keyed on the server's *public* key, so any attacker can forge a valid
mac1 — the code-validity probe is a strictly stronger filter. Host-tested
(`db_code_valid`: unused→1, just-used→1, spent→2, unknown→0, NULL→-1).

#### M-6. msg4 header fields are outside the AEAD associated data (MEDIUM)

`tx_data` (`wg.c:794`) encrypts with `ad = NULL, ad_len = 0`, so the
msg4 header (`session_id`, `receiver_index`, `counter`) is not covered
by the Poly1305 tag. `counter` is implicitly bound (it's the nonce),
but `session_id`/`receiver_index` — the fields the receiver *routes*
on — can be flipped by an on-path attacker without breaking the tag.
Impact is limited (a redirected frame fails to decrypt under the wrong
slot's key), but it's a routing-integrity gap.

*Fix:* pass the header as AEAD associated data in both `tx_data` and
`rx_data`.

*Status (2026-07-08):* **OPEN.** `tx_data`/`rx_data` still pass
`ad = NULL, ad_len = 0`.

#### M-7. Relay login-route ownership check uses `&&` instead of `||` (MEDIUM)

`on_msg1_to_server` (`relay.c:176`):
`if (r->a_ipv4 != rip && r->a_port != rport) return;` — only rejects
when *both* IP and port differ. A packet from the same IP, different
port (same NAT, or an on-path attacker reusing the victim's IP) passes
and is accepted as the route owner. The three sibling handlers all
correctly use `||` (`relay.c:242,286,347`). An authentication-weakening
copy-paste bug on the login path.

*Fix:* change `&&` to `||`.

*Status (2026-07-08):* **FIXED.** `relay.c:176` now uses `||`,
consistent with the three sibling handlers.

#### M-8. `read_record_at` trusts on-disk record length against a caller-sized flexible array (MEDIUM, latent)

`contacts.cpp:311-335` `memcpy`s up to `LOG_MAX_PAYLOAD` (256) bytes
into `struct log_record`'s flexible-array `payload[]`
(`contacts.h:17-21`) with no capacity parameter — correctness is
entirely the caller's to guarantee. The only in-tree caller sizes its
buffer right, so it's safe **today**, but log records originate from
received messages (a peer's text persisted to `/c/<userid>.bin`), so a
future UI caller that under-allocates gets a peer-influenced overflow.

*Fix:* add an explicit `payload_cap` argument to
`read_record_at`/`log_read`/`log_prev`/`log_fwd` and clamp the copy.

*Status (2026-07-08):* **RETIRED.** `contacts.cpp` and the entire
legacy `log_*` parser were deleted in the 2026-06-25 logbook cutover;
the replacement record format (`logbook.c`) AEAD-authenticates each
record and bounds its copies. The finding has no surviving code.

#### M-9. Lower-severity hygiene (LOW)

- **Predictable wg indices:** `next_sender_id` starts at 0
  (`wg.c:26`), `my_next_index` at 786 (`wg.c:834`); stock WireGuard
  randomises them. Limited impact — routing is primarily by the
  random 64-bit session_id. Randomise on assignment.
- **`net.c:43-49` `udp_socket_open`** aliases fd 0 as a bind-failure
  sentinel and `exit(0)`s on hard errors (a supervisor sees clean
  exit). Use `exit(1)`.
- **Relay metadata logging:** `relay.c` and `route_pool_dump`
  `printf` endpoints, part_keys, and session_ids — the exact
  endpoint↔identity correlation §6.6 / the secserver privacy policy
  try to keep the relay blind to. Gate behind a debug flag, off in
  production.
- **`MD5Final` scrub bug** (`md5.cpp:152`): `memset(ctx, 0,
  sizeof(ctx))` clears 8 bytes (pointer size), not the context.
  *No live MD5 caller exists* — the deployed auth is the Noise
  handshake, not the legacy MD5 challenge in `users.schema` — so this
  is latent hygiene only.
- **Byte-at-a-time log delimiter scan** (`contacts.cpp:338-355`):
  one `seek`+`read` syscall per byte over a peer-growable log →
  slow-UI / flash-wear DoS, no OOB. Cap log size; scan in blocks.
  *(Status 2026-07-08: RETIRED — code deleted with `contacts.cpp`
  in the logbook cutover.)*

*Status of the rest of M-9 (2026-07-08):* **PARTIALLY FIXED.**
- *fd-0 sentinel:* FIXED — `net.c` now `exit(1)` on hard socket
  failure (both sites).
- *`MD5Final` scrub:* FIXED — `md5.cpp:152` now `sizeof(*ctx)` (still
  latent — no live MD5 caller — but correct).
- *Predictable wg indices:* N/A — re-checked, `next_sender_id`
  (wg.c) and `my_next_index` (`struct peer`) are **dead**: assigned
  but never read anywhere in the tree. The real routing indices are
  the partkey (`get_part_key`) and the random 64-bit `session_id`, so
  there is nothing predictable to exploit; editing wg.c to randomise
  dead variables was declined as pointless churn in a do-not-edit file.
- *Relay metadata logging:* OPEN — still ungated `printf`s in
  `relay.c` / `route_pool_dump`; deferred (needs a debug-flag design).

### 12.3 Reviewed and found sound (negatives worth recording)

So the register isn't read as "everything is broken," the following
were specifically checked and are correct:

- **SQL injection: closed.** Every `db.c` query is a parameterized
  `sqlite3_bind` prepared statement (verified across all callers);
  the activation code from the untrusted `mac2` field is additionally
  filtered to `[a-z]` before it reaches SQL (`server.c:155-162`). The
  historical MySQL-era `sprintf` holes are gone.
- **Activation flow** is not harmfully replayable (60 s idempotency
  window + atomic `AVAILABLE→USED` transition), and activation codes
  are strong (`dbadmin` reads `/dev/urandom`, 16 lowercase letters ≈
  75 bits).
- **Firmware inbound payload length is bounds-checked** before any
  use (`xyfr.ino` udp dispatch, ~`:524`), so the "peer claims
  len=65535 on a 40-byte frame" OOB-read scenario is **not present**
  on the device — the frame is dropped as a bogus length.
- **DATA_VOICE reconstruction** into `q_speaker` (`audio.cpp:216-227`)
  indexes strictly within `len`; `q_write` is a drop-on-full ring, so
  an oversized voice claim glitches audio, never overflows.
- **Session/call pool indexing** re-validates every attacker-supplied
  `session_id`/index against pool bounds; `call_id` is a compared tag,
  never an array index; the `scratch_peer` DoS-shield runs the msg1
  handshake before allocating a slot, so msg1 floods can't evict live
  sessions.
- **The byte-stuffing de-stuffer** (`contacts.cpp`) guards its
  trailing-escape case (`i+1 < src_len`), so a malformed stuffed
  stream does not read past the buffer. *(Historical — this code was
  deleted with `contacts.cpp` in the logbook cutover.)*

### 12.4 Triage summary

| ID | Class | Severity | Component | Status (2026-07-08) | One-line |
|----|-------|----------|-----------|--------|----------|
| J-1 | Major | **CRITICAL** | hosts/keygen | **FIXED** | unseeded RNG → predictable host keys & identities |
| M-1 | Minor | HIGH | wg.c/server | **FIXED** | `rx_data` length underflow → OOB read DoS |
| J-2 | Major | HIGH | wg.c | **FIXED** | per-keypair msg4 anti-replay window (`peer_check_replay`, ae99b35) |
| J-3 | Major | HIGH | wg.c | OPEN | no msg1 timestamp anti-replay |
| J-4 | Major | HIGH | relay | **FIXED** | return-routability cookie (keyed under B's cached pubkey) + per-dest throttle + endpoint pin (`route_ingress`) |
| J-5 | Major | HIGH | relay | **MOSTLY FIXED** | cookie-gated round-trip + endpoint pin + random 64-bit session_id; residual = ungated activation (J-7) |
| J-7 | Major | HIGH | relay | **MOSTLY FIXED** | server pre-DH `db_code_valid` gate removes the CPU amplification (1:1); relay activation forwarding still ungated but bounded (login reserve + 10 s TTL) |
| J-6 | Major | MEDIUM | relay | **MOSTLY FIXED** | login reserve (1024) + J-4 cookie close login starvation + the spoof flood; residual = activation slot churn (J-7) |
| M-2 | Minor | MEDIUM | server | **FIXED** (latent residue) | msg4 over uninitialized peer, no length check |
| M-3 | Minor | MEDIUM | server | **FIXED** | msg1 case has no length check |
| M-4 | Minor | MEDIUM | wg.c | **FIXED** | non-constant-time mac1 compare |
| M-5 | Minor | MEDIUM | wg.c/server | **FIXED** | server pre-DH `db_code_valid` probe gates the DH — a code flood costs a DB lookup, not a scalar-mult |
| M-6 | Minor | MEDIUM | wg.c | OPEN | msg4 header not in AEAD AD |
| M-7 | Minor | MEDIUM | relay | **FIXED** | login-route ownership `&&` should be `||` |
| M-8 | Minor | MEDIUM (latent) | contacts | **RETIRED** | legacy log parser deleted in the logbook cutover |
| M-9 | Minor | LOW | various | **FIXED** | fd-0 sentinel + MD5 scrub fixed; wg indices N/A (dead); relay metadata logging now `relay_log_verbose`-gated (off in prod) — minor server-side tunnel-debug residual (relay, not client, metadata) |

**Done in the 2026-07-08 cheap-fix pass:** M-1, M-2 (trigger), M-3,
M-4, M-7, and the safe parts of M-9 — all verified to build on host
(`make -C secserver`) and device (`tools/build.sh build`). **Done
2026-07-09:** J-2 (msg4 anti-replay window, `ae99b35`, device-verified
across live mid-call rekeys). **What's left, by cost:** the relay
cluster J-4/J-5/J-6/J-7 is now largely closed (J-4 FIXED; J-5/J-6/J-7 MOSTLY FIXED) — the one remaining relay workitem is a
GLOBAL activation rate-limit that closes the shared J-5/J-6/J-7 residual (the
sole ungated route-seeder is the activation path, whose `mac2` carries the code,
not a cookie). The remaining wg.c items (J-3 msg1 timestamp, M-6 header-in-AEAD)
each need new state or a
transmission-format change and touch do-not-edit files — flag for sign-off
before editing (as was done for J-1's
`fill_random` fix, this pass's M-1/M-4, and J-2's replay window).
