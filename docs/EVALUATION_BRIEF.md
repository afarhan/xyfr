# Xyfr — Technical Evaluation Brief

**For technical evaluation by a government body considering adoption.**

*Prepared from the source code in this repository. Every claim below was
checked against the code, not against the project's own design documents — several of
those have drifted from the implementation and are noted where it matters. Firmware and
host code are published under the **GNU General Public License v3** at
`<REPOSITORY URL — TO BE FILLED IN BEFORE RELEASE>`.*

---

## 1. Scope and summary

Xyfr is a **dedicated handheld terminal for end-to-end encrypted voice calls and text
messages** between parties who already know each other. It is not an application
installed on a phone. The hardware is a Raspberry Pi Pico 2W (RP2350, dual-core
Cortex-M33), a small colour display, a 6×6 matrix keyboard, one microphone on an ADC
input and one speaker on a PWM output. It reaches the network over Wi-Fi and UDP, and
over nothing else.

What the device does not have is as much of the design as what it has. There is no
cellular baseband, no camera, no satellite positioning, no Bluetooth pairing, no
browser, no app store, no general-purpose operating system, and no mechanism by which
third-party code can execute. There is no telemetry, no crash reporting, no push
service and no cloud backup. The microphone is sampled only while a call is open.
Every byte that leaves the device leaves because the user pressed a key.

**Two of those guarantees are enforced by switches, not by software.** One hardware
switch disconnects the microphone. A second cuts power to the whole board. Neither can
be overridden, disabled or faked by firmware — including firmware an attacker replaced —
because in both cases the circuit is simply open. This matters more than it first
appears, and §5.5 returns to it: it means "the microphone is off" and "the keys are
gone" are statements about wiring rather than statements about code the user is being
asked to trust.

**Bluetooth is absent by decision, not by omission**, and it is worth separating from the
rest of the list because it is the one radio a handheld device of this kind would
normally be expected to carry. Four things ruled it out, and any one of them would have
been enough:

- **It is a listening radio.** Bluetooth accepts traffic from devices that were never
  paired with it, so it is remote attack surface reachable by anyone standing nearby,
  present whenever the device is powered on, and requiring no network and no user action
  to reach. Xyfr's only radio is Wi-Fi, and the only party that can send it anything over
  that radio is one whose handshake the device admits (§4.7).
- **Its pairing and key negotiation have been broken repeatedly**, and by whole classes of
  attack rather than by one-off implementation slips — entropy downgrade of the
  negotiated key, impersonation of a previously paired device, and remote code execution
  in the stacks themselves. A security device does not want a second, weaker key exchange
  sitting beside the one it was designed around.
- **The controller firmware is a vendor blob.** A Bluetooth stack is largely closed
  silicon and closed firmware, so putting one inside the trust boundary would dead-end the
  audit in exactly the way §6 and §7 refuse to.
- **It is a proximity beacon.** A Bluetooth radio advertises a stable identifier that
  makes the device trackable in physical space by anyone within range. That is a metadata
  leak with nothing to do with message encryption, and it defeats the point of §4.5 —
  there is no value in denying a relay the social graph while broadcasting the user's
  physical location to the room.

The reasoning behind that shape: in practice the leaks that matter in secure messaging
are rarely breaks of the message encryption. They are the operating system underneath
it, the baseband beside it, the push notification service that knows a message arrived,
the cloud backup that quietly mirrors the plaintext, the screenshot, and the phone
number that ties a messaging account to a carrier billing record. Xyfr removes that
platform instead of trying to harden it.

**Status in one paragraph.** The transport, the messaging system, voice calls,
push-to-talk and the encrypted on-device store are implemented and have been verified on
real hardware. Encryption at rest is structurally complete and device-verified, but on a
device whose user has not run the disk-key wizard the volume key is wrapped under a
passphrase that is a constant in this open-source repository — the mechanism is armed
per device, by the user, and is not armed by default. There is no signed boot and no
reproducible build recipe yet; firmware provenance today rests on a hardware-pinned
recovery path and a published checksum. Four defects in the transport layer are known,
recorded and still open; none of them breaks conversation confidentiality, and all four
are listed by name in §9. Group messaging is in design and is not part of the system
described here.

This document is deliberately organised so that §9 — the status register and the
residual risks — can be read first. A brief that hides its own gaps is not evaluable.

---

## 2. Architecture

### 2.1 Three actors

**Device.** The firmware. The same portable C core also compiles and runs as an ordinary
Linux binary, which is what allows the real code paths to be tested under valgrind and
address sanitiser rather than a re-implementation of them.

**Relay.** A UDP forwarder. All traffic between two devices goes A → relay → B; devices
never send to each other directly. The relay routes on a random 64-bit `session_id`,
plus a 4-byte key prefix for login routes only. It holds **no key material for any
conversation** and its routing state is in RAM. The architecture is multi-relay and **so
is the deployment in service today**: each contact record stores that peer's own relay
endpoint, an outbound handshake goes to the peer's relay rather than to ours, and peers
homed onto different relays exchange traffic across them. Nothing in the design assumes
a single relay and nothing in the deployment depends on one, which is what makes "run
your own relay" (§7) a configuration choice rather than a fork.

**Directory server.** Registration, activation, login presence, and one query:
`userid → full public key + that user's current relay endpoint`. It is **not on the
conversation path**. It never sees a peer-to-peer handshake and never carries
conversation traffic.

### 2.2 The protocol stack

From the bottom up. Each layer rides inside the encrypted payload of the one below it.

| Layer | What it is |
|---|---|
| **wg** (`wg.c`, `crypto.c`) | A WireGuard-derived Noise **IKpsk2** handshake, with the upstream construction strings, the msg1 / msg2 / cookie-reply / msg4 frame set, the mac1/mac2 cookie machinery, and ChaCha20-Poly1305 transport encryption. |
| **netif** (`netif.c`) | Exchange frames with a peer named by its 32-byte public key. The medium is not part of the contract — nothing above this layer contains an IP address, a port, a socket or the word "relay". |
| **stream** (`stream.c`) | A reliable byte stream derived from TCP: sequence numbers, cumulative acknowledgement, retransmission on a timer, and an advertised receive window, addressed by (peer, port). What it drops from TCP is the connection — there is no open, no accept and no close, because a write to a peer and a port *is* the stream. The current implementation advertises a window but keeps one 1024-byte segment outstanding at a time, which needs no send queue, no retransmit list and no reordering. |
| **apps** | Messaging, voice calls, push-to-talk, and a remote terminal. |

Two transports sit above the session and only two: an unreliable datagram for real-time
media, where a late frame is worthless, and the reliable stream for anything that must
arrive.

**One consequence is worth naming to an evaluator.** The reliable stream withholds its
acknowledgement until the receiving application has written the bytes to flash. A
message therefore has no application-level "delivered" reply, because the transport
acknowledgement already means "durably stored on the recipient's device." There is no
place in the design where a server could generate a delivery receipt, because no server
is involved.

### 2.3 Identity and addressing

A peer **is** its Curve25519 public key. There is no account, no phone number, no email
address and no user record the user does not create themselves. The short identifier
used everywhere — in routing, in the directory database, in the contact list, and as the
8-hex-character userid the user reads aloud — is the **partkey**: the first four bytes
of the public key as a big-endian 32-bit integer.

A four-byte identifier can collide, and two independent facts make that an
administrative matter rather than a threat.

**The directory will not admit a colliding key.** Keeping one partkey mapped to one
public key is the server's responsibility, and the schema enforces it: the users table
makes the partkey the primary key, and registration counts the existing rows for that
partkey before inserting. A second key whose first four bytes match a registered user's
is not accepted into the directory, so the collision an attacker would have to
manufacture cannot be published.

**And the handshake never runs on four bytes.** Authentication is against the full
32-byte public key — all 256 bits — so a key deliberately generated to share a victim's
prefix still cannot complete a handshake in the victim's place; the attacker would need
the victim's private key, which is what the prefix has nothing to do with. Every
admission decision on the device compares the full 32 bytes (`policy.c`,
`admit_handshake`), and a peer matching on the prefix but differing anywhere in the
remaining 28 is refused.

The partkey is a routing and lookup convenience. Nothing authenticates on it.

Resolving a userid to a full key and a current endpoint is an anonymous query (§4.6).

### 2.4 Storage

The device does not use a general-purpose filesystem. It uses a purpose-built store over
raw flash sectors, because deterministic erase is the point — a wear-levelling
copy-on-write filesystem actively fights crypto-erase by design, keeping copies the
application cannot see or destroy.

The key schedule, all of it built on the primitives in `crypto.c`:

```
disk passphrase
  └─ KDF (PBKDF2 structure, keyed BLAKE2s as PRF, 16384 iterations)
      └─ key-encrypting key
          └─ unwraps the volume key (random, stored wrapped on flash)
              ├─ wraps the device's Curve25519 private key
              ├─ encrypts the settings image
              └─ wraps each file's own data key
                  └─ that file's contents
```

The decrypted volume key exists in RAM only and is re-derived at every cold boot. The
disk passphrase is **generated by the device**, not chosen by the user: an 8-word BIP-39
phrase, roughly 88 bits of real entropy. Machine-generated entropy is what makes a
16,384-iteration KDF an acceptable choice; a user-chosen passphrase at that iteration
count would not be.

**One contact is one file, and its message history is that file's log.** The file's data
key is minted when the file is created and never leaves the device. Destroying a contact
scrubs that key, which makes the contact record *and its entire message thread*
unreadable in one operation, with no sweep over the flash and no other file touched.

**What a contact record holds** is the peer's name, its full 32-byte public key, the
relay endpoint to reach it at, the data key for its message log, a per-contact settings
bitmap, and **a 32-byte preshared key for that peer**. The whole record is the encrypted
body of one file header, so every one of those fields — the peer's identity and its
preshared key alike — is AEAD-encrypted under the file's own key and is destroyed with
it. Keeping the preshared key *in the contact record* rather than in a global table is
what makes it per-peer: two users' shared secret is stored with the relationship it
belongs to, it is crypto-erased when that relationship is deleted, and no other contact's
compromise reaches it. That key is the input to the handshake's preshared-key stage, and
what it buys — resistance to an adversary recording traffic today against a future
quantum computer — is §3.3.

The first 32 bytes of each file's index entry are deliberately **cleartext** — the file
identity, its type, and a write counter — and that same span is the associated data of
the key wrap. Two properties follow. The device can list what it holds without any key
at all, so a mount is possible before the user has unlocked anything; and a wrong volume
key surfaces as a *named file that will not decrypt* rather than as a store that looks
empty. A design that fails by looking empty invites a user to overwrite their own data.

---

## 3. Assets and adversaries

### 3.1 What is being protected

1. **Conversation content** — the audio of a call, the text of a message, in transit and
   at rest.
2. **The social graph** — who talks to whom, when, how often, for how long. For many
   users this is more sensitive than the content.
3. **The long-term identity key** — the device's Curve25519 private key.
4. **Per-session ephemeral keys** — short-lived, but they decrypt one recorded session.
5. **The stored contact list** — an offline snapshot of part of the social graph.
6. **The stored message history.**
7. **Device location** — the IP address the device is currently reachable from.

### 3.2 The adversaries

Four ordinary classes, and then the class this evaluation is really about.

- **Passive network observer.** Sees traffic, cannot modify it. Bulk collection at
  arbitrary scale.
- **Active network attacker.** Drops, replays, reorders, modifies and injects UDP.
  Includes a hostile Wi-Fi access point.
- **Compromised relay operator.** Assumed worst case: the adversary owns whichever relay
  the user selected, reads every packet crossing it, logs source and destination
  addresses and timing, and shares the log.
- **Compromised directory server operator.** Can enumerate the registered user base,
  learn which relay each user currently homes onto, and return a falsified answer to any
  lookup.

### 3.3 The state actor, decomposed

"State actor" is not a capability. Treating it as one produces a document that either
claims too much or gives up. The capabilities that actually distinguish a state
adversary from a well-funded criminal one are these, and each is answered separately in
§4 and §5:

| Capability | Where it is answered |
|---|---|
| Bulk passive collection of the carrier network, retained for later decryption | §4.1 |
| Active interception and modification on any link | §4.2 |
| **Legal compulsion of the relay or directory operator** — the operator is ordered to hand over what it has | §4.3, §4.4, §8 |
| **Interdiction of a shipment** — the device is opened in transit and its firmware replaced | §5.2 |
| **Evil-maid access** — a device already in service is reflashed while its owner is away | §5.3 |
| A forensics laboratory with the device in hand | §5.5 |
| Coercion of the user | §5.6 |
| Correlation of infrastructure logs across operators and carriers | §4.5, §9 |

**One state capability the protocol answers structurally: harvesting traffic now to
decrypt it with a future quantum computer.** The handshake is Noise **IKpsk2** — the
preshared-key variant — and the preshared key enters the handshake as its own key
derivation stage, mixed into the chaining key on top of the Curve25519 exchanges rather
than instead of them. Two peers who share a preshared key out of band therefore have a
**hybrid**: recovering a recorded session requires breaking the elliptic-curve exchange
*and* holding the preshared secret. A quantum computer capable of the first does not, on
its own, decrypt the traffic. That is the standard answer to "record everything today,
decrypt it in fifteen years", and it costs nothing at run time — the preshared key is
mixed in by the same derivation the handshake already performs.

The construction is present and correct in the transport: `wg.c` mixes the preshared key
through `wireguard_kdf3` on both the initiator and the responder paths, and the contact
record reserves 32 bytes per contact to hold one. **It is not populated in the current
build.** Nothing outside `wg.c` assigns a preshared key, so the value mixed in is
all-zero and the hybrid is available in the protocol rather than armed in the product.
Distributing and storing per-contact preshared keys is listed in §9.4 as outstanding
work; it is the single highest-value item on that list, because it is the only one that
changes what a recorded session is worth to an adversary who waits.

Two capabilities are stated as **out of scope**, plainly, because no measure in this
system touches them: replacement of the RP2350 with a modified part before the device
reaches the user, and a break of Curve25519 or ChaCha20-Poly1305 as they stand today
against a classical adversary. A brief that claimed otherwise would be misleading.

---

## 4. Threats and the mechanisms that answer them

### 4.1 Recording traffic now to decrypt it later

Every session is established by a Noise IKpsk2 handshake with per-session ephemeral
Curve25519 keys, and those ephemeral keys are never written to flash. A session that has
completed cannot be recovered from a later compromise of the long-term identity key —
the recorded ciphertext is not decryptable with the static key alone. Links re-handshake
every 120 seconds while in use, so the material covered by any one ephemeral key pair is
bounded.

Against the specific version of this attack that waits for a quantum computer rather
than for a key compromise, the structural answer is the preshared-key stage of the
handshake described in §3.3 — present in the protocol, not yet populated per contact.

*Residual:* forward secrecy is a property of completed sessions. A live session on a
device seized while powered on and unlocked is a different matter, treated in §5.5.

### 4.2 Modification, replay and injection on the wire

Content integrity is the AEAD's: any modification of an encrypted frame fails its
authentication tag and the frame is discarded. Replay is handled at two levels. The
handshake carries monotonic counters. Every data frame is checked against a sliding
replay window keyed to the current key pair, after its tag has verified, and the window
is reset on every rekey.

*Two deviations from upstream WireGuard are relevant here and are open findings, not
design choices.* The replay window is 32 bits wide where upstream uses roughly 2048 —
correct logic, a smaller tolerance for the reordering a 25-frames-per-second voice
stream produces. And the initiation message's timestamp is decrypted but **never
validated**, so the anti-replay protection WireGuard specifies for the handshake
initiation is absent; a captured initiation can be replayed to force a session reset.
That is a denial-of-service defect, not a confidentiality one — the replayed handshake
completes only with keys the attacker does not hold — but it is a real defect and it is
listed in §9.

### 4.3 A relay that reads everything crossing it

The relay is assumed hostile. It sees encrypted envelopes and the source and destination
addresses of those envelopes. It holds no session key and no static key belonging to any
conversation, and it routes purely on an opaque 64-bit session identifier that the
initiator mints at random. Its route table lives in RAM and is a fixed pool with
expiry-only eviction — a live call is never evicted, and a full pool fails an allocation
rather than dropping someone's call.

The relay is also where the denial-of-service perimeter sits. It enforces the cookie
proof-of-work challenge on handshakes and on lookups, it pins a session identifier to
the endpoint that first used it and rejects the same identifier arriving from a
different address, and it strips a client's cookie before forwarding a handshake onward.

*What a compelled relay operator can produce:* a list of which network endpoints
exchanged traffic through it, and when. *What it cannot produce:* the content, the
identity behind an endpoint, or a peer's public key — the relay never receives one.

### 4.4 A directory server that lies, or is compelled

The directory answers one question and stores no conversation data, so a subpoena
against it returns registration records and nothing else. Its activation table is
explicitly built so that the code a user redeemed cannot be linked back to that user:
the bookkeeping column holds an opaque session token, never a public key or a partkey,
and any prior "sold to" value is overwritten when a code is consumed.

A hostile directory can still lie in its answer to a lookup. This is worth stating
precisely, because it is the difference between an inconvenience and a break. The
lookup returns a public key and an endpoint. **The handshake that follows is
authenticated against the key the device already holds for that contact.** So for an
existing contact, a forged directory answer can black-hole the traffic — a denial of
service — but cannot decrypt or impersonate. The exposure is at *first* resolution, when
the device has no stored key to check against, which is exactly why the absence of an
out-of-band key-verification ceremony is listed in §9 as a real gap and not a nicety.

### 4.5 Bulk metadata collection

The directory learns who is registered and which relay a user homes onto. The relay
learns an endpoint-level timing graph. Neither learns conversation content. Two design
choices limit what those two logs are worth when combined:

**The identity a device presents to its relay is not the identity it uses to originate.**
Two UDP sockets are used. One is the identity socket, on which the device logs in and by
which the relay knows it. Originations go out on a separate socket that is registered
nowhere and never used to log in. The relay therefore learns *that* a device received a
call or a message, not who placed it.

*This is one place where the project's own threat model overstates the code and this
brief corrects it.* That document describes a fresh ephemeral source port per
origination. The code opens the anonymous socket once, lazily, and reuses it for the
life of the boot. The split between identity and origination is real; per-session
rotation is not implemented.

**The lookup does not identify the querier, and cannot be timed.** See §4.6.

*Residual, and it is inherent:* every flow from a device shares one public IP address. A
party that watches both the relay and that address can re-link by address. Defeating
that requires an anonymity-network overlay at the network layer, which Xyfr does not
attempt and does not claim.

### 4.6 The contact lookup, and why its timing carries no signal

Resolving a userid uses a purpose-built query pair rather than a logged-in session. The
device mints a **fresh ephemeral key pair for every query**, derives a key by
Diffie-Hellman straight to the server's static key, and encrypts a four-byte payload —
the userid being asked about. The query carries no querier field, no static key and no
signature. The server is stateless in handling it and the handler is a read: it logs
nothing and stores nothing.

The query is tunnelled inside the relay's own encrypted session to the server. So the
**server sees the relay's address, never the device's**, and the **relay sees opaque
ciphertext, never the userid**. Neither party holds both halves of `(who asked, who was
asked about)`, and neither can reconstruct it from the other's absence.

Timing is handled as a first-class concern rather than left to chance. The device
queries one contact from its list every 15–20 minutes at random, walking the list in
round-robin order and **querying resolved and unresolved contacts alike** — because
asking only about the interesting ones is precisely what would make the timing
informative. A genuinely new contact is resolved immediately and is indistinguishable
from the periodic traffic. Retry after a timeout is a single global backoff from 30
seconds to 15 minutes, retrying indefinitely; exhausting it never marks a contact as
non-existent, because "we could not reach the server" and "the server says no such user"
must not be confused.

### 4.7 A stranger trying to reach the device

A non-contact cannot deliver anything to the device, and this is enforced below the
application: the handshake itself is refused. The refusal is unconditional under every
allow-policy setting, so a stranger never obtains a session and nothing it sends can
reach storage.

What happens to the refused stranger is deliberately split in two. The device records
the attempt in one of ten RAM slots — a **knock** — and refuses. Separately, the lookup
pump asks the directory whether that key belongs to a registered user, and the knock is
shown to the user only if the server confirms it **and** the returned 32-byte key
matches byte for byte. An unverified or forged knock is never surfaced.

The economics are the point. A key pair is free, so a per-key block list is worthless. A
*registration* costs a single-use activation code. A flood of freshly generated key pairs
churns ten RAM slots and touches not one byte of the 1.8 MB flash store.

Real-time media passes a second gate on top of that one. Inbound voice and
push-to-talk are contacts-only regardless of policy, and a blocked or
presence-suppressed contact is refused even though its text messages are accepted. A
refused call is declined **before a call slot is allocated**, so a stranger can neither
occupy the call pool nor draw ringback tone out of the device, and the refusal is
indistinguishable from the device being busy.

---

## 5. Firmware integrity against a state actor

This section is the one an evaluator should read hardest, because it is where the honest
answer is partly "designed, not built", and where the threat is most specific to a state
adversary.

### 5.1 What the attack actually is

An adversary who cannot break the cryptography attacks the endpoint instead. Concretely:
replace the firmware with a version that looks and behaves identically but records the
disk passphrase as the owner types it, or copies plaintext out over the network. There
are three distinct opportunities to do this, and they need different answers.

### 5.2 A backdoored image, shipped or interdicted

A device is built with hostile firmware, or a shipment is opened in transit and
reflashed.

**What answers it today.** The RP2350's BOOTSEL recovery path is pinned in hardware, not
in software. Holding the BOOTSEL button while applying power exposes a USB mass-storage
volume that accepts a firmware file by drag-and-drop, **with no cooperation from whatever
firmware is currently resident**. Software already on the device cannot disable this,
hide it, or fake it. So any recipient — not only a technically skilled one — can
overwrite whatever was shipped with an image they chose.

That converts the trust question from "do I trust whoever handed me this device" into
"do I trust the source of the image I flash", which is a materially better question,
because the second one has answers that scale: an adopting body can build the image
itself from the published GPLv3 source, using its own toolchain, on its own machines,
and never run a vendor binary at all.

**What does not answer it today.** The build is not reproducible. Two engineers
compiling the same commit do not get byte-identical binaries, because the Arduino
toolchain embeds paths and timestamps and does not pin library versions. Until that is
fixed, "compare your hash to the published hash" works only for a user who flashes the
*published* binary, not for one who builds their own. Making the build reproducible —
pinned toolchain, pinned core, pinned libraries, `-ffile-prefix-map`, no build
timestamps — is identified work, not finished work.

### 5.3 Evil-maid access to a device already in service

The device is taken from a hotel room, reflashed, and returned before the owner notices.
This is the attack the disk passphrase is most vulnerable to, because the passphrase is
typed into whatever code is running, and hostile code can log it.

**What answers it today: nothing sufficient.** This is stated plainly. The device has no
signed boot and no on-screen display of the running image's hash, so an owner cannot
detect a swapped image without external comparison.

**The designed answer, and why it takes the shape it does.** The obvious fix —
manufacturer-locked secure boot — is refused, because it forbids the property this
project treats as more important: the owner must be able to audit the source, compile
it, and flash their own build. A device the owner cannot reflash is a device whose
manufacturer must be trusted absolutely, which is the failure this whole design exists to
avoid.

The resolution is **owner-controlled secure boot**, the model Android's verified boot,
Chromebooks and Heads converged on independently. The *user* holds the signing key. On
the RP2350 that means: audit the source, build it, generate a key pair, sign the image,
burn the hash of the public key into one-time-programmable memory, and enable secure
boot. The manufacturer is then outside the trust boundary entirely.

Three rules make that design hold rather than merely sound reassuring:

1. **Any change of ownership, any secure-boot toggle, any re-enabling of the debug port
   must force a full crypto-erase.** An adversary who takes ownership of the device gets
   a blank one. The wipe is what makes tampering *visible* rather than silent — the
   owner returns to a device that has forgotten them, which is an alarm.
2. **Verify the image before executing it — entering update mode is not the boundary.**
   A flag saying "an update is authorised" is one bit, and an attacker can set it.
   Security has to rest on what the device will *execute*, so the boot code authenticates
   the image before jumping to it. Then it does not matter who armed the update.
3. **Two application slots, and never scrub the working copy until the replacement has
   been proven good.** A failed verification or a power cut mid-write leaves the previous
   image active. No brick, and a torn update heals itself.

An interim design, further along than the signed path, replaces the signature with a
checksum the *user* verifies: the bootloader hashes the image it received and displays
the hash as a word list for the user to compare against the published one. Words rather
than hexadecimal, because a human comparing a fingerprint only checks the part they
actually read, and a word list resists skipping the middle. Today's over-the-air update
already hashes the staged image with BLAKE2s and re-verifies it before applying it; what
it does not do is check a signature or bind that hash to anything the user confirmed.

### 5.4 Remote code execution — the vector a purely physical framing misses

A memory-safety defect in the network-facing parsers needs no physical access at all,
and on a microcontroller with no memory management unit and executable RAM, it yields
everything at once. This is why the small trust boundary in §6 is a security property
rather than an aesthetic preference, and why the network-facing parsers are the first
recommended audit target in §10. Enforcing execute-never on RAM through the Cortex-M33's
memory protection unit is identified, not implemented.

### 5.5 The device in a laboratory

The governing principle here is worth stating because it drives every other choice:
**the winning strategy is absence, not concealment.** A key that is hidden loses to
physical access eventually — fuses can be glitched, meshes can be drilled, live RAM can
be probed. A key that is *not present* cannot be extracted at any budget.

So the strongest measure is the least technological one: **powered off is the secure
state**, and the device has a hardware switch that cuts power to the whole board. Off
means the SRAM is cleared, means no volume key, means nothing to image. Messages queue on
the *sender's* device and are retried for 24 hours, so being off is not being
unreachable.

**A second switch physically disconnects the microphone**, and it is worth separating
what that buys from what the firmware already claims. The firmware samples the microphone
only during a call — but that is a property of code, and code is what an evil-maid
attacker replaces (§5.3). An open switch is not. With the microphone disconnected, a
device running hostile firmware cannot record the room, because there is no signal path
to record from. Both switches share one property that makes them worth more than their
cost: they are the only two controls on the device whose guarantee does not depend on the
integrity of the firmware, and they are therefore the two an owner can rely on precisely
when they can rely on nothing else.

Against a device that is powered off, a flash dump yields AEAD ciphertext and public key
derivation parameters — provided the owner has set a disk passphrase (§9). Against a
device that is powered on and unlocked, the realistic vectors are the SWD debug port,
the boot ROM's USB and UART loaders — both of which can read memory directly — and fault
injection to bypass the fuses that would have closed the first two. The countermeasures
are known and unimplemented: fuse off the debug port, fuse off **both** ROM loaders (USB
alone is not enough, the UART loader is a third way in), and cut power on enclosure
entry so that a laboratory reaching the board finds it already wiped.

One scoping result is useful for a hardware evaluator: the tamper boundary needs to
enclose **only the microcontroller die and its power path**, because that is where the
live key is. The external flash holds ciphertext and is safe even when fully extracted.

**Two residuals are stated and not solved.** Fault injection against a live, key-resident
chip is not eliminable on a general-purpose microcontroller; it is bounded only by
removing power the instant an attacker gains physical entry. And a substituted
microcontroller is beyond the reach of any firmware measure — no code of ours runs on a
part we did not ship.

### 5.6 Coercion

There is no answer to a user compelled to type their passphrase, and the design does not
pretend otherwise. What exists is narrower and honest about being narrow: a **burner
code**, a second lock-screen PIN that silently destroys the keys of contacts flagged as
sensitive, along with their entire message histories, and then unlocks normally with no
indication that two codes exist. It is a targeted panic wipe. It is not deniable
messaging and it is not general coercion resistance.

---

## 6. Why open source is a security property here

The code is published under the GPLv3. For this system that is an engineering decision
before it is a licensing one, and it shows up in three places.

**The trust boundary is deliberately small enough to read.** The UI toolkit (LVGL) was
removed from the firmware — not to save memory, but because it was the largest body of
unaudited third-party code inside the trust boundary. The user interface is now rendered
by an in-house text engine of a few thousand lines. The cryptography is a **single file
with no external library**: Curve25519 from curve25519-donna with its original copyright
intact, Poly1305 from poly1305-donna, and ChaCha20, XChaCha20-Poly1305 and BLAKE2s
transcribed from their specifications. An auditor reviewing the cryptography reviews one
file, not a dependency tree.

**The security-critical files are under a documented do-not-edit discipline.** Changes to
the handshake and cryptography files require explicit authorisation, and every exception
ever granted is recorded in the repository with its date and its rationale — three of
them, each one traceable. That is unusual, and it exists so that a reviewer can ask "what
has been changed in the crypto, and why" and get a complete answer rather than a
`git log`.

**The project publishes its own findings.** An internal line-by-line audit exists in the
repository, with severities, and with items that are still open still marked open. Some
of them are in this document, by name, in §9. A body evaluating this system starts from
the known defect list instead of rediscovering it, and can measure the project by whether
its own list is honest — which is a check no vendor claim can substitute for.

**What the GPLv3 gives an adopting body specifically.** It can build the firmware, audit
it, modify it, and maintain its own version indefinitely without the vendor's
cooperation or continued existence. It can have the code reviewed by any party it
chooses without a non-disclosure agreement. And because the licence is copyleft, no
downstream party — including the original vendor — can take the code proprietary and
ship an adopting body a black box derived from it. Auditability is not a promise that
can be withdrawn later; it is a licence term.

---

## 7. Why commodity components, not specialised security silicon

The obvious criticism of this hardware is that it uses an ordinary microcontroller with
no secure element, no hardware key store, and no hardware PIN rate limiting. That is a
deliberate decision and it is worth arguing rather than asserting.

**What a secure element would buy.** Genuinely useful things: hardware-enforced retry
limits on the PIN, so guessing costs real time; key storage the main processor cannot
read; a tamper-resistant boundary designed by people who do that for a living.

**What it would cost.** The audit dead-ends at the chip. Every claim about the device's
security would then rest on a document from a vendor about silicon nobody outside that
vendor can inspect, with a trust root — and often an attestation identity — belonging to
a foreign company under a foreign jurisdiction. For a system whose central proposition is
"you do not have to trust any particular actor", introducing exactly one actor who must
be trusted absolutely, and who cannot be audited even in principle, is a contradiction at
the foundation rather than a trade-off at the margin.

**The same argument applies to the fuses on the chip we already have.** The RP2350 can
one-time-program its own secure-boot key hash, and doing so is irreversible: it destroys
the BOOTSEL recovery path that §5.2 identifies as the owner's strongest defence against
a backdoored image. Version 1 keeps the recovery path and does not fuse.

**So version 1 keeps the entire trust path in auditable software plus a high-entropy
secret held by the user**, and pays the usability cost openly: a boot passphrase, and no
hardware rate limiting behind it. The standing rule for anything added later is a single
sentence: **no black box is ever the sole gate.** A secure element used defensively —
where the worst case is the security this baseline already provides — is acceptable. An
open one, of the TROPIC01 or OpenTitan class, is better. Neither may become the only
thing standing between an attacker and the data.

**For procurement, three consequences follow from commodity parts:**

- **Second-sourceable, and assemblable domestically.** The bill of materials is a
  general-purpose microcontroller module, a display, a keyboard matrix, a microphone and
  a speaker. There is no part on it that is single-sourced from one foreign vendor, no
  part under export control as a cryptographic module, and no part whose supply can be
  used as leverage. The board can be manufactured and assembled in-country.
- **No foreign trust root in the device.** There is no attestation certificate chain
  rooted at a foreign vendor, no provisioning service to contact, and no key the device
  was born with that anyone outside the owner's organisation knows.
- **The infrastructure is ordinary software.** The relay and the directory server are
  small C programs with a SQLite database, in the same repository, under the same
  licence. An adopting body can run its own relays and its own directory on its own
  hardware, in its own facilities. That converts §4.3 and §4.4 — the hostile-operator
  threats — from a residual risk into an internal administrative matter.

---

## 8. Trusting no particular actor

The claim in the title of this section is strong, so here is each actor in turn, with
what it can see and what it cannot do even if entirely hostile.

| Actor | What it sees | What it cannot do, even fully hostile |
|---|---|---|
| **Manufacturer / vendor** | Nothing after the device ships. It generates no key for the device — the identity key pair is created on the device. | Cannot read any conversation; cannot recover an identity key; cannot prevent the owner reflashing the device with their own build (§5.2). Residual: a backdoor in a *shipped* image that the owner never replaces (§9). |
| **Relay operator** | Encrypted envelopes; source and destination addresses; timing; an opaque session identifier. | Cannot read content. Holds no conversation key. Never receives any peer's public key. Cannot attribute an origination to a registered identity (§4.5). |
| **Directory operator** | The registered user base; which relay each user homes onto; that *someone* asked about a given userid. | Cannot read content — it is not on the conversation path. Cannot learn who asked about whom (§4.6). Cannot impersonate an existing contact, only black-hole it (§4.4). Holds no message content to surrender under compulsion. |
| **Both together, colluding** | The union of the two rows above. | Still no content. Still no `(querier → queried)` graph: the relay holds ciphertext it cannot read, and the server holds a userid without a querier. Correlation is possible at the IP level (§9). |
| **Network carrier / passive collector** | Encrypted UDP between the device and a relay; packet sizes and timing. | Cannot read content, now or retrospectively (§4.1). Can recognise that a call is in progress from its 25-frames-per-second cadence (§9). |
| **The peer on the other end** | Everything you send them — necessarily. | Cannot reach your other contacts' keys. Each peer relationship is independent, with its own record and its own storage key. |
| **The adopting body, self-hosting** | Whatever its own relay and directory see — the two rows above. | Cannot read its users' conversation content. This is worth stating explicitly: running the infrastructure does **not** confer access to the traffic. |

The two structural facts underneath the table: the server holds no conversation content,
so there is nothing to compel it to produce; and the relay holds no key, so compelling it
produces ciphertext.

---

## 9. Status register and residual risks

Every property, with its actual state in the code this brief was written against.
Verified on device means exercised on real RP2350 hardware, not only in host tests.

### 9.1 Implemented and verified

| Property | State |
|---|---|
| End-to-end encryption of voice and text between peers | Shipped, verified on device |
| Forward secrecy of completed sessions | Shipped |
| Data-frame replay protection (32-bit window, post-authentication) | Shipped |
| Contacts-only admission; stranger handshakes refused; knock recording | Shipped, verified on device |
| Media gate (voice, push-to-talk) contacts-only, refused before slot allocation | Shipped |
| Anonymous contact lookup; server sees no querier, relay sees no query | Shipped, verified on device |
| Lookup cover traffic, 15–20 minutes, resolved and unresolved alike | Shipped |
| Identity socket separated from origination socket | Shipped |
| Encryption at rest: settings, contacts, message threads, private key | Shipped, verified on device across a real power cycle |
| Crypto-erase of a contact and its whole thread as one operation | Shipped, verified on device |
| Relay endpoint pinning and cookie proof-of-work perimeter | Shipped |
| Activation records carry no link to the user who consumed them | Shipped |
| Burner code — selective panic wipe | Built; UI not yet verified on device |
| Over-the-air update: staged, BLAKE2s-hashed, re-verified before applying | Shipped, verified on device |

### 9.2 Built but not armed by default — the most important row in this document

**The at-rest trust root is opt-in.** Out of the box, the volume key is wrapped under a
**hardcoded default passphrase that is a constant in this open-source repository**, and
the device unlocks itself at boot with it. The 8-word disk-key wizard exists and has been
exercised on hardware; setting a phrase re-wraps the same volume key, so no data is
re-encrypted and the change is instant. But until the user runs it, the encryption at
rest provides **no secrecy against an informed attacker with a flash dump**, because that
attacker can read the repository and derive the key.

The mechanism is complete and the arming is a user action. An adopting body's deployment
policy should treat setting the disk key as a provisioning step, not as a user
preference. A future build should refuse to complete first-boot setup without one.

### 9.3 Open findings, recorded and unfixed

| Finding | Effect | Severity in context |
|---|---|---|
| The handshake initiation timestamp is decrypted but never validated | A captured initiation replays into a session reset | Denial of service only; no confidentiality impact |
| Data-frame header fields are outside the authenticated associated data | Routing fields are integrity-protected only indirectly | A deviation from upstream; no content impact |
| The lookup response reuses one key and nonce across a replayed query | A replayed lookup re-encrypts under an identical key and nonce, permitting recovery of the one-time authenticator key and forgery of a lookup answer | Bounded: a forged answer black-holes a contact, and cannot impersonate one, because the subsequent handshake authenticates against the stored key (§4.4) |
| The cookie proof-of-work layer can be disabled by a single call | All three binaries call it; the relay enforces the challenge itself, so the perimeter holds — but the call sites deserve an auditor's eye | Configuration risk |

### 9.4 Designed, not built

- **Per-contact preshared keys — the post-quantum hybrid (§3.3).** The handshake stage
  is implemented and the contact record reserves the 32 bytes; nothing populates them, so
  the key mixed in is all-zero today. Wiring this, plus a way for two users to establish a
  preshared key out of band, is the highest-value item on this list: it is what makes a
  recorded session worthless to an adversary who intends to wait for a quantum computer.
- **Signed boot, in any form.** Neither owner-controlled secure boot (§5.3) nor the
  interim user-verified word-checksum bootloader is implemented.
- **Reproducible builds.** Required before "build it yourself and compare hashes" is
  meaningful for anyone but the publisher.
- **On-device display of the running image's hash**, so an owner can check the firmware
  without external tools.
- **Out-of-band key verification.** There is no safety-number or QR comparison flow. A
  first contact resolution trusts the directory's answer; direct entry of a full 64-hex
  key bypasses the directory entirely and is the current answer for high-assurance use.
- **Idle eviction of the volume key**, which would bound the powered-on theft window. The
  keystore has the locked-session state and the PIN machinery for it; the timer is not
  wired.
- **Execute-never enforcement on RAM** via the memory protection unit (§5.4).
- **Fusing off the debug port and both boot-ROM loaders** on production units (§5.5).
- **A voice codec.** Voice is transmitted as raw 16-bit linear PCM at 8 kHz, roughly
  140 kbit/s per direction inside the encrypted channel. A codec is planned; the framing
  already matches GSM 06.10.
- **Group messaging.** In active design. The storage layer models a group as a file with
  its own key, but the group protocol is not complete and is not part of this evaluation.

### 9.5 Accepted residuals — not defects, and not going away

- **The source-IP floor.** A device has one public address. A party watching both a relay
  and that address correlates at the IP level. Only an anonymity-network overlay would
  close this, and Xyfr does not attempt one.
- **Voice cadence.** A 25-frames-per-second stream is a recognisable fingerprint of a
  call in progress, through the encryption. Padding is to a 32-byte boundary and is not
  traffic-shaping.
- **Cover traffic beyond the lookup pump.** An idle device sends only NAT keepalives.
- **Loss of the device is loss of the history.** There is no cloud backup, by design.
  Encrypted local backup and restore exist; their privacy is exactly as good as the disk
  key that was set.
- **A substituted microcontroller, and laboratory fault injection on a powered-on
  device** (§5.5).

---

## 10. How to evaluate this system

**Build it.** The host side builds with `make -C secserver`. The firmware builds with
`tools/build.sh`, a wrapper around `arduino-cli` that compiles, flashes and captures the
serial log in one command. The host `phone` binary plus a local server and relay make a
complete two-party test system on a single machine, running **the same portable C core
the device runs** — not a re-implementation.

**Suggested order of audit, by value per hour:**

1. **The cryptography and the handshake** — roughly 2,800 lines across two files, read
   against the Noise IKpsk2 and WireGuard specifications, concentrating on the deviations
   this document lists in §4.2 and §9.3.
2. **The two constructions that are not transcribed from a standard**: the at-rest key
   derivation (PBKDF2 structure with keyed BLAKE2s as the pseudo-random function rather
   than HMAC) and the anonymous lookup pair, including the replay defect named in §9.3.
   These are the only novel cryptography in an otherwise standards-derived codebase, and
   they deserve the most external scrutiny.
3. **The network-facing parsers**, for memory safety — this is the remote code execution
   vector of §5.4 and the highest-consequence class of defect in the system.
4. **The at-rest layer**: the key store, the store integration, and the filesystem's
   nonce discipline and crypto-erase semantics.
5. **The admission path**: `policy.c`, the knock flow, and the handshake demultiplexer.
6. **The relay perimeter**: the route pool, endpoint pinning and the cookie challenge.

**Test suites** exist for the storage stack, the key store, the settings block, the
filesystem and the stream, all valgrind-clean, plus two-phase on-device acceptance tests
that survive a real power cycle — which is the only way to prove that an in-place flash
flag clear and a torn write behave as designed when the supply actually goes away.

**A closing note on how to read the project's own documents.** Some of the design
documents in this repository have drifted ahead of or behind the code — this brief
corrects two such cases by name, in §4.5 and §9.4. The code is the authority. Where an
evaluator finds a document and a source file disagreeing, the source file is what ships.

---

*Prepared from the source as it stands. Every mechanism described here was
read in the code during preparation. Items marked designed-not-built were confirmed
absent, not assumed absent.*
