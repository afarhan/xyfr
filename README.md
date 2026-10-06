# xyfr

xyfr (pronounced "cifer") is a handheld for encrypted voice and text. It has no
operating system: the firmware in this repository is everything that runs on the
microcontroller. This repository also holds the relay and the directory server
the handhelds talk to.

- **Hardware:** Raspberry Pi Pico 2 W (RP2350), one Wi-Fi radio, a keyboard, a
  microphone and speaker, and a Sharp LS032 or ILI9488 display.
- **Transport:** a WireGuard-derived Noise IKpsk2 handshake over UDP, with
  Curve25519, ChaCha20-Poly1305 and BLAKE2s.
- **Storage:** an encrypted layout written directly to raw NOR flash, with one
  key per contact so that deleting a contact destroys its messages.

## What is here

| Path | Contents |
| --- | --- |
| `xyfr.ino` and the files beside it | The firmware and the portable C core |
| `secserver/` | The directory server, the relay, and a build of the core for Linux |
| `tools/` | The build script and the code generators |
| `THREAT_MODEL.md` | Adversaries, defences, and the open defects (section 12) |
| `STORAGE_SECURITY.md` | The design of encryption at rest |
| `docs/EVALUATION_BRIEF.md` | A technical brief for evaluators |

Documents for the hardware, the architecture, the coding conventions and the
wire and storage formats are being prepared and will be added under `docs/`.
The threat model already refers to some of them by their future names.

## Building the firmware

The firmware builds with `arduino-cli`, the arduino-pico core and the Adafruit
GFX library. The sketch folder must be named `xyfr`, which is what a plain clone
gives you.

```sh
tools/build.sh setup    # once: installs arduino-cli, the core and the library
tools/build.sh build    # compiles; images land in firmware/
tools/build.sh upload   # compiles and flashes over USB
```

## Building the servers

The servers need a C compiler, `make` and the SQLite development headers.

```sh
cd secserver
make server relay keygen
cp server.conf.example server.conf    # then fill in; ./keygen makes keys
cp relay.conf.example relay.conf
```

Neither program has built-in keys or addresses. Each refuses to start until its
configuration file supplies them.

## Status

This is working code under active development, and it has known defects. They
are recorded in `THREAT_MODEL.md`. Read that before relying on it.

## Licence

GNU General Public License, version 3. See `LICENSE`. A few files come from
other projects and keep their own notices in their headers.
