#!/usr/bin/env python3
# xyfr_upload.py — push a firmware image to a Xyfr device over its web upload API.
#
# The device, after a disk-key-gated "Firmware Update" on its screen, shows a
# 6-digit access code and stands up a web server (poll-mode, like Restore). This
# tool does a single HTTP POST of the raw .bin to that server; the device stages
# it, checksums it, and (once confirmed) applies it on the next reboot.
#
#   ./xyfr_upload.py <device-ip> <firmware.bin> [--code NNNNNN]
#
# In Developer Mode the device skips the access-code check, so --code is optional
# there. For production it is required (shown on the device screen).
#
# Doubles as the Arduino-IDE upload tool: the IDE hands us
# {build.path}/{build.project_name}.bin as the last arg (see platform.local.txt).
#
# Stdlib only (http.client, hashlib) — no pip installs, so it runs anywhere the
# Arduino toolchain's python does.

import sys
import os
import hashlib
import http.client
import argparse

OTA_PATH = "/firmware"           # POST endpoint on the device web server
OTA_PORT = 80
TIMEOUT_S = 120                  # a ~1 MB image over poll-mode WiFi is not instant


def main():
    ap = argparse.ArgumentParser(description="Upload firmware to a Xyfr device.")
    ap.add_argument("ip", help="device IP address (shown on the update screen)")
    ap.add_argument("binary", help="path to the firmware .bin")
    ap.add_argument("--code", default="", help="6-digit access code (production; skipped in Developer Mode)")
    ap.add_argument("--apply", action="store_true", help="apply immediately after a verified upload (device reboots into the new image)")
    ap.add_argument("--port", type=int, default=OTA_PORT)
    args = ap.parse_args()

    if not os.path.isfile(args.binary):
        sys.exit("error: no such file: %s" % args.binary)

    with open(args.binary, "rb") as f:
        image = f.read()

    if len(image) == 0:
        sys.exit("error: %s is empty" % args.binary)

    # BLAKE2s-256 over the image so the device can independently verify that what it
    # staged matches what we sent. BLAKE2s (not SHA-256) because that is the hash the
    # device's crypto.c already implements — it recomputes it over the freshly-staged
    # flash bytes and compares.
    digest = hashlib.blake2s(image, digest_size=32).hexdigest()

    path = OTA_PATH
    q = []
    if args.code:
        q.append("code=%s" % args.code)
    q.append("b2s=%s" % digest)
    if args.apply:
        q.append("apply=1")
    path += "?" + "&".join(q)

    print("uploading %s (%d bytes, blake2s=%s) to %s:%d%s" %
          (os.path.basename(args.binary), len(image), digest, args.ip, args.port, OTA_PATH))

    conn = http.client.HTTPConnection(args.ip, args.port, timeout=TIMEOUT_S)
    try:
        headers = {
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(image)),
        }
        conn.request("POST", path, body=image, headers=headers)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", "replace").strip()
        print("device: %d %s — %s" % (resp.status, resp.reason, body))
        if resp.status != 200:
            sys.exit(1)
    except OSError as e:
        sys.exit("error: could not reach device %s:%d — %s" % (args.ip, args.port, e))
    finally:
        conn.close()

    print("done. If the device confirms and reboots, the new firmware is live.")


if __name__ == "__main__":
    main()
