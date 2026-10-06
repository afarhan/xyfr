#!/usr/bin/env python3
#
# monread.py — DTR-raising serial reader/writer, a drop-in for `arduino-cli
# monitor` in tools/build.sh.
#
# WHY THIS EXISTS: after a reflash the Pico CDC re-enumerates with DTR
# deasserted. arduino-pico's Serial treats the port as "not connected" until
# the host asserts DTR (tud_cdc_connected() follows DTR), and our non-blocking
# Debug object drops every line while disconnected. `arduino-cli monitor` and
# plain `cat` do NOT raise DTR, so the monitor shows nothing until a physical
# unplug-replug. This reader asserts DTR on open, so output flows immediately
# after a flash with no replug. It also uses per-read timeouts so it can never
# wedge in uninterruptible D-state the way `cat` does on this CDC.
#
# Behaviour mirrors what build.sh relied on from arduino-cli monitor:
#   - serial -> stdout for --secs seconds (then exit)
#   - stdin  -> serial, forwarded raw (so `printf 'cmd\n' | monread ...` works)
#
# Usage: monread.py --port /dev/ttyACM0 --baud 115200 --secs 30
#
import argparse, sys, time, threading

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", required=True)
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--secs", type=float, default=30.0)
    args = ap.parse_args()

    try:
        import serial  # pyserial
    except ImportError:
        sys.stderr.write("monread: pyserial not installed (pip install pyserial)\n")
        return 2

    try:
        s = serial.Serial(args.port, args.baud, timeout=0.2)
    except Exception as e:
        sys.stderr.write("monread: open %s failed: %s\n" % (args.port, e))
        return 1

    # The whole point: assert DTR (and RTS) so the firmware sees a terminal.
    try:
        s.dtr = True
        s.rts = True
    except Exception:
        pass
    time.sleep(0.1)

    out = sys.stdout.buffer

    # stdin -> serial, as a daemon so it never blocks process exit. Forwards
    # raw bytes (the producers already include their own newlines).
    def pump_stdin():
        try:
            stdin = sys.stdin.buffer
            while True:
                b = stdin.read(1)
                if not b:
                    break
                try:
                    s.write(b)
                except Exception:
                    break
        except Exception:
            pass
    threading.Thread(target=pump_stdin, daemon=True).start()

    # serial -> stdout for the capture window.
    deadline = time.time() + args.secs
    while time.time() < deadline:
        try:
            d = s.read(256)   # per-read timeout (0.2s) -> never hangs
        except Exception:
            break
        if d:
            out.write(d)
            out.flush()
    try:
        s.close()
    except Exception:
        pass
    return 0

if __name__ == "__main__":
    sys.exit(main())
