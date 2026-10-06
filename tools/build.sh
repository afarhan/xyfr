#!/usr/bin/env bash
# Automate compile + flash + Serial-monitor for the Pico 2W firmware.
# Lets Claude (and humans) close the loop on on-device tests without
# leaving the terminal.
#
# Usage:
#   tools/build.sh check                    Probe env: arduino-cli, port, libs,
#                                           and text-engine copies vs upstream
#   tools/build.sh engine                   Only the text-engine sync check
#                                           (non-zero exit if a copy has drifted)
#   tools/build.sh setup                    Install arduino-cli + core + libs (one-time)
#   tools/build.sh build                    Compile only
#   tools/build.sh upload                   Compile + flash via $PORT
#   tools/build.sh monitor [SECS]           Capture serial for SECS sec (default 30)
#   tools/build.sh send "<line>" [SECS]     Write <line>+newline to the device and
#                                           capture serial for SECS sec (default 10).
#                                           Use to drive Serial commands like
#                                             tools/build.sh send "call 12345678" 20
#   tools/build.sh backup FILE              Send `dump` to the device, capture the
#                                           plain-text backup into FILE. Run BEFORE
#                                           every flash that might wipe user data.
#   tools/build.sh restore FILE             Replay a backup: send each `set` line
#                                           plus a final `save`. Plain text in,
#                                           hand-editable on disk.
#   tools/build.sh test [SECS]              upload + monitor
#   tools/build.sh dist [OUTDIR]            Build BOTH panels into named UF2s
#                                           (OUTDIR/sharp/*, OUTDIR/ili9488/*;
#                                           default OUTDIR = <sketch>/dist)
#
# Env overrides:
#   FQBN=rp2040:rp2040:rpipico2w   (default for RP2350 Pico 2W; switch to
#                                   rpipicow / rpipico for RP2040 boards)
#   PANEL=sharp | ili9488          Pick the display at compile time WITHOUT
#                                   editing display_select.h (passes
#                                   -DDISPLAY_ILI9488=0/1). Unset = source
#                                   default (Sharp). Applies to build/upload/test.
#   PORT=/dev/ttyACM0
#   BAUD=115200
#   LOG_FILE=/tmp/xyfr-serial.log    (always tee'd here on monitor/send/test)
#   ENGINE_DIR=~/Documents/radiocloud/text_engine
#                                  Standalone text-engine repo the sketch's
#                                  engine files are copied FROM. Absent = the
#                                  sync check is skipped, not failed.

set -euo pipefail

# ---------- config ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKETCH_DIR="$(dirname "$SCRIPT_DIR")"
# NOTE on the FQBN options: do NOT drop any of them. The defaults
# arduino-cli would fall back to are NOT the same as what the Arduino
# IDE has been using for this sketch — most critically `flash=4194304_0`
# (4MB sketch, no filesystem) would let the new UF2 claim the LittleFS
# region (0x10200000–0x103FFFFF) and wipe every contact under /c/. The
# value below mirrors what the IDE's own build cache records (verified
# from .cache/arduino/.../build.options.json on 2026-05-16):
#   flash=4194304_2097152   2MB sketch + 2MB LittleFS  ← preserves /c/
#   freq=150 arch=arm       150 MHz, ARM core (vs. RP2350's RISC-V)
#   opt=Small               size-optimised build
#   usbstack=picosdk        Pico SDK USB CDC (vs. TinyUSB)
# Override the entire string with FQBN=... if you genuinely want a
# different partition layout — and back up the device first.
FQBN="${FQBN:-rp2040:rp2040:rpipico2w:flash=4194304_2097152,freq=150,arch=arm,opt=Small,profile=Disabled,rtti=Disabled,stackprotect=Disabled,exceptions=Disabled,dbgport=Disabled,dbglvl=None,wificountry=worldwide,usbstack=picosdk,ipbtstack=ipv4only,uploadmethod=default}"
PORT="${PORT:-/dev/ttyACM0}"
BAUD="${BAUD:-115200}"
LOG_FILE="${LOG_FILE:-/tmp/xyfr-serial.log}"

# Locate arduino-cli. Falls back to the install path setup uses.
if command -v arduino-cli >/dev/null 2>&1; then
	ACLI="$(command -v arduino-cli)"
else
	ACLI="$HOME/.local/bin/arduino-cli"
fi

# If the Arduino IDE is already installed it has its own arduino-cli.yaml
# with the user's sketchbook (and therefore library) path. Reuse it so we
# inherit the cores + libs the IDE has already fetched, instead of
# re-downloading hundreds of MB into a parallel default-location config.
IDE_CONFIG="$HOME/.arduinoIDE/arduino-cli.yaml"
if [ -f "$IDE_CONFIG" ]; then
	ACLI_ARGS=(--config-file "$IDE_CONFIG")
else
	ACLI_ARGS=()
fi

# Required libraries (PWMAudio and ADCInput ship with the rp2040 core). The
# ILI9488 build needs nothing beyond the core: the UI renders through the
# in-house text engine (text_engine.cpp + ili9488.cpp + tfont tables).
# Adafruit GFX is the Sharp path's (sharp_ls032.*) only; the name is
# arduino-cli's, and it pulls Adafruit BusIO in itself.
LIBS=("Adafruit GFX Library")

PICO_INDEX_URL="https://github.com/earlephilhower/arduino-pico/releases/download/global/package_rp2040_index.json"

# ---------- helpers ----------
log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

require_acli() {
	if ! [ -x "$ACLI" ]; then
		log "arduino-cli not found at $ACLI. Run: $0 setup"
		exit 1
	fi
}

wait_for_port() {
	local deadline=$((SECONDS + 30))
	while [ $SECONDS -lt $deadline ]; do
		[ -e "$PORT" ] && return 0
		sleep 0.5
	done
	log "ERROR: $PORT did not reappear within 30s"
	return 1
}

# Serial reader/writer that ASSERTS DTR — replaces `arduino-cli monitor`, which
# (like `cat`) leaves DTR deasserted, so after a reflash the CDC re-enumerates
# "not connected" and our non-blocking Debug drops all output until a physical
# unplug-replug. monread.py raises DTR on open (output flows immediately after a
# flash) and uses per-read timeouts (no D-state hangs). Reads stdin->serial so
# `printf 'cmd\n' | monread <secs>` still injects commands. Falls back to
# arduino-cli monitor if python3/pyserial is unavailable.
MONREAD="$SCRIPT_DIR/monread.py"
monread() {
	local secs="${1:-30}"
	if command -v python3 >/dev/null 2>&1 && python3 -c 'import serial' >/dev/null 2>&1; then
		python3 "$MONREAD" --port "$PORT" --baud "$BAUD" --secs "$secs"
	else
		log "monread: python3/pyserial missing — falling back to arduino-cli monitor (DTR not asserted; reflash may need a replug)"
		( printf ''; sleep "$secs" ) \
			| timeout --foreground "${secs}s" \
				"$ACLI" "${ACLI_ARGS[@]}" monitor -p "$PORT" -c "baudrate=$BAUD" --quiet 2>/dev/null \
			|| true
	fi
}

# ---------- subcommands ----------
do_check() {
	echo "Sketch dir : $SKETCH_DIR"
	echo "FQBN       : $FQBN"
	echo "Port       : $PORT $( [ -e "$PORT" ] && echo '(present)' || echo '(MISSING)' )"
	echo "Baud       : $BAUD"
	echo "Log file   : $LOG_FILE"
	echo "arduino-cli: ${ACLI}$( [ -x "$ACLI" ] && echo "  → $($ACLI version 2>/dev/null | head -1)" || echo '  (NOT INSTALLED — run: '"$0"' setup)' )"
	if [ ${#ACLI_ARGS[@]} -gt 0 ]; then
		echo "Config file: $IDE_CONFIG  (reusing Arduino IDE config)"
	else
		echo "Config file: default (~/.arduino15/arduino-cli.yaml)"
	fi
	if [ -x "$ACLI" ]; then
		echo "User dir   : $("$ACLI" "${ACLI_ARGS[@]}" config get directories.user 2>/dev/null)"
		echo
		echo "Cores installed:"
		"$ACLI" "${ACLI_ARGS[@]}" core list 2>/dev/null | grep -E "^(rp2040|ID)" || echo "  (rp2040 core not installed)"
		echo
		echo "Required libs:"
		local installed
		installed="$("$ACLI" "${ACLI_ARGS[@]}" lib list 2>/dev/null || true)"
		for lib in "${LIBS[@]}"; do
			if echo "$installed" | grep -qi "^$lib "; then
				echo "  $lib: $(echo "$installed" | grep -i "^$lib " | head -1 | sed "s/^$lib *//" | awk '{print $1}')"
			else
				echo "  $lib: MISSING"
			fi
		done
	fi
	echo
	do_engine_check || true
}

# The text engine's sources are COPIES. They are developed and regression-tested
# in a standalone sketch (its own git repo, remote radio@xyfr.io:text-engine.git)
# and copied here verbatim; the rule is "fix bugs THERE and re-copy", because a
# fork is how a port rots. A rule kept only in a comment is
# enforced by whoever last remembers it. This makes drift loud.
#
# A missing upstream is NOT a failure: a machine that only builds the firmware
# has no reason to have the engine repo checked out. Only a file that exists in
# both and differs is an error.
ENGINE_DIR="${ENGINE_DIR:-$HOME/Documents/radiocloud/text_engine}"
ENGINE_FILES=(ili9488.cpp ili9488.h text_engine.cpp text_engine.h
              text_edit.cpp text_edit.h tfont.h mont14.c mont10.c tamzen_tfont.c)

do_engine_check() {
	echo "Text-engine sync ($ENGINE_DIR):"
	if [ ! -d "$ENGINE_DIR" ]; then
		echo "  upstream not present — skipped (set ENGINE_DIR to check)"
		return 0
	fi
	local drift=0 missing=0 f up
	for f in "${ENGINE_FILES[@]}"; do
		up="$ENGINE_DIR/$f"
		if [ ! -f "$up" ]; then
			echo "  $f: not in upstream"
			missing=$((missing + 1))
		elif ! diff -q "$SKETCH_DIR/$f" "$up" >/dev/null 2>&1; then
			echo "  $f: DRIFTED ($(diff "$SKETCH_DIR/$f" "$up" | grep -c '^[<>]') changed lines)"
			drift=$((drift + 1))
		fi
	done
	if [ "$drift" -eq 0 ]; then
		echo "  ${#ENGINE_FILES[@]} files identical to upstream ✓$( [ "$missing" -gt 0 ] && echo " ($missing not upstream)" )"
		return 0
	fi
	echo
	echo "  $drift file(s) differ. The sketch copies are NOT the source of truth:"
	echo "  fix it in $ENGINE_DIR, run its harness, then copy back here."
	echo "  To see a drift:  diff $SKETCH_DIR/<file> $ENGINE_DIR/<file>"
	return 1
}

do_setup() {
	# arduino-cli binary.
	if ! [ -x "$ACLI" ]; then
		log "Installing arduino-cli to ~/.local/bin"
		mkdir -p "$HOME/.local/bin"
		curl -fsSL https://raw.githubusercontent.com/arduino/arduino-cli/master/install.sh \
			| BINDIR="$HOME/.local/bin" sh
	else
		log "arduino-cli already at $ACLI ($($ACLI version 2>/dev/null | head -1))"
	fi

	# If the Arduino IDE config is present we use it directly (no extra
	# arduino-cli config needed). Otherwise initialise a default config
	# and add the pico index URL.
	if [ ${#ACLI_ARGS[@]} -eq 0 ]; then
		"$ACLI" config init 2>/dev/null || true
		"$ACLI" config add board_manager.additional_urls "$PICO_INDEX_URL" 2>/dev/null || true
	else
		log "Reusing Arduino IDE config at $IDE_CONFIG (skipping config init)"
	fi

	# Core: skip if already installed. The Arduino IDE installs into the
	# same packages directory arduino-cli reads, so if the user built via
	# the IDE the core is already present and re-downloading would just
	# overwrite their working version with a newer one (likely fine, but
	# unnecessary and slow — 100+ MB).
	if "$ACLI" "${ACLI_ARGS[@]}" core list 2>/dev/null | grep -q '^rp2040:rp2040'; then
		log "rp2040 core already installed; skipping core install"
	else
		"$ACLI" "${ACLI_ARGS[@]}" core update-index
		"$ACLI" "${ACLI_ARGS[@]}" core install rp2040:rp2040
	fi

	# Libraries: same logic — skip what's already there.
	local installed
	installed="$("$ACLI" "${ACLI_ARGS[@]}" lib list 2>/dev/null || true)"
	local needed=()
	for lib in "${LIBS[@]}"; do
		if echo "$installed" | grep -qi "^$lib "; then
			log "Library $lib already installed; skipping"
		else
			needed+=("$lib")
		fi
	done
	if [ ${#needed[@]} -gt 0 ]; then
		"$ACLI" "${ACLI_ARGS[@]}" lib update-index
		for lib in "${needed[@]}"; do
			"$ACLI" "${ACLI_ARGS[@]}" lib install "$lib"
		done
	fi

	log "Setup complete. Try: $0 check && $0 build"
}

# Resolve the optional PANEL env var to a -D flag. Prints nothing when PANEL is
# unset (so the compile uses display_select.h's own default). Exits non-zero on
# an unrecognised value. NOTE: the env var is PANEL, not DISPLAY — DISPLAY is
# X11's and is always set on a Linux desktop.
display_flag() {
	case "${PANEL:-}" in
		"")                        return 0 ;;                       # no override
		sharp|Sharp|ls032|0)       printf -- '-DDISPLAY_ILI9488=0' ;;
		ili9488|ILI9488|ili|tft|1) printf -- '-DDISPLAY_ILI9488=1' ;;
		*) log "ERROR: unknown PANEL='$PANEL' (use: sharp | ili9488)"; return 1 ;;
	esac
}

# Compile. Extra args (e.g. --output-dir DIR) are forwarded to arduino-cli.
do_build() {
	require_acli
	local flag build_args=()
	flag="$(display_flag)" || return 1
	if [ -n "$flag" ]; then
		# Pass the panel -D via compiler.{cpp,c}.extra_flags (empty by default,
		# additive), NOT build.extra_flags. The rpipico2w board sets
		# build.extra_flags=-DPICO_CYW43_SUPPORTED=1 -DCYW43_PIN_WL_DYNAMIC=1 (the
		# CYW43/WiFi enable flags); a --build-property build.extra_flags=... REPLACES
		# that, silently dropping WiFi (WiFi.status() -> 255 WL_NO_SHIELD, scan sees
		# 0 APs). compiler.{cpp,c}.extra_flags reach every recipe alongside it and
		# no rpipico2w menu uses them, so this adds the define without clobbering.
		build_args+=(--build-property "compiler.cpp.extra_flags=$flag"
		             --build-property "compiler.c.extra_flags=$flag")
		log "Panel override: $flag (via compiler.{cpp,c}.extra_flags)"
	fi
	# Drop the raw .bin — the image OUR uploader takes (tools/xyfr_upload.py POSTs it
	# to the device's /firmware endpoint; the .uf2 is only arduino-cli's USB path) —
	# into the sketch folder on every build, so an OTA push never needs a dig through
	# arduino-cli's cache. Skipped when the caller supplies its own --output-dir
	# (do_dist does).
	local a wants_outdir=0
	for a in "$@"; do
		[ "$a" = "--output-dir" ] && wants_outdir=1
	done
	if [ "$wants_outdir" = 1 ]; then
		"$ACLI" "${ACLI_ARGS[@]}" compile --fqbn "$FQBN" --warnings default \
			"${build_args[@]}" "$@" "$SKETCH_DIR"
		return
	fi

	local outtmp rc
	outtmp="$(mktemp -d)"
	"$ACLI" "${ACLI_ARGS[@]}" compile --fqbn "$FQBN" --warnings default \
		"${build_args[@]}" --output-dir "$outtmp" "$@" "$SKETCH_DIR"
	rc=$?
	if [ "$rc" -eq 0 ]; then
		# Both images go in firmware/ — the .bin OUR uploader takes
		# (tools/xyfr_upload.py POSTs it to the device's /firmware endpoint) and
		# the .uf2 for USB/BOOTSEL. Kept out of the sketch root so a stale image
		# is not left where it gets drag-flashed by mistake, which once put an old
		# firmware generation on a device (a day lost to "messages show null" that
		# was really a pre-header-change .uf2). Both are refreshed every build so
		# they never drift from the source.
		local fwdir="$SKETCH_DIR/firmware"
		mkdir -p "$fwdir"
		local img
		img="$(ls "$outtmp"/*.ino.bin 2>/dev/null | head -1)"
		if [ -n "$img" ]; then
			cp -f "$img" "$fwdir/$(basename "$img")"
			log "OTA image → $fwdir/$(basename "$img")  (panel: ${PANEL:-source default})"
		else
			log "WARNING: build produced no .bin to copy"
		fi
		local uf2
		uf2="$(ls "$outtmp"/*.ino.uf2 2>/dev/null | head -1)"
		if [ -n "$uf2" ]; then
			cp -f "$uf2" "$fwdir/$(basename "$uf2")"
			log "UF2 image → $fwdir/$(basename "$uf2")  (panel: ${PANEL:-source default})"
		else
			log "WARNING: build produced no .uf2 to copy"
		fi
	fi
	rm -rf "$outtmp"
	return "$rc"
}

# Build both panels into OUTDIR/{sharp,ili9488}.
do_dist() {
	require_acli
	local outdir="${1:-$SKETCH_DIR/dist}"
	log "dist: building Sharp → $outdir/sharp"
	PANEL=sharp do_build --output-dir "$outdir/sharp"
	log "dist: building ILI9488 → $outdir/ili9488"
	PANEL=ili9488 do_build --output-dir "$outdir/ili9488"
	log "dist: done — UF2s under $outdir/{sharp,ili9488}"
}

do_upload() {
	require_acli
	do_build
	# The UF2 writes the SKETCH region only. FQBN reserves 2 MB of the 4 MB
	# for the store, and identity, Wi-Fi APs, keystore and message threads all
	# survive a reflash — device-verified 2026-08-24 on two units, and what
	# xyfr.ino:1153 relies on to offer `wipe confirm` as the escape
	# hatch for a device stuck on the disk-key screen.
	#
	# To erase at rest you have to ask: `wipe confirm` over serial (whole
	# store) or `fswipe` (messages and contacts only). `$0 backup <file>`
	# takes a copy first; it is never auto-written, holding private material
	# that leaves the device only when the user says so.
	"$ACLI" "${ACLI_ARGS[@]}" upload --fqbn "$FQBN" -p "$PORT" "$SKETCH_DIR"
	wait_for_port
	# Brief grace for the CDC endpoint to settle after the reset.
	sleep 1
}

do_monitor() {
	require_acli
	local secs="${1:-30}"
	wait_for_port
	log "Capturing serial for ${secs}s (tee $LOG_FILE)"
	# monread asserts DTR and self-bounds to ${secs}s; tee to the log.
	monread "$secs" | tee "$LOG_FILE"
}

do_send() {
	require_acli
	local message="$1"
	local secs="${2:-10}"
	if [ -z "$message" ]; then
		log "send: empty message"
		return 1
	fi
	wait_for_port
	log "Send: [$message]; capture for ${secs}s (tee $LOG_FILE)"
	# monread keeps the read window open for ${secs}s regardless of stdin EOF,
	# so we just feed the line in (no trailing sleep needed).
	printf '%s\n' "$message" | monread "$secs" | tee "$LOG_FILE" || true
}

do_test() {
	local secs="${1:-30}"
	do_upload
	do_monitor "$secs"
}

# Send `dump\n` to the device and capture the response (stripped of any
# banner) to a file. Designed to be run BEFORE every `upload`, since
# arduino-cli upload's UF2 flash will wipe EEPROM + LittleFS (= the
# whole `struct saved block` + every contact under /c). The capture
# uses a long-ish window because the device prints sequentially and
# can take a second or two for full contact lists.
do_backup() {
	require_acli
	local outfile="${1:-}"
	if [ -z "$outfile" ]; then
		log "backup: usage: $0 backup <output-file>"
		return 1
	fi
	wait_for_port
	log "Backup → $outfile"
	# 10 s capture is enough for the block + a handful of contacts.
	# The device emits "# scramler backup end" as the last line;
	# downstream tooling can trim to that marker if a longer
	# capture window picks up unrelated boot chatter.
	printf 'dump\n' | monread 10 > "$outfile.raw" || true
	# Keep everything from "scramler backup begin" through end markers
	# inclusive — strips any pre-dump scrollback.
	awk '/scramler backup begin/{p=1} p{print} /scramler backup end/{p=0}' \
		"$outfile.raw" > "$outfile"
	rm -f "$outfile.raw"
	local count
	count=$(wc -l < "$outfile")
	if [ "$count" -lt 5 ]; then
		log "WARNING: backup looks short ($count lines). Is the device idle and on $PORT?"
		return 1
	fi
	log "Wrote $count lines to $outfile"
}

# Replay a backup file: feed every non-comment, non-blank line back to
# the device as a `set` command, then send `save`. The firmware tolerates
# any ordering of contact field lines (it auto-flushes when the userid
# changes), so a hand-edited backup works.
do_restore() {
	require_acli
	local infile="${1:-}"
	if [ -z "$infile" ] || [ ! -f "$infile" ]; then
		log "restore: usage: $0 restore <backup-file>"
		return 1
	fi
	wait_for_port
	log "Restore ← $infile (this can take 20-30 s)"
	# Build the command stream: each non-blank, non-# line becomes
	# `set <line>\n`, then a single `save\n` to commit, then a brief
	# sleep so the device's last responses make it back into the log.
	# The whole stream is piped into one arduino-cli monitor process
	# so we don't pay re-open latency per line.
	{
		while IFS= read -r ln; do
			# Strip CR (windows line endings) and skip blanks/comments.
			ln="${ln%$'\r'}"
			[ -z "$ln" ] && continue
			case "$ln" in \#*) continue ;; esac
			printf 'set %s\n' "$ln"
		done < "$infile"
		printf 'save\n'
	} | monread 60 | tee "$LOG_FILE" || true
	log "Restore done. Verify with: $0 send dump 10"
}

# ---------- dispatch ----------
cmd="${1:-help}"
shift || true

case "$cmd" in
	check)   do_check ;;
	engine)  do_engine_check ;;
	setup)   do_setup ;;
	build)   do_build ;;
	upload)  do_upload ;;
	monitor) do_monitor "${1:-30}" ;;
	send)    do_send "${1:-}" "${2:-10}" ;;
	backup)  do_backup "${1:-}" ;;
	restore) do_restore "${1:-}" ;;
	test)    do_test "${1:-30}" ;;
	dist)    do_dist "${1:-}" ;;
	help|--help|-h|*)
		sed -n '2,38p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
		;;
esac
