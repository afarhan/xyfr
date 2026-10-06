
CC = gcc
CFLAGS = -Wall -Wextra -g -pthread -std=gnu99 -I.. -MMD -MP
LIBS = -lsqlite3

# libvterm (phone / xyfr-termd only). Default to a system install (-lvterm,
# headers on the default path). The droplet has neither -- it builds libvterm
# from a tarball as a static .a and can't reach github -- so override there:
#   make phone VTERM_INC="-I$HOME/libvterm-0.3.3/include" \
#              VTERM_LIB="$HOME/libvterm-0.3.3/libvterm.a"
VTERM_INC ?=
VTERM_LIB ?= -lvterm

# wg.c / wg.h / crypto.c live in the firmware sketch root (one level up) so
# the host binaries and the Arduino build share a single canonical copy.
# vpath lets the existing %.o: %.c rule pick them up from .. transparently.
vpath %.c ..

# hal_posix.o provides hal_rand() (getrandom CSPRNG) — wg.c's fill_random() now
# calls it instead of unseeded libc rand() (closes threat-model J-1 for the
# server/relay too), so every binary linking wg.o must also link the HAL.
OBJS = db.o net.o wg.o crypto.o hal_posix.o logstamp.o

SRCS = server.c relay.c route_pool.c
BINS = server dbc keygen dbadmin relay

all: $(BINS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# (client.c retired — the legacy standalone test client with its own
# CLIENT_* state machine + DATA_VOICE loopback rig. Superseded by `phone`
# (phone_host.c), which links the SAME shared portable core as the firmware.
# The source remains in git history. audio_alsa.c is kept — `phone` uses it.)

s3: s3.c $(OBJS)
	@echo "(deprecated target 's3' - use 'server')"; exit 1

server: server.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ server.c $(OBJS) $(LIBS)

keygen: keygen.c crypto.o hal_posix.o bip39.o bip39_wordlist.o
	$(CC) $(CFLAGS) -o $@ keygen.c crypto.o hal_posix.o bip39.o bip39_wordlist.o $(LIBS)

# --- backup_tool: host inspector/decryptor for a device backup file. Peels the
# --- per-sector OUTER AEAD (fixed BK_OUTER_KEY) and, with --json, mounts the raw
# --- image through the real portable storage stack to dump settings/contacts/msgs.
BT_CFLAGS = -g -O0 -Wall -D_GNU_SOURCE -std=gnu99 -I..
backup_tool:
	gcc $(BT_CFLAGS) -c ../crypto.c        -o bt_crypto.o
	gcc $(BT_CFLAGS) -c ../keystore.c      -o bt_keystore.o
	gcc $(BT_CFLAGS) -c ../abblock.c       -o bt_abblock.o
	gcc $(BT_CFLAGS) -c ../bootblock.c     -o bt_bootblock.o
	gcc $(BT_CFLAGS) -c ../settingsblock.c -o bt_settingsblock.o
	gcc $(BT_CFLAGS) -c ../secure_store.c         -o bt_store.o
	gcc $(BT_CFLAGS) -c ../filesystem.c    -o bt_filesystem.o
	gcc $(BT_CFLAGS) -c backup_tool.c      -o bt_main.o
	gcc -g -O0 -o backup_tool bt_main.o bt_crypto.o bt_keystore.o bt_abblock.o bt_bootblock.o \
		bt_settingsblock.o bt_store.o bt_filesystem.o
	@echo "built ./backup_tool"

dbadmin: dbadmin.c db.o hal_posix.o
	$(CC) $(CFLAGS) -o $@ dbadmin.c db.o hal_posix.o $(LIBS)

dbc: dbc.c db.o
	$(CC) $(CFLAGS) -o $@ dbc.c db.o $(LIBS)

relay: relay.c route_pool.o $(OBJS)
	$(CC) $(CFLAGS) -o $@ relay.c route_pool.o $(OBJS) $(LIBS)

# --- host-side unit test: run the SHARED test_contacts() on Linux against the
# --- POSIX fs backend (fs_posix.c, writes ./fsroot). Builds the device's
# --- contacts.c (portable C) + test_contacts.cpp VERBATIM; debug.h is host-aware
# --- and hostinc/Arduino.h satisfies the <Arduino.h> include. C sources (fs/hal/
# --- wg/crypto/contacts) compile with gcc as C; .cpp with g++ as C++; linked g++.
HT_CFLAGS   = -g -O0 -Wall -D_GNU_SOURCE -std=gnu99 -Ihostinc -I..
HT_CXXFLAGS = -g -O0 -Wall -Ihostinc -I..
host_test:
	gcc $(HT_CFLAGS)   -c hal_posix.c        -o ht_hal.o
	gcc $(HT_CFLAGS)   -c fs_posix.c         -o ht_fs.o
	gcc $(HT_CFLAGS)   -c ../wg.c            -o ht_wg.o
	gcc $(HT_CFLAGS)   -c ../crypto.c        -o ht_crypto.o
	g++ $(HT_CXXFLAGS) -c host_test_main.cpp -o ht_main.o
	gcc $(HT_CFLAGS)   -c ../contacts.c      -o ht_contacts.o
	gcc $(HT_CFLAGS)   -c ../filesystem.c    -o ht_filesystem.o
	gcc $(HT_CFLAGS)   -c ../secure_store.c         -o ht_store.o
	gcc $(HT_CFLAGS)   -c ../keystore.c      -o ht_keystore.o
	gcc $(HT_CFLAGS)   -c ../abblock.c       -o ht_abblock.o
	gcc $(HT_CFLAGS)   -c ../bootblock.c     -o ht_bootblock.o
	gcc $(HT_CFLAGS)   -c ../settingsblock.c -o ht_settingsblock.o
	gcc $(HT_CFLAGS)   -c rawflash_posix.c   -o ht_rawflash.o
	gcc $(HT_CFLAGS)   -c bootflash_posix.c  -o ht_bootflash.o
	g++ $(HT_CXXFLAGS) -c ../test_contacts.cpp -o ht_test.o
	g++ -g -O0 -o host_test ht_hal.o ht_fs.o ht_wg.o ht_crypto.o ht_main.o ht_contacts.o ht_test.o \
		ht_filesystem.o ht_store.o ht_keystore.o ht_abblock.o ht_bootblock.o ht_settingsblock.o \
		ht_rawflash.o ht_bootflash.o
	@echo "built ./host_test — run it; writes ./fsroot"

# --- host-side unit test for the at-rest key schedule: keystore.c + bootblock.c
# --- over the file-backed bootflash_posix backend (./fsroot/bootblock.img).
# --- Proves provision/unlock/PIN/passphrase-change/torn-write/wipe on Linux
# --- before any device flash code. All C; gcc compile + link.
KT_CFLAGS = -g -O0 -Wall -Wextra -D_GNU_SOURCE -std=gnu99 -I..
keystore_test:
	gcc $(KT_CFLAGS) -c ../abblock.c     -o kt_abblock.o
	gcc $(KT_CFLAGS) -c ../bootblock.c   -o kt_bootblock.o
	gcc $(KT_CFLAGS) -c ../keystore.c    -o kt_keystore.o
	gcc $(KT_CFLAGS) -c bootflash_posix.c  -o kt_bootflash.o
	gcc $(KT_CFLAGS) -c hal_posix.c      -o kt_hal.o
	gcc $(KT_CFLAGS) -c ../wg.c          -o kt_wg.o
	gcc $(KT_CFLAGS) -c ../crypto.c      -o kt_crypto.o
	gcc $(KT_CFLAGS) -c test_keystore.c  -o kt_test.o
	gcc -g -O0 -o keystore_test kt_abblock.o kt_bootblock.o kt_keystore.o kt_bootflash.o kt_hal.o kt_wg.o kt_crypto.o kt_test.o
	@echo "built ./keystore_test — run it; writes ./fsroot/bootblock.img"

# --- append-log + record layers, formerly bytelog+msgstore) over the rawflash
# --- file backend. append/read/recent/search/compact/crash-safety on Linux
# --- before any device flash. All C; gcc compile + link.


# --- host-side unit test for the libvterm wrapper (vterm_glue.c): feeds raw
# --- escape sequences and asserts the resulting cell grid. No PTY, no network,
# --- no device. Needs libvterm-dev (the phone binary links -lvterm too).
VG_CFLAGS = -g -O0 -Wall -Wextra -D_GNU_SOURCE -std=gnu99 -I..
vterm_glue_test:
	gcc $(VG_CFLAGS) $(VTERM_INC) -c vterm_glue.c -o vg_glue.o
	gcc $(VG_CFLAGS) -c test_vterm_glue.c -o vg_test.o
	gcc -g -O0 -o vterm_glue_test vg_glue.o vg_test.o $(VTERM_LIB)
	@echo "built ./vterm_glue_test — run it; no side effects"

# --- host-side unit test for the TERMG differ/framer. Pure C, no libvterm, no
# --- network: drives a simulated host screen through the encoder and a
# --- simulated device through the decoder, and asserts they converge.
TG_CFLAGS = -g -O0 -Wall -Wextra -D_GNU_SOURCE -std=gnu99 -I..
install-termd: xyfr-termd
	@packaging/install-termd.sh ./xyfr-termd

xyfr-termd:
	gcc $(PH_CFLAGS)   -c termd_host.c    -o td_host.o
	gcc $(PH_CFLAGS)   -c net_posix.c     -o td_net.o
	gcc $(PH_CFLAGS)   -c fs_posix.c      -o td_fs.o
	gcc $(PH_CFLAGS)   -c hal_posix.c     -o td_hal.o
	gcc $(PH_CFLAGS)   -c ../kernel.c -o td_core.o
	gcc $(PH_CFLAGS)   -c ../config.c     -o td_config.o
	gcc $(PH_CFLAGS)   -c config_env.c    -o td_config_env.o
	gcc $(PH_CFLAGS)   -c ../netif.c      -o td_netif.o
	gcc $(PH_CFLAGS)   -c ../stream.c     -o td_stream.o
	gcc $(PH_CFLAGS)   -c ../app_call.c       -o td_call.o
	gcc $(PH_CFLAGS)   -c ../cmdq.c       -o td_cmdq.o
	gcc $(PH_CFLAGS)   -c ../msg.c        -o td_msg.o
	gcc $(PH_CFLAGS)   -c ../channel_log.c    -o td_channel.o
	gcc $(PH_CFLAGS)   -c ../app_channel.c -o td_appchan.o
	gcc $(PH_CFLAGS)   -c ../msg_debug.c  -o td_msgdbg.o
	gcc $(PH_CFLAGS)   -c ../wg.c         -o td_wg.o
	gcc $(PH_CFLAGS)   -c ../crypto.c     -o td_crypto.o
	gcc $(PH_CFLAGS)   -c ../secure_store.c        -o td_store.o
	gcc $(PH_CFLAGS)   -c ../keystore.c     -o td_keystore.o
	gcc $(PH_CFLAGS)   -c ../abblock.c      -o td_abblock.o
	gcc $(PH_CFLAGS)   -c ../settingsblock.c   -o td_settingsblock.o
	gcc $(PH_CFLAGS)   -c ../bootblock.c    -o td_bootblock.o
	gcc $(PH_CFLAGS)   -c ../filesystem.c   -o td_filesystem.o
	gcc $(PH_CFLAGS)   -c rawflash_posix.c  -o td_rawflash.o
	gcc $(PH_CFLAGS)   -c bootflash_posix.c   -o td_bootflash.o
	gcc $(PH_CFLAGS)   -c ../contacts.c   -o td_contacts.o
	gcc $(PH_CFLAGS)   -c ../policy.c     -o td_policy.o
	gcc $(PH_CFLAGS)   -c term_host.c     -o td_term.o
	gcc $(PH_CFLAGS) $(VTERM_INC) -c vterm_glue.c -o td_vglue.o
	gcc $(PH_CFLAGS)   -c ../termg.c      -o td_termg.o
	gcc $(PH_CFLAGS)   -c logstamp.c      -o td_logstamp.o
	g++ -g -O0 -pthread -o xyfr-termd td_host.o td_net.o td_fs.o td_hal.o td_core.o \
		td_netif.o td_stream.o td_call.o td_cmdq.o td_msg.o td_msgdbg.o td_channel.o td_appchan.o td_wg.o td_crypto.o \
		td_store.o td_keystore.o td_abblock.o td_settingsblock.o td_bootblock.o td_filesystem.o \
		td_rawflash.o td_bootflash.o td_contacts.o td_policy.o td_term.o td_vglue.o td_termg.o td_logstamp.o \
		td_config.o td_config_env.o \
		-lm -lutil $(VTERM_LIB)
	@echo "built ./xyfr-termd — the standalone terminal server (own key, run as its own user)"

termg_test:
	gcc $(TG_CFLAGS) -c ../termg.c   -o tg_termg.o
	gcc $(TG_CFLAGS) -c test_termg.c -o tg_test.o
	gcc -g -O0 -o termg_test tg_termg.o tg_test.o
	@echo "built ./termg_test — run it; no side effects"

# --- host-side unit test for the contact ring (the device contact store):
# --- erase / remount / GC / 500-cap on Linux before any device flash.
CR_CFLAGS = -g -O0 -Wall -Wextra -D_GNU_SOURCE -std=gnu99 -I..
FS_CFLAGS = -g -O0 -Wall -Wextra -D_GNU_SOURCE -std=gnu99 -I..
filesystem_test:
	gcc $(FS_CFLAGS) -c ../filesystem.c  -o fs_filesystem.o
	gcc $(FS_CFLAGS) -c ../config.c      -o fs_config.o
	gcc $(FS_CFLAGS) -c config_env.c     -o fs_config_env.o
	gcc $(FS_CFLAGS) -c rawflash_posix.c -o fs_rawflash.o
	gcc $(FS_CFLAGS) -c hal_posix.c      -o fs_hal.o
	gcc $(FS_CFLAGS) -c ../wg.c          -o fs_wg.o
	gcc $(FS_CFLAGS) -c ../crypto.c      -o fs_crypto.o
	gcc $(FS_CFLAGS) -c test_filesystem.c -o fs_test.o
	gcc -g -O0 -o filesystem_test fs_filesystem.o fs_config.o fs_config_env.o fs_rawflash.o fs_hal.o fs_wg.o fs_crypto.o fs_test.o
	@echo "built ./filesystem_test — run it; writes ./fsroot/rawflash.img"


# --- host CLI on the SHARED phone core: links the same C sources as the
# --- firmware (phone_core + netif/session/stream/apps/call/cmdq + storage/contacts)
# --- behind the POSIX HAL (net/fs/hal _posix). Two threads (stack pump + stdin
# --- console) over the lock-free cmdq. Platform stubs + main live in
# --- phone_host.c. All shared sources are now plain C (secure_store.c absorbed storage.cpp).
PH_CFLAGS   = -g -O0 -Wall -D_GNU_SOURCE -std=gnu99 -pthread -Ihostinc -I..
PH_CXXFLAGS = -g -O0 -Wall -pthread -Ihostinc -I..
stream_test:
	gcc $(PH_CFLAGS)   -c ../stream.c    -o st_stream.o
	gcc $(PH_CFLAGS)   -c stream_test.c  -o st_main.o
	gcc -g -O0 -o stream_test st_main.o st_stream.o
	@echo "built ./stream_test — two endpoints in one process over a stub network"

phone:
	gcc $(PH_CFLAGS)   -c phone_host.c    -o ph_host.o
	gcc $(PH_CFLAGS)   -c net_posix.c     -o ph_net.o
	gcc $(PH_CFLAGS)   -c fs_posix.c      -o ph_fs.o
	gcc $(PH_CFLAGS)   -c hal_posix.c     -o ph_hal.o
	gcc $(PH_CFLAGS)   -c ../kernel.c -o ph_core.o
	gcc $(PH_CFLAGS)   -c ../config.c     -o ph_config.o
	gcc $(PH_CFLAGS)   -c config_env.c    -o ph_config_env.o
	gcc $(PH_CFLAGS)   -c ../netif.c      -o ph_netif.o
	gcc $(PH_CFLAGS)   -c ../stream.c     -o ph_stream.o
	gcc $(PH_CFLAGS)   -c ../app_call.c       -o ph_call.o
	gcc $(PH_CFLAGS)   -c ../cmdq.c       -o ph_cmdq.o
	gcc $(PH_CFLAGS)   -c ../msg.c        -o ph_msg.o
	gcc $(PH_CFLAGS)   -c ../msg_debug.c  -o ph_msgdbg.o
	gcc $(PH_CFLAGS)   -c ../wg.c         -o ph_wg.o
	gcc $(PH_CFLAGS)   -c ../crypto.c     -o ph_crypto.o
	gcc $(PH_CFLAGS)   -c audio_alsa.c    -o ph_alsa.o
	gcc $(PH_CFLAGS)   -c ../secure_store.c        -o ph_store.o
	gcc $(PH_CFLAGS)   -c ../keystore.c     -o ph_keystore.o
	gcc $(PH_CFLAGS)   -c ../abblock.c      -o ph_abblock.o
	gcc $(PH_CFLAGS)   -c ../settingsblock.c   -o ph_settingsblock.o
	gcc $(PH_CFLAGS)   -c ../bootblock.c    -o ph_bootblock.o
	gcc $(PH_CFLAGS)   -c ../filesystem.c   -o ph_filesystem.o
	gcc $(PH_CFLAGS)   -c rawflash_posix.c  -o ph_rawflash.o
	gcc $(PH_CFLAGS)   -c bootflash_posix.c   -o ph_bootflash.o
	gcc $(PH_CFLAGS)   -c ../contacts.c   -o ph_contacts.o
	gcc $(PH_CFLAGS)   -c ../channel_log.c    -o ph_channel.o
	gcc $(PH_CFLAGS)   -c ../app_channel.c -o ph_appchan.o
	gcc $(PH_CFLAGS)   -c ../policy.c     -o ph_policy.o
	gcc $(PH_CFLAGS)   -c term_host.c     -o ph_term.o
	gcc $(PH_CFLAGS) $(VTERM_INC) -c vterm_glue.c -o ph_vglue.o
	gcc $(PH_CFLAGS)   -c ../termg.c      -o ph_termg.o
	gcc $(PH_CFLAGS)   -c logstamp.c      -o ph_logstamp.o
	g++ -g -O0 -pthread -o phone ph_host.o ph_net.o ph_fs.o ph_hal.o ph_core.o \
		ph_netif.o ph_stream.o ph_call.o ph_cmdq.o ph_msg.o ph_msgdbg.o ph_wg.o ph_crypto.o \
		ph_store.o ph_keystore.o ph_abblock.o ph_settingsblock.o ph_bootblock.o ph_filesystem.o ph_rawflash.o ph_bootflash.o \
		ph_alsa.o ph_contacts.o ph_channel.o ph_appchan.o ph_policy.o ph_term.o ph_vglue.o ph_termg.o ph_logstamp.o \
		ph_config.o ph_config_env.o \
		-lasound -lm -lutil $(VTERM_LIB)
	@echo "built ./phone — shared-core CLI (ALSA audio); reads client.conf, writes ./fsroot"

# --- actv: standalone activation-path tester. Builds a msg_type=5 activation
# --- msg1 exactly like the firmware (peer_handshake_request_generate + the code
# --- in mac2) and sends it to a relay's :5004, reporting the tunneled-back reply
# --- (SUCCESS / UNKNOWN_CODE / CODE_USED). Provides its own stubs for the two
# --- platform symbols wg.o references. Diagnostic tool; not part of `all`.
actv: actv.c wg.o crypto.o hal_posix.o
	$(CC) $(CFLAGS) -o $@ actv.c wg.o crypto.o hal_posix.o
	@echo "built ./actv — usage: ./actv <relay_ip> <server_pub_hex64> <my_priv_hex64> <code16>"

clean:
	rm -f $(BINS) $(OBJS) route_pool.o audio_alsa.o actv *.d host_test ht_*.o phone ph_*.o xyfr-termd td_*.o keystore_test kt_*.o secure_store_test st_*.o settingsblock_test sb_*.o filesystem_test fs_*.o backup_tool bt_*.o
	rm -rf fsroot

# -MMD -MP above emits per-object .d files listing every header each .c
# transitively includes. Pull them in so editing any header (e.g. wg.h)
# correctly invalidates dependent objects on the next build.
-include $(OBJS:.o=.d)

# phone + host_test have no file prerequisites and recompile everything in their
# recipe, so they must be PHONY — otherwise make sees the existing binary and
# says "up to date", silently skipping source edits.
.PHONY: all clean phone xyfr-termd install-termd host_test keystore_test settingsblock_test secure_store_test filesystem_test vterm_glue_test termg_test stream_test

# --- host-side unit test for the at-rest integration point (secure_store.c): keystore
# --- (over bootflash_posix) + fixed block (over rawflash_posix) composed.
ST_CFLAGS = -g -O0 -Wall -Wextra -D_GNU_SOURCE -std=gnu99 -I..
secure_store_test:
	gcc $(ST_CFLAGS) -c ../secure_store.c       -o st_store.o
	gcc $(ST_CFLAGS) -c ../abblock.c     -o st_abblock.o
	gcc $(ST_CFLAGS) -c ../settingsblock.c  -o st_settingsblock.o
	gcc $(ST_CFLAGS) -c ../bootblock.c   -o st_bootblock.o
	gcc $(ST_CFLAGS) -c ../keystore.c    -o st_keystore.o
	gcc $(ST_CFLAGS) -c rawflash_posix.c -o st_rawflash.o
	gcc $(ST_CFLAGS) -c bootflash_posix.c  -o st_bootflash.o
	gcc $(ST_CFLAGS) -c hal_posix.c      -o st_hal.o
	gcc $(ST_CFLAGS) -c ../wg.c          -o st_wg.o
	gcc $(ST_CFLAGS) -c ../crypto.c      -o st_crypto.o
	gcc $(ST_CFLAGS) -c test_secure_store.c     -o st_test.o
	gcc -g -O0 -o secure_store_test st_store.o st_abblock.o st_settingsblock.o st_bootblock.o st_keystore.o st_rawflash.o st_bootflash.o st_hal.o st_wg.o st_crypto.o st_test.o
	@echo "built ./secure_store_test"

# --- host-side unit test for the multi-sector A/B image store (settingsblock).
FB_CFLAGS = -g -O0 -Wall -Wextra -D_GNU_SOURCE -std=gnu99 -I..
settingsblock_test:
	gcc $(FB_CFLAGS) -c ../abblock.c         -o fb_abblock.o
	gcc $(FB_CFLAGS) -c ../settingsblock.c   -o fb_settingsblock.o
	gcc $(FB_CFLAGS) -c rawflash_posix.c  -o fb_rawflash.o
	gcc $(FB_CFLAGS) -c test_settingsblock.c -o fb_test.o
	gcc -g -O0 -o settingsblock_test fb_abblock.o fb_settingsblock.o fb_rawflash.o fb_test.o
	@echo "built ./settingsblock_test"

# (the standalone bytelog_test was retired: the append-log layer is now internal
# to filesystem.c and is exercised through the public file_* API.)
