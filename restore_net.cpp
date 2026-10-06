// ============================================================================
// restore_net.cpp — full-device RESTORE over a temporary on-device web server.
//
// WHY POLL MODE (and not arduino's normal WiFi):
//
//   Restore must erase+program every FS sector WHILE receiving the backup over
//   WiFi. An RP2350 flash erase turns XIP off and disables interrupts for the
//   duration (tens of ms/sector). arduino-pico services the cyw43 radio with the
//   pico-sdk "threadsafe_background" (tsb) async_context: a background IRQ + the
//   cyw43 host-wake IRQ drive PIO-SPI/DMA transfers to the radio ASYNCHRONOUSLY.
//   When those transfers race a flash erase, the radio bus desyncs and the device
//   WEDGES (hard hang). This was reproduced ~a dozen ways and could not be fixed
//   from inside tsb (holding the cyw43 lock / __lockBluetooth did NOT help): tsb's
//   async_context vtable literally has `.poll = 0`, so a tsb context cannot be
//   hand-pumped — servicing is fundamentally asynchronous and unstoppable.
//
//   picowota (the OTA bootloader) writes flash over WiFi for exactly this reason
//   using the OTHER cyw43 arch: "lwip_poll". In poll mode the radio is serviced
//   ONLY by explicit cyw43_arch_poll() calls. So between polls — which is when we
//   erase — there is GUARANTEED no radio transfer in flight. TCP backpressure
//   (window) paces the sender to our flash speed. Proven: 2 MB streamed, all 512
//   sectors written live, zero wedge.
//
// HOW THE tsb -> POLL SWITCH IS DONE (restore_boot, the hard-won part):
//
//   You cannot just bring a working netif up in poll mode here, because:
//     (a) arduino hardwires tsb (initVariant -> cyw43_arch_init at boot), and the
//         poll-arch cyw43_arch_init/poll/deinit symbols would COLLIDE with the tsb
//         ones already linked — so we can't #include the SDK poll arch; and
//     (b) arduino stubs cyw43_cb_tcpip_init to a NO-OP and routes ALL radio RX
//         through __wrap_cyw43_cb_process_ethernet -> __getCYW43Netif() ==
//         CYW43::_netif, a private static set ONLY by WiFiClass/CYW43::begin (tsb).
//   So: connect ONCE via arduino WiFi (tsb) to create + register CYW43::_netif and
//   its RX routing; grab that netif; then cyw43_arch_deinit() (CYW43::_netif is
//   WiFi's static, so it SURVIVES and RX still lands); then build a POLL context
//   ourselves from the arch-AGNOSTIC pieces that ARE linked — vendored
//   async_context_poll.c's async_context_poll_init_with_defaults() +
//   cyw43_arch_set_async_context() (common arch) + cyw43_driver_init() +
//   lwip_nosys_init(); re-join with cyw43_arch_wifi_connect_async + pump
//   cyw43_arch_poll() until link; then dhcp_start() on the persisted netif and
//   pump for the lease. After that, cyw43_arch_poll() drives EVERYTHING (RX, lwIP
//   timeouts, DHCP) and we erase/program between polls. The common cyw43_arch
//   helpers (cyw43_arch_poll / _async_context / _set_async_context) are arch-
//   agnostic — only init/deinit are tsb-specific — which is what makes this legal.
//
//   WARM-REBOOT CAVEAT: a warm reboot (the menu's rp2040.reboot) does NOT power-
//   reset the cyw43 chip the way a cold boot / UF2 flash does, so initVariant's
//   cyw43_arch_init() comes up on a stale chip — it associates + gets a lease but
//   can't pass traffic. restore_boot therefore does cyw43_arch_deinit()/init()
//   FIRST to force the driver to re-reset the chip from a known state.
//
//   LVGL: ui_init() (core1/LVGL) must come up AFTER the radio switch (bringing it
//   up before wedges the re-join), and the restore loop repaints with lv_refr_now,
//   NOT ui_slice — the indev path touches kernel state restore never inited.
//
// Spec: STORAGE backup format in backup_format.h. Device-only / core 0.
// ============================================================================

#include "debug.h"
#include <Arduino.h>
#include <WiFi.h>      // arduino WiFi: used ONCE (tsb) to create + register the cyw43 netif

// Low-level pico headers — restore drives the radio in poll mode after the switch.
#include <pico/cyw43_arch.h>
#include <pico/async_context_poll.h>
#include <pico/cyw43_driver.h>
#include <pico/lwip_nosys.h>
#include <lwip/tcp.h>
#include <lwip/netif.h>
#include <lwip/dhcp.h>
#include <hardware/watchdog.h>   // watchdog_hw->scratch[] — reboot-surviving flag
#include <pico/bootrom.h>        // reset_usb_boot — the menu's BOOTSEL action

#include "rawflash.h"
#include "ui.h"
#include "view.h"   // VIEW_K_* key codes (was lvgl's LV_KEY_*)          // ui_init/ui_slice/ui_force_refresh/ui_splash_clear + LVGL
#include "display_backend.h"  // panel_* direct-draw primitives for the restore screen
#include "wg.h"          // xchacha20poly1305_decrypt
#include "backup_format.h"  // bk_header, BK_OUTER_KEY, BK_* constants
#include "ota.h"          // firmware-update mode: OTA_STAGING + ota_stage_* (staging-only writes)
#include "device_record.h"     // struct device_record `block`, ap_list (WiFi creds from the store)
#include "secure_store.h"       // store_init / store_boot_unlock / block_read
#include "hal.h"         // hal_rand (access-code RNG)
#include "restore_net.h"

// arduino-pico's cyw43 netif (CYW43::_netif). RX from the radio routes ONLY here
// (__wrap_cyw43_cb_process_ethernet -> __getCYW43Netif). Set by WiFiClass/CYW43::begin
// in tsb; persists across cyw43_arch_deinit() (it's WiFi's static), so RX still
// lands after we re-join under poll.
struct netif *__getCYW43Netif(void);   // C++ linkage (defined in CYW43shim.cpp / core weak)

// Fallback WiFi creds, used only if the store has no saved AP (bench/unconfigured).
// The normal path reads device_record.ap_list[0] in restore_boot (see WiFi-from-store).
#define WIFI_SSID  "Airtel_71hh"
#define WIFI_PASS  "71isOpen."

// ---- reboot-surviving "enter restore" flag ----
// A watchdog scratch register survives a WARM reboot (rp2040.reboot() does
// watchdog_reboot, which preserves scratch[0..3]) but is cleared by a power
// cycle — so a power-cycle is the automatic escape back to the normal phone.
// scratch[4..7] are bootrom-reserved on RP2350; use scratch[2].
#define RESTORE_FLAG_REG    2
#define RESTORE_FLAG_MAGIC  0x52455354u   // "REST"

void restore_request_reboot(void) {
    // The warm reboot goes dark for ~10 s (radio tsb->poll switch + restore-server
    // bring-up all happen BEFORE the UI can come up). Show a product-look notice
    // first so that dark screen reads as expected, not a crash.
    // Don't draw here — restore_boot paints the "please wait" notice early on the
    // far side of the reboot (fresh panel init). Drawing it here too made it
    // flash, go dark across the reboot, then reappear.
    watchdog_hw->scratch[RESTORE_FLAG_REG] = RESTORE_FLAG_MAGIC;
    // Deauth from the AP first: a warm reboot doesn't tear the association down,
    // so the AP would keep a stale entry for our MAC and not forward to the
    // freshly re-associated restore-mode radio (device gets a lease but is
    // unreachable). Disconnect cleanly, give the AP a moment, THEN reboot.
    WiFi.disconnect(true);
    delay(400);
    rp2040.reboot();   // warm reboot; scratch survives -> setup() enters restore
}

bool restore_boot_requested(void) {
    if (watchdog_hw->scratch[RESTORE_FLAG_REG] == RESTORE_FLAG_MAGIC) {
        watchdog_hw->scratch[RESTORE_FLAG_REG] = 0;   // one-shot: consume it
        return true;
    }
    return false;
}

// ---- firmware-update mode ---------------------------------------------------
// Reuses this file's poll-mode WiFi + TCP :80 + HTTP front + ring + UI. The only
// difference from restore: the POST body is a raw firmware .bin streamed into the
// OTA STAGING region (ota.h) and BLAKE2s-hashed on the fly; at end-of-body the hash
// is checked against the uploader's `b2s=` and reported. Every staging write clamps
// to the store-derived capacity, so this can NEVER touch the store. NO apply yet
// (that is the reboot-copier increment). Same scratch reg, a DISTINCT magic.
#define FW_FLAG_MAGIC  0x46495257u   // "FIRW"
static bool s_fw_mode = false;       // set by firmware_boot_requested(); guards restore vs firmware

void firmware_request_reboot(void) {
    watchdog_hw->scratch[RESTORE_FLAG_REG] = FW_FLAG_MAGIC;
    WiFi.disconnect(true);
    delay(400);
    rp2040.reboot();
}

void bootsel_reboot(void) {
    WiFi.disconnect(true);
    delay(400);
    reset_usb_boot(0, 0);   // does not return; a power cycle boots the phone again
}
bool firmware_boot_requested(void) {
    if (watchdog_hw->scratch[RESTORE_FLAG_REG] == FW_FLAG_MAGIC) {
        watchdog_hw->scratch[RESTORE_FLAG_REG] = 0;   // one-shot
        s_fw_mode = true;
        return true;
    }
    return false;
}

#define SECTOR_BYTES   4096u

#define RING_BYTES     (64u * 1024u)
// Backed by the shared HAL scratch arena (hal.h), grabbed in restore_boot(). Restore
// is a dedicated boot mode — nothing else touches the arena — and it always ends in a
// reboot, so the buffer is reclaimed without an explicit hal_free.
static uint8_t *s_ring = nullptr;
static volatile uint32_t s_head = 0;
static volatile uint32_t s_tail = 0;

static struct tcp_pcb *s_client = nullptr;
static volatile bool   s_closed = false;
static uint32_t s_total_rx  = 0;
static bool     s_active    = false;

// ---- backup-stream decode state ----
static bool      s_hdr_done = false;
static bk_header s_hdr;
static uint32_t  s_rec_idx  = 0;   // next record index expected (= sectors processed)
static uint32_t  s_verified = 0;   // records whose AEAD tag verified
static uint32_t  s_failed   = 0;   // records that FAILED AEAD
static bool      s_stream_err = false;  // header/format rejected
static bool      s_done       = false;  // completion reported (reset per connection)

static inline uint32_t ring_count(void) { return s_head - s_tail; }
static inline uint32_t ring_space(void) { return RING_BYTES - ring_count(); }

// ---- access code: a random 6-digit code shown on the device screen; the browser
// must echo it in POST /restore?code=NNNNNN. Stops a wardriver from pushing an
// image without physical sight of the device. ----
static char s_code[8] = {0};
static char s_ipstr[24] = {0};   // device IP (for the heartbeat/diagnostics)

// ---- HTTP front (poll mode handles the whole stream, so ONE POST, no chunking) ----
static bool s_http_done = false;   // request line + headers parsed; body (backup) follows
static bool s_resp_sent = false;   // final HTTP response written

static const char PAGE[] =
    "<!doctype html><meta name=viewport content=\"width=device-width,initial-scale=1\">"
    "<title>Xyfr Restore</title>"
    "<body style=\"font-family:sans-serif;max-width:30em;margin:2em auto;padding:0 1em\">"
    "<h2>Xyfr Restore</h2>"
    "<p>Restore this device from a backup file, in three steps. "
    "Watch the device screen for progress.</p>"
    "<p><b>1. Enter the access code</b> (shown on the device screen):<br>"
    "<input id=c size=10 inputmode=numeric style=\"font-size:1.1em;padding:.5em;margin-top:.4em\"></p>"
    "<p><b>2. Select the backup</b><br>"
    "<label for=f style=\"display:inline-block;font-size:1.1em;padding:.7em 1.4em;"
    "margin-top:.4em;border:1px solid #888;border-radius:.3em;cursor:pointer\">"
    "Choose backup file&#8230;</label>"
    "<input type=file id=f style=\"display:none\" "
    "onchange=\"document.getElementById('fn').textContent=this.files[0]?this.files[0].name:''\">"
    " <span id=fn></span></p>"
    "<p><b>3. Restore</b><br>"
    "<button style=\"font-size:1.1em;padding:.7em 1.4em;margin-top:.4em\" "
    "onclick=\"up()\">Restore &#8593;</button></p>"
    "<p id=s></p>"
    "<script>function st(t){document.getElementById('s').textContent=t;}\n"
    "async function up(){var f=document.getElementById('f').files[0];"
    "if(!f){alert('Choose a backup file first.');return;}"
    "var code=document.getElementById('c').value.trim();"
    "if(!code){alert('Enter the access code shown on the device screen.');return;}"
    "st('Reading & validating\\u2026');"
    "var b=atob((await f.text()).replace(/\\s+/g,''));"
    "var n=b.length,bin=new Uint8Array(n);for(var i=0;i<n;i++)bin[i]=b.charCodeAt(i);"
    "var dv=new DataView(bin.buffer);"
    "var magic=String.fromCharCode.apply(null,bin.subarray(0,8));"
    "if(magic!='XYFRBK01'){st('Not an Xyfr backup file.');return;}"
    "var sectors=dv.getUint16(20,true),exp=42+sectors*4112;"
    "if(n!=exp){st('File truncated/corrupt: '+n+' bytes, expected '+exp+'.');return;}"
    "if(!confirm('Restore '+sectors+' sectors to this device? It will reboot when done.'))return;"
    "st('Uploading '+n+' bytes\\u2026 watch the device screen.');"
    "try{var r=await fetch('/restore?code='+encodeURIComponent(code),{method:'POST',body:bin});"
    "st('Device: '+await r.text());}"
    "catch(e){st('Upload finished (device may have rebooted).');}}"
    "</script></body>";

// Best-effort TCP write (PAGE/response fit inside TCP_SND_BUF). lwIP raw calls
// are safe here: single-threaded poll, called between cyw43_arch_poll() ticks.
static void tcp_send_str(const char *data, uint32_t len) {
    if (s_client && len) {
      tcp_write(s_client, data, len, TCP_WRITE_FLAG_COPY);
      tcp_output(s_client);
    }
}

static void http_serve_page(void) {
    char h[112];
    int n = snprintf(h, sizeof h,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: %u\r\n\r\n",
        (unsigned)(sizeof(PAGE) - 1));
    tcp_send_str(h, n);
    tcp_send_str(PAGE, sizeof(PAGE) - 1);
}

static void http_status_respond(const char *status, const char *body) {
    char h[160];
    int n = snprintf(h, sizeof h,
        "HTTP/1.1 %s\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: %u\r\n\r\n",
        status, (unsigned)strlen(body));
    tcp_send_str(h, n);
    tcp_send_str(body, strlen(body));
}
static void http_respond(const char *body) { http_status_respond("200 OK", body); }

static void http_close(void) {
    if (s_client) {
      tcp_close(s_client);
      s_client = nullptr;
    }
}

// ---- direct-draw restore screen (NO LVGL — see the big header comment) ----
static char s_ssid[33]  = {0};    // WiFi SSID for step 1 (captured from the store)
static int  s_bar_x     = 0;      // remembered progress-bar geometry so progress can repaint
static int  s_bar_w     = 0;
static int  s_bar_y     = 0;      // remembered rows so status/progress can repaint
static int  s_status_y  = 0;

// Draw the whole static screen once the IP + access code are known.
static void restore_draw_screen(void) {
    panel_clear();
    const int X = 48, W = panel_width();                              // +40 left margin
    int y = 43;                                                     // below the chrome bar + a bit of top spacing
    panel_text(X, y, 3, s_fw_mode ? "Firmware Update" : "Restoring from Backup"); y += 36;
    panel_text_color(180);                                             // steps in light grey so the heading stands out
    panel_text(X, y, 2, "1. Connect your computer to WiFi:");          y += 20;
    { char l[64]; snprintf(l, sizeof l, "      %s", s_ssid[0] ? s_ssid : "(this device)"); panel_text(X, y, 2, l); } y += 26;
    { char l[64]; snprintf(l, sizeof l, "2. In the browser, type EXACTLY:"); panel_text(X, y, 2, l); }              y += 20;
    { char l[64]; snprintf(l, sizeof l, "      http://%s   (never https)", s_ipstr); panel_text(X, y, 2, l); }      y += 22;
    { char l[48]; snprintf(l, sizeof l, "3. Enter access code  %s", s_code); panel_text(X, y, 2, l); }              y += 22;
    panel_text(X, y, 2, s_fw_mode ? "4. Choose the firmware .bin, then Upload"
                               : "4. Choose your backup, then Restore");        y += 22;
    panel_text(X, y, 2, s_fw_mode ? "5. Compare the checksum shown below"
                               : "5. Wait for the restore to finish");         y += 30;   // gap above the progress bar
    panel_text_color(255);                                             // back to white for the bar/chrome
    s_bar_w = W / 2; s_bar_x = (W - s_bar_w) / 2;                   // progress bar: centered, half the width
    s_bar_y = y;
    panel_frame(s_bar_x, s_bar_y, s_bar_w, 16);
    s_status_y = s_bar_y + 22;
    // Escape hatch: this screen is reached by a single Enter (easy to hit by mistake),
    // so advertise how to back out EXPLICITLY — white, full-size, its own line.
    // Backspace reboots to the phone (handler in restore_loop). Drawn below the live
    // status line, whose updates repaint only their own band, so this is never erased.
    panel_text_color(255);
    panel_text_center(s_status_y + 24, 2, "Press Backspace to cancel and go back");
    panel_present();
    ui_tick();                 // draw the chrome bar (wifi|title|battery|clock) on top
}

// Live status line, drawn right under the progress bar (visual association).
static void restore_ui_status(const char *s) {
    if (s_status_y <= 0)  // screen not up yet (still in the radio switch)
      return;
    int W = panel_width();
    panel_canvas_begin(0, s_status_y, W, 16);                 // full-width band -> centered small text, no blink
    panel_fill(0, s_status_y, W, 16, false);
    panel_text_center(s_status_y, 1, s);                      // small font (montserrat_10), centered
    panel_canvas_end();
}

// Progress-bar fill (0..100), inside the frame drawn by restore_draw_screen().
static void restore_draw_progress(int pct) {
    if (s_bar_y <= 0)
      return;
    int inner = s_bar_w - 4;
    panel_canvas_begin(s_bar_x + 2, s_bar_y + 2, inner, 12);    // compose off-screen -> no blink
    panel_fill(s_bar_x + 2, s_bar_y + 2, inner, 12, false);     // clear interior
    if (pct > 0)
      panel_fill(s_bar_x + 2, s_bar_y + 2, inner * pct / 100, 12, true);
    panel_canvas_end();
}

// Copy `len` bytes out of the ring (wrapping), advance the read tail, and open
// the TCP window for them (deferred-recved backpressure).
static void ring_pull(void *dst, uint32_t len) {
    uint8_t *d = (uint8_t *)dst;
    for (uint32_t i = 0; i < len; i++)
      d[i] = s_ring[(s_tail + i) % RING_BYTES];
    s_tail += len;
    if (s_client)
      tcp_recved(s_client, len);
}

// Drop `len` bytes from the ring (advance tail + open window), no copy.
static void ring_discard(uint32_t len) {
    s_tail += len;
    if (s_client)
      tcp_recved(s_client, len);
}

// Find "\r\n\r\n" in the unread ring; return header length (bytes before it) or -1.
// HTTP headers arrive first while tail==0, so they don't wrap — linear scan is safe.
static int ring_find_header_end(void) {
    uint32_t cnt = ring_count();
    for (uint32_t i = 0; i + 3 < cnt; i++) {
        if (s_ring[(s_tail + i)     % RING_BYTES] == '\r' &&
            s_ring[(s_tail + i + 1) % RING_BYTES] == '\n' &&
            s_ring[(s_tail + i + 2) % RING_BYTES] == '\r' &&
            s_ring[(s_tail + i + 3) % RING_BYTES] == '\n') return (int)i;
    }
    return -1;
}

// Per-sector OUTER AEAD decrypt+verify (mirrors webbackup.cpp's encrypt):
//   nonce = salt(20) || idx_be32 ; aad = bk_header(42) || idx_be32 ; key = BK_OUTER_KEY
// Returns true iff the tag verifies (=> `plain` is authentic 4096-byte sector).
static bool rec_decrypt(uint32_t idx, const uint8_t *rec, uint8_t *plain) {
    uint8_t nonce[24];
    memcpy(nonce, s_hdr.salt, 20);
    nonce[20] = idx >> 24; nonce[21] = idx >> 16; nonce[22] = idx >> 8; nonce[23] = idx;
    uint8_t aad[sizeof(bk_header) + 4];
    memcpy(aad, &s_hdr, sizeof s_hdr);
    aad[sizeof s_hdr + 0] = idx >> 24; aad[sizeof s_hdr + 1] = idx >> 16;
    aad[sizeof s_hdr + 2] = idx >> 8;  aad[sizeof s_hdr + 3] = idx;
    return xchacha20poly1305_decrypt(plain, rec, BK_RECORD_BYTES, aad, sizeof aad, nonce, BK_OUTER_KEY);
}

// Consume one 4112-byte record from the ring: decrypt+verify, and on success
// write the 4096-byte plaintext sector. SCRATCH (cycling) until RESTORE_WRITE_REAL.
static void process_one_record(void) {
    static uint8_t rec[BK_RECORD_BYTES];
    static uint8_t plain[BK_SECTOR_BYTES];
    ring_pull(rec, BK_RECORD_BYTES);

    bool ok = rec_decrypt(s_rec_idx, rec, plain);
    if (ok) {
        s_verified++;
        // Write the verified plaintext to the REAL FS region: record index = sector.
        rawflash_erase(RAWFLASH_DEV_INTERNAL, s_rec_idx);
        rawflash_program(RAWFLASH_DEV_INTERNAL, s_rec_idx, 0, plain, BK_SECTOR_BYTES);
    } else {
        s_failed++;
        Debug.printf("restore: record %u AEAD FAILED\n", (unsigned)s_rec_idx);
    }
    s_rec_idx++;
}

static err_t on_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    (void)arg; (void)pcb;
    if (p == nullptr) {
      s_closed = true;
      return ERR_OK;
    }
    if (err != ERR_OK) {
      pbuf_free(p);
      return err;
    }
    if (p->tot_len <= ring_space()) {
        uint16_t copied = 0;
        for (struct pbuf *q = p; q != nullptr; q = q->next) {
            for (uint16_t i = 0; i < q->len; i++)
                s_ring[(s_head + copied + i) % RING_BYTES] = ((uint8_t *)q->payload)[i];
            copied += q->len;
        }
        s_head += copied;
        s_total_rx += copied;
        pbuf_free(p);
        return ERR_OK;   // tcp_recved deferred until flushed (backpressure)
    }
    return ERR_MEM;
}

static err_t on_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
    (void)arg;
    if (err != ERR_OK || newpcb == nullptr)
      return ERR_VAL;
    // Fresh connection = fresh restore stream. Reset the ring + decode state so
    // any stray bytes from a prior probe/connection don't corrupt the header.
    s_head = s_tail = 0;
    s_total_rx = 0;
    s_hdr_done = false;
    s_stream_err = false;
    s_rec_idx = s_verified = s_failed = 0;
    s_closed = false;
    s_done = false;
    s_http_done = false;
    s_resp_sent = false;
    s_client = newpcb;
    tcp_recv(newpcb, on_recv);
    Debug.println("restore: client connected (stream reset)");
    return ERR_OK;
}

// ---- the tsb -> POLL switch (see header) ----
static async_context_poll_t g_poll_ctx;

static bool poll_mode_bringup(void) {
    if (!async_context_poll_init_with_defaults(&g_poll_ctx)) {
        Debug.println("restore: async_context_poll_init FAILED");
        return false;
    }
    async_context_t *ctx = &g_poll_ctx.core;
    cyw43_arch_set_async_context(ctx);   // common cyw43_arch_poll() now polls THIS
    if (!cyw43_driver_init(ctx)) {
      Debug.println("restore: cyw43_driver_init FAILED");
      return false;
    }
    if (!lwip_nosys_init(ctx)) {
      Debug.println("restore: lwip_nosys_init FAILED");
      return false;
    }
    return true;
}

void restore_boot(void) {
    // Boot-capture window: repeat the banner so a freshly-attached serial reader
    // catches it. NOTE: the display/LVGL (ui_init) is brought up LATER, only after
    // the radio is switched to poll mode and serving — bringing up core1/LVGL
    // BEFORE the tsb->poll switch wedges the re-join (core1 active during the
    // radio switch). So: network first (core1 idle, proven), then UI.
    // Panel up FIRST (core0-only, no LVGL/core1 — safe) with a notice, so the dark
    // window is only the reboot itself, not the banner delay + the radio switch too.
    // The real screen is drawn later (restore_draw_screen), after IP + code.
    panel_begin();
    panel_text_center(panel_height() / 2 - 20, 2, s_fw_mode ? LV_SYMBOL_LOOP "  Entering firmware update..."
                                                      : LV_SYMBOL_LOOP "  Entering restore mode...");
    panel_text_center(panel_height() / 2 + 4,  2, "please wait");
    panel_present();

    for (int i = 0; i < 6; i++) {
      Debug.println("RB: restore boot start");
      delay(500);
    }

    // Claim the shared scratch arena for the upload ring (64 KB). Free at boot, since
    // restore runs alone; released implicitly by the reboot that ends restore.
    s_ring = (uint8_t *)hal_malloc(RING_BYTES);
    if (!s_ring) {
      Debug.println("restore: FATAL — scratch arena unavailable");
      return;
    }

    // A WARM reboot (from the menu/serial) does NOT power-reset the cyw43 chip the
    // way a cold boot / UF2 flash does, so initVariant's cyw43_arch_init() comes up
    // on a stale chip: it associates + gets a DHCP lease but can't pass traffic
    // (device unreachable). Force a clean deinit+reinit so the driver re-resets the
    // chip from a known state before we use WiFi.
    cyw43_arch_deinit();
    delay(500);
    if (cyw43_arch_init())
      Debug.println("restore: cyw43 re-init returned error");
    delay(200);
    Debug.println("restore: cyw43 re-initialised (clean chip state)");

    // 0) WiFi creds from the store (the device's own saved AP). Read the at-rest
    //    settings BEFORE the restore overwrites flash; fall back to compiled creds
    //    only if the store has no AP (bench / unconfigured).
    // EVERY saved AP is a candidate, not just slot 0: the phone connects via a
    // multi-AP walk, so a device whose slot 0 is stale (wrong passphrase, out of
    // range) still gets online — restore must reach the same networks it does.
    const char *cand_ssid[MAX_APS];
    const char *cand_key[MAX_APS];
    int ncand = 0;
    if (store_init()) {
        store_boot_unlock();
        if (block_read()) {
            for (int i = 0; i < MAX_APS; i++) {
                if (device_record.ap_list[i].ssid[0]) {
                    cand_ssid[ncand] = device_record.ap_list[i].ssid;
                    cand_key[ncand]  = device_record.ap_list[i].key;
                    ncand++;
                }
            }
        }
    }
    if (ncand == 0) {
        Debug.println("restore: store has no AP — using fallback creds");
        cand_ssid[0] = WIFI_SSID;
        cand_key[0]  = WIFI_PASS;
        ncand = 1;
    }
    const char *ssid = cand_ssid[0];
    const char *key  = cand_key[0];
    snprintf(s_ssid, sizeof s_ssid, "%s", ssid);   // for step 1 on screen
    Debug.printf("restore: %d WiFi candidate(s), first '%s'\n", ncand, ssid);

    // Tell the user we're connecting (this is the slow part after the reboot).
    panel_clear();
    panel_text_center(panel_height() / 2 - 8, 2, LV_SYMBOL_LOOP "  Connecting to WiFi...");
    panel_present();

    // 1) Connect via arduino WiFi (tsb). This is the ONLY way to create + register
    //    the cyw43 netif (CYW43::_netif) and hook RX to it — poll mode can't.
    WiFi.mode(WIFI_STA);
    uint32_t t0;
    bool tsb_ok = false;
    for (int a = 0; a < 3 * ncand && !tsb_ok; a++) {
        ssid = cand_ssid[a % ncand];       // round-robin the saved APs
        key  = cand_key[a % ncand];
        snprintf(s_ssid, sizeof s_ssid, "%s", ssid);
        Debug.printf("restore: WiFi.begin('%s') tsb attempt %d ...\n", ssid, a + 1);
        WiFi.begin(ssid, key);
        t0 = millis();
        while (WiFi.status() != WL_CONNECTED && (uint32_t)(millis() - t0) < 12000)
          delay(100);
        tsb_ok = (WiFi.status() == WL_CONNECTED);
        if (!tsb_ok) {
          Debug.printf("restore: tsb attempt %d failed (st=%d)\n", a, WiFi.status());
          WiFi.disconnect();
          delay(600);
        }
    }
    if (!tsb_ok) {
        Debug.println("restore: tsb connect FAILED — abort");
        panel_clear();
        panel_text_center(panel_height() / 2 - 20, 2, LV_SYMBOL_WARNING "  WiFi connection failed.");
        panel_text_center(panel_height() / 2 + 4,  2, "Backspace to return to the phone.");
        panel_present();
        return;   // s_active stays false; the restore_loop idle branch polls Backspace
    }
    Debug.printf("restore: tsb connected, IP=%s\n", WiFi.localIP().toString().c_str());
    snprintf(s_ssid, sizeof s_ssid, "%s", ssid);   // the AP we actually joined -> step 1 tells the user which WiFi
    restore_ui_status("switching to restore radio...");

    struct netif *nif = __getCYW43Netif();
    if (!nif) {
      Debug.println("restore: __getCYW43Netif NULL — abort");
      return;
    }

    // 2) Tear tsb down, rebuild the radio in POLL mode. CYW43::_netif (the RX
    //    target) is WiFi's static and survives deinit, so RX still lands after.
    cyw43_arch_deinit();
    Debug.println("restore: cyw43_arch_deinit (tsb gone)");
    delay(100);
    if (!poll_mode_bringup()) {
      Debug.println("restore: poll bring-up FAILED — abort");
      return;
    }
    Debug.println("restore: poll bring-up ok (radio poll-serviced)");
    delay(200);

    // 3) Re-join under poll (the association dropped with the driver). Pump until
    //    associated — RX flows into the persisted netif via the wrapped callback.
    cyw43_arch_enable_sta_mode();
    Debug.println("restore: re-joining under poll ...");
    cyw43_arch_wifi_connect_async(ssid, key, CYW43_AUTH_WPA2_AES_PSK);
    int ls = CYW43_LINK_DOWN;
    t0 = millis();
    while ((uint32_t)(millis() - t0) < 25000) {
        cyw43_arch_poll();
        ls = cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA);
        if (ls == CYW43_LINK_UP || ls == CYW43_LINK_JOIN)
          break;
        if (ls == CYW43_LINK_FAIL || ls == CYW43_LINK_NONET || ls == CYW43_LINK_BADAUTH)
          break;
        cyw43_arch_wait_for_work_until(make_timeout_time_ms(20));
    }
    if (ls != CYW43_LINK_UP && ls != CYW43_LINK_JOIN) {
        Debug.printf("restore: poll re-join FAILED ls=%d — abort\n", ls);
        return;
    }
    Debug.printf("restore: re-joined under poll (ls=%d), DHCP ...\n", ls);

    // 4) Refresh DHCP on the persisted netif, serviced by our polls.
    netif_set_link_up(nif);
    dhcp_start(nif);
    t0 = millis();
    bool got_ip = false;
    while ((uint32_t)(millis() - t0) < 20000) {
        cyw43_arch_poll();
        const ip4_addr_t *ip = netif_ip4_addr(nif);
        if (ip && !ip4_addr_isany_val(*ip)) {
          got_ip = true;
          break;
        }
        cyw43_arch_wait_for_work_until(make_timeout_time_ms(20));
    }
    if (!got_ip) {
      Debug.println("restore: poll DHCP no lease — abort");
      return;
    }
    snprintf(s_ipstr, sizeof s_ipstr, "%s", ipaddr_ntoa(netif_ip4_addr(nif)));
    Debug.printf("restore: WiFi up (poll). IP = %s\n", s_ipstr);

    struct tcp_pcb *srv = tcp_new();
    if (!srv || tcp_bind(srv, IP_ANY_TYPE, 80) != ERR_OK) {
        Debug.println("restore: bind :80 FAILED — abort");
        return;
    }
    srv = tcp_listen(srv);
    tcp_accept(srv, on_accept);

    if (s_fw_mode)
        Debug.printf("fw: listening on :80 (stages firmware to OTA region, %u bytes cap)\n",
                     (unsigned)ota_stage_capacity());
    else
        Debug.printf("restore: listening on :80 (writes the REAL FS, %u sectors)\n",
                     (unsigned)rawflash_sector_count(RAWFLASH_DEV_INTERNAL));

    // Access code: random 6-digit, shown here, required in the browser POST.
    snprintf(s_code, sizeof s_code, "%06lu", (unsigned long)(hal_rand() % 1000000u));
    Debug.printf("restore: access code = %s\n", s_code);

    // Draw the real screen directly (no LVGL) — the panel is already up from the
    // early "please wait" notice; IP/code/SSID are all known now.
    // Feed the chrome bar: SSID (restore knows it) + a one-off battery read (safe
    // here — restore runs no audio, so nothing races a bare ADC read). Time stays
    // 00:00 (no NTP in poll mode).
    extern volatile int batt_adc_raw;                  // audio.cpp
    strcpy(wifi_indicator_str, s_ssid);                // wifi indicator = the joined SSID
    analogReadResolution(12);
    batt_adc_raw = analogRead(A0);
    ui_set_title(s_fw_mode ? "Firmware Update" : "Restore");
    restore_draw_screen();
    restore_ui_status("Waiting for your computer to connect...");
    Debug.println("RB: UI up");

    s_active = true;
}

bool restore_active(void) { return s_active; }

// ---- firmware-update: page + streaming staging + verify --------------------
#define FW_PAGE_BYTES 256u                 // OTA_STAGING program granularity (SDK flash page)

static uint32_t    s_fw_clen   = 0;        // Content-Length of the body
static uint32_t    s_fw_rx     = 0;        // body bytes staged
static uint32_t    s_fw_pfill  = 0;        // bytes buffered in the current page
static uint8_t     s_fw_page[FW_PAGE_BYTES];
static blake2s_ctx s_fw_ctx;
static char        s_fw_expect[65] = {0};  // uploader's b2s hex (optional)
static bool        s_fw_started = false;
static bool        s_fw_bad     = false;   // staging write refused (body too big) / write error
static bool        s_fw_done    = false;
static bool        s_fw_apply_ready = false;   // staged + descriptor written -> Enter to apply
static bool        s_fw_auto_apply  = false;   // ?apply=1 -> apply without a keypress once ready

// Warm-reboot into the apply path: ota_apply_run() (first in setup) copies the
// staged image over the live firmware and resets. Distinct magic on the shared
// scratch reg (consumed already when firmware mode started, so it's free now).
static void fw_request_apply(void) {
    watchdog_hw->scratch[OTA_APPLY_SCRATCH_REG] = OTA_APPLY_MAGIC;
    WiFi.disconnect(true);
    delay(300);
    rp2040.reboot();   // does not return
}

// The apply goes dark for ~15 s (the copier runs before any UI is up), so warn the
// user clearly before the reboot — otherwise a blank screen reads as a crash.
static void fw_draw_applying(void) {
    panel_clear();
    int y = panel_height() / 2 - 30;
    panel_text_center(y, 3, "Applying firmware");                       y += 34;
    panel_text_center(y, 2, "The screen goes dark for about 15 sec.");  y += 22;
    panel_text_center(y, 2, "DO NOT power off. Do not panic.");
    panel_present();
}

// The upload-result screen: a readable status line, the 64-hex checksum split over
// two lines (compare it to the published one), and the Apply/Cancel prompt. Replaces
// the single tiny restore_ui_status line, which crammed the hash + prompt together.
static void fw_draw_result(const char *status, const char *hex, bool applyable) {
    panel_clear();
    int y = panel_height() / 2 - 56;
    panel_text_center(y, 3, status);                     y += 34;
    if (hex && hex[0]) {
        panel_text_center(y, 1, "Checksum (BLAKE2s):");  y += 18;
        char h1[33], h2[33];
        strncpy(h1, hex,      32); h1[32] = 0;
        strncpy(h2, hex + 32, 32); h2[32] = 0;
        panel_text_center(y, 2, h1);                     y += 22;
        panel_text_center(y, 2, h2);                     y += 30;
    }
    panel_text_center(y, 2, applyable ? "Enter = Apply     Backspace = Cancel"
                                   : "Backspace to return");
    panel_present();
}

static const char FW_PAGE_HTML[] =
    "<!doctype html><meta name=viewport content=\"width=device-width,initial-scale=1\">"
    "<title>Xyfr Firmware</title>"
    "<body style=\"font-family:sans-serif;max-width:32em;margin:2em auto;padding:0 1em\">"
    "<h2>Xyfr Firmware Update</h2>"
    "<div id=form>"
    "<p>Upload a firmware .bin. The device screen shows the staged checksum - compare "
    "it to the published one, then press Enter on the device to apply.</p>"
    "<p>Access code (on the device screen):<br><input id=c size=10 inputmode=numeric></p>"
    "<p><input type=file id=f></p>"
    "<p><button style=\"font-size:1.1em;padding:.7em 1.4em\" onclick=\"up()\">Upload &#8593;</button></p>"
    "<p id=s></p>"
    "</div>"
    "<div id=done style=\"display:none\">"
    "<h3>Upload complete</h3>"
    "<pre id=r style=\"white-space:pre-wrap;word-break:break-all;font-size:1.05em;"
    "background:#f4f4f4;padding:.8em;border-radius:6px\"></pre>"
    "<p>Compare the checksum above to the published one. If it matches, press "
    "<b>Enter on the device</b> to apply (or <b>Backspace</b> to cancel).</p>"
    "</div>"
    "<script>function st(t){document.getElementById('s').textContent=t;}\n"
    // Split the 64-hex checksum onto two 32-char lines (like the device screen) so
    // the two are easy to compare by eye. Presentation only — the device response
    // stays a clean single-line hex.
    "function fin(t){t=t.replace(/([0-9a-f]{32})([0-9a-f]{32})/i,'$1\\n$2');"
    "document.getElementById('r').textContent=t;"
    "document.getElementById('form').style.display='none';"
    "document.getElementById('done').style.display='block';}\n"
    "async function up(){var f=document.getElementById('f').files[0];"
    "if(!f){alert('Choose a .bin first.');return;}"
    "var code=document.getElementById('c').value.trim();"
    "if(!code){alert('Enter the access code on the device screen.');return;}"
    "st('Uploading '+f.size+' bytes\\u2026 watch the device screen.');"
    "try{var r=await fetch('/firmware?code='+encodeURIComponent(code),{method:'POST',body:f});"
    "fin(await r.text());}"
    "catch(e){fin('Upload finished - see the device screen.');}}"
    "</script></body>";

static void fw_serve_page(void) {
    char h[112];
    int n = snprintf(h, sizeof h,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: %u\r\n\r\n",
        (unsigned)(sizeof(FW_PAGE_HTML) - 1));
    tcp_send_str(h, n);
    tcp_send_str(FW_PAGE_HTML, sizeof(FW_PAGE_HTML) - 1);
}

static bool fw_is_hex(char c) { return (c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'); }

// Parse Content-Length + optional b2s from the header block, erase staging, begin the
// incremental hash. `hdr` is the NUL-terminated request line + headers.
static void fw_post_begin(const char *hdr) {
    s_fw_clen = 0;
    const char *cl = strstr(hdr, "Content-Length:");
    if (cl)
      s_fw_clen = (uint32_t)strtoul(cl + 15, NULL, 10);
    s_fw_expect[0] = 0;
    const char *bp = strstr(hdr, "b2s=");
    if (bp) {
        bp += 4;
        int i = 0;
        while (i < 64 && fw_is_hex(bp[i])) {
            char c = bp[i];
            if (c >= 'A' && c <= 'F')  // lowercase (snprintf %02x is lowercase)
              c += 32;
            s_fw_expect[i++] = c;
        }
        s_fw_expect[i] = 0;
    }
    s_fw_auto_apply = (strstr(hdr, "apply=1") != NULL);   // apply without a keypress once verified
    ota_stage_erase();
    blake2s_init(&s_fw_ctx, 32, NULL, 0);
    s_fw_rx = 0; s_fw_pfill = 0; s_fw_started = true; s_fw_bad = false; s_fw_done = false;
    Debug.printf("fw: receiving %u bytes (expect b2s=%s)\n",
                 (unsigned)s_fw_clen, s_fw_expect[0] ? s_fw_expect : "(none)");
}

// Drain body bytes from the ring into staging (page-buffered), hashing as we go.
static void fw_consume_body(void) {
    while (s_fw_started && !s_fw_bad && s_fw_rx < s_fw_clen && ring_count() > 0) {
        uint32_t rem_body = s_fw_clen - s_fw_rx;
        uint32_t rem_page = FW_PAGE_BYTES - s_fw_pfill;
        uint32_t want = ring_count();
        if (want > rem_page)
          want = rem_page;
        if (want > rem_body)
          want = rem_body;
        ring_pull(s_fw_page + s_fw_pfill, want);           // copies + opens the TCP window
        blake2s_update(&s_fw_ctx, s_fw_page + s_fw_pfill, want);
        s_fw_pfill += want;
        s_fw_rx    += want;
        bool last = (s_fw_rx == s_fw_clen);
        if (s_fw_pfill == FW_PAGE_BYTES || (last && s_fw_pfill > 0)) {
            uint32_t poff = s_fw_rx - s_fw_pfill;          // page-aligned staging offset
            if (s_fw_pfill < FW_PAGE_BYTES)
                memset(s_fw_page + s_fw_pfill, 0xFF, FW_PAGE_BYTES - s_fw_pfill);  // pad final page
            if (!ota_stage_program(poff, s_fw_page, FW_PAGE_BYTES)) {
                s_fw_bad = true;                            // past staging capacity (image too big)
                Debug.printf("fw: stage program refused at 0x%x — image too big for staging\n",
                             (unsigned)poff);
                break;
            }
            s_fw_pfill = 0;
        }
    }
}

// Report once the body is fully staged (or aborted). Verifies the hash vs b2s.
static void fw_maybe_complete(void) {
    bool finished = s_fw_started && !s_fw_bad && s_fw_clen > 0 && s_fw_rx >= s_fw_clen;
    bool aborted  = s_fw_bad || (s_closed && s_fw_started && s_fw_rx < s_fw_clen);
    if (!(finished || aborted) || s_fw_done)
      return;
    s_fw_done = true;
    // Worst case: "STAGED <10> bytes (unverified) - Enter to Apply\n" + 64 hex + NUL
    // (~118 B). Web uploads can't send b2s, so they hit the longer "unverified" status;
    // 110 truncated the last 5 hex chars off the browser's copy (device screen was fine).
    char body[160];
    char status[48] = {0};
    char hex[65]    = {0};
    if (finished) {
        uint8_t h[32]; blake2s_final(&s_fw_ctx, h);
        for (int i = 0; i < 32; i++)
          snprintf(hex + i * 2, 3, "%02x", h[i]);
        bool have_expect = s_fw_expect[0] != 0;
        bool match = have_expect && !strcmp(hex, s_fw_expect);   // both lowercase hex
        Debug.printf("fw: staged %u bytes blake2s=%s expect=%s -> %s\n",
                     (unsigned)s_fw_rx, hex, have_expect ? s_fw_expect : "(none)",
                     have_expect ? (match ? "MATCH" : "MISMATCH") : "unverified");
        // Applyable = a good stage: verified (b2s matched) OR unverified (no b2s, the
        // user compares the hash by eye). NOT a b2s MISMATCH (known-corrupt). Write the
        // descriptor so the apply path can re-verify + copy on reboot.
        bool applyable = !have_expect || match;
        if (applyable && ota_stage_finalize(s_fw_rx, h)) {
            s_fw_apply_ready = true;
            snprintf(status, sizeof status, have_expect ? "VERIFIED %u bytes"
                                                        : "STAGED %u bytes (unverified)", (unsigned)s_fw_rx);
            snprintf(body, sizeof body, "%s - Enter to Apply\n%s", status, hex);
        } else if (have_expect && !match) {
            snprintf(status, sizeof status, "CHECKSUM MISMATCH");
            snprintf(body, sizeof body, "CHECKSUM MISMATCH - not applyable\ngot %s", hex);
        } else {
            snprintf(status, sizeof status, "Stage failed");
            snprintf(body, sizeof body, "STAGED %u bytes (finalize failed)\n%s", (unsigned)s_fw_rx, hex);
        }
        restore_draw_progress(100);   // snap the bar to full (it froze at the last live tick)
    } else {
        snprintf(status, sizeof status, "Upload aborted");
        snprintf(body, sizeof body, "ERROR: upload aborted (%u/%u bytes)",
                 (unsigned)s_fw_rx, (unsigned)s_fw_clen);
    }
    fw_draw_result(status, hex, s_fw_apply_ready);
    if (!s_resp_sent) {
      http_respond(body);
      s_resp_sent = true;
    }
    http_close();
}

void restore_loop(void) {
    // Firmware update / restore is a long, unattended, must-not-be-interrupted
    // operation with no keystrokes for minutes — but keyboard_scan() below runs
    // display_pump(), which would blank the backlight display_timeout ms after the
    // last key. Kick the timer every iteration so the screen (checksum, progress,
    // Enter/Backspace prompts, and the boot-failed reason) stays lit throughout.
    display_kick();

    // If restore_boot aborted (WiFi/poll failure), the radio may be down — don't
    // poll a dead context. Just heartbeat; a power cycle returns to the phone.
    if (!s_active) {
        // Boot/WiFi failed — the screen shows why. Let Backspace return to the phone.
        keyboard_scan();
        // The prompt says Backspace, so honour Backspace (ESC kept as an alias —
        // this branch once listened for ESC alone, making the prompt a lie).
        int k = keyboard_read();
        if (k == VIEW_K_BACKSPACE || k == VIEW_K_ESC) {
            watchdog_hw->scratch[RESTORE_FLAG_REG] = 0;
            panel_clear(); panel_text_center(panel_height() / 2, 2, LV_SYMBOL_LOOP "  Returning to phone..."); panel_present();
            delay(300); rp2040.reboot();
        }
        static uint32_t el = 0;
        if ((uint32_t)(millis() - el) >= 2000) {
          el = millis();
          Debug.println("[restore idle] boot failed — Backspace/power-cycle to return");
        }
        return;
    }
    cyw43_arch_poll();
    static uint32_t s_polls = 0;   // poll rate since the last heartbeat (diagnostics)
    s_polls++;

    // Backspace on the device keyboard exits restore mode back to the phone (poll
    // the matrix directly — there is no LVGL indev in restore mode). In firmware mode,
    // Enter APPLIES a staged+ready image (copy staged->live on the next boot).
    keyboard_scan();
    uint32_t kc = keyboard_read();
    if (kc == VIEW_K_ESC) {   // Backspace = the "back/exit" gesture (mapped to ESC, not '<')
        watchdog_hw->scratch[RESTORE_FLAG_REG] = 0;   // clear the flag -> next boot is normal
        panel_clear();
        panel_text_center(panel_height() / 2, 2, LV_SYMBOL_LOOP "  Returning to phone...");
        panel_present();
        delay(300);
        rp2040.reboot();
    }
    if (s_fw_mode && s_fw_apply_ready && kc == VIEW_K_ENTER) {
        fw_draw_applying();
        fw_request_apply();   // does not return
    }

    // 0) HTTP request line + headers (once per connection). GET -> serve the page
    //    and close; POST -> check the access code, then the body is the backup.
    if (!s_http_done && !s_stream_err && s_client) {
        int he = ring_find_header_end();
        if (he >= 0) {
            // Copy the WHOLE header block (request line + headers) — firmware mode
            // needs Content-Length from a header line, not just the request line.
            char hdr[512];
            uint32_t hl = ((uint32_t)he < sizeof(hdr) - 1) ? (uint32_t)he : sizeof(hdr) - 1;
            for (uint32_t i = 0; i < hl; i++)
              hdr[i] = s_ring[(s_tail + i) % RING_BYTES];
            hdr[hl] = 0;
            // Request line = the first line (for method + ?code=/?b2s= parse).
            char reqline[200];
            { int n = 0; while (n < (int)sizeof(reqline) - 1 && hdr[n] && hdr[n] != '\r' && hdr[n] != '\n') { reqline[n] = hdr[n]; n++; } reqline[n] = 0; }
            char meth[8] = {0};
            for (int i = 0; i < 7 && reqline[i] && reqline[i] != ' '; i++)
              meth[i] = reqline[i];
            ring_discard((uint32_t)he + 4);   // consume request line + headers + blank line

            if (!strcmp(meth, "GET")) {
                if (s_fw_mode)
                  fw_serve_page();
                else
                  http_serve_page();
                http_close();                 // browser reconnects with the POST
            } else if (!strcmp(meth, "POST")) {
                // Access-code gate: require ?code=<the code shown on screen>.
                char *cp = strstr(reqline, "code=");
                bool code_ok = cp && s_code[0] && !strncmp(cp + 5, s_code, strlen(s_code))
                                  && (cp[5 + strlen(s_code)] == 0 || cp[5 + strlen(s_code)] == '&'
                                      || cp[5 + strlen(s_code)] == ' ');
                if (!code_ok) {
                    Debug.println("net: POST rejected — bad/missing access code");
                    http_status_respond("403 Forbidden", "wrong access code");
                    http_close();
                    restore_ui_status("wrong code — re-check the device screen");
                } else if (s_fw_mode) {
                    s_http_done = true;        // body feeds the firmware staging pipeline
                    fw_post_begin(hdr);        // parse Content-Length + b2s, erase staging, start hash
                    restore_ui_status("code OK — receiving firmware...");
                } else {
                    s_http_done = true;        // body (backup binary) feeds the AEAD pipeline
                    Debug.println("restore: POST accepted — receiving backup body");
                    restore_ui_status("code OK — receiving backup...");
                }
            } else {
                s_stream_err = true;
            }
        } else if (ring_count() > 3072) {     // headers absurdly long => not HTTP
            s_stream_err = true;
        }
    }

    // Firmware mode: stream the body into staging + hash (replaces the restore
    // header/record pipeline below, which is guarded off).
    if (s_fw_mode) {
        if (s_http_done)
          fw_consume_body();
        fw_maybe_complete();
        // Auto-apply (?apply=1): once staged+ready, wait a few polls so the HTTP
        // response flushes to the uploader, then apply (does not return).
        if (s_fw_auto_apply && s_fw_apply_ready) {
            static int s_apply_delay = 0;
            if (++s_apply_delay > 25) {
                fw_draw_applying();
                fw_request_apply();   // does not return
            }
        }
    }

    // 1) header (once) — parse + validate magic/format/layout. (RESTORE only.)
    if (!s_fw_mode && s_http_done && !s_hdr_done && !s_stream_err && ring_count() >= sizeof(bk_header)) {
        ring_pull(&s_hdr, sizeof(bk_header));
        if (memcmp(s_hdr.magic, BK_MAGIC, 8) != 0) {
            Debug.println("restore: NOT an Xyfr backup (bad magic)"); s_stream_err = true;
        } else if (s_hdr.format_version != BK_FORMAT_VERSION) {
            Debug.println("restore: unknown backup format"); s_stream_err = true;
        } else if (s_hdr.layout_version != BK_LAYOUT_VERSION) {
            Debug.println("restore: incompatible layout"); s_stream_err = true;
        } else {
            s_hdr_done = true;
            Debug.printf("restore: header OK — sector_count=%u (writing REAL FS)\n",
                         (unsigned)s_hdr.sector_count);
        }
    }

    // 2) records — decrypt+verify each 4112-byte record.
    while (s_hdr_done && s_rec_idx < s_hdr.sector_count && ring_count() >= BK_RECORD_BYTES) {
        process_one_record();
        if ((s_rec_idx & 0x1f) == 0)
            Debug.printf("restore: verified %u/%u (failed %u)\n",
                         (unsigned)s_verified, (unsigned)s_hdr.sector_count, (unsigned)s_failed);
    }

    // Live progress + status (throttled), drawn directly.
    static uint32_t ui_last = 0;
    if ((uint32_t)(millis() - ui_last) >= 200) {
        ui_last = millis();
        if (s_fw_mode) {
            if (s_fw_started && s_fw_clen && !s_fw_done) {
                int pct = (int)((uint64_t)s_fw_rx * 100 / s_fw_clen);
                if (pct > 100)
                  pct = 100;
                restore_draw_progress(pct);
                char b[64];
                snprintf(b, sizeof b, "Receiving firmware: %u / %u bytes",
                         (unsigned)s_fw_rx, (unsigned)s_fw_clen);
                restore_ui_status(b);
            }
        } else {
            uint32_t total = s_hdr_done ? s_hdr.sector_count : 0;
            if (total) {
                int pct = (int)((uint64_t)s_rec_idx * 100 / total);
                if (pct > 100)
                  pct = 100;
                restore_draw_progress(pct);
            }
            if (s_hdr_done) {
                char b[72];
                snprintf(b, sizeof b, "Restoring: %u/%u  (%u failed)",
                         (unsigned)s_verified, (unsigned)s_hdr.sector_count, (unsigned)s_failed);
                restore_ui_status(b);
            } else if (s_stream_err) {
                restore_ui_status("ERROR: not a valid backup");
            }
        }
    }

    // 3) completion — reply to the POST and close. (RESTORE only; firmware completes
    //    in fw_maybe_complete above.)
    bool finished = !s_fw_mode && s_http_done && s_hdr_done && s_rec_idx >= s_hdr.sector_count;
    bool aborted  = !s_fw_mode && s_closed && (s_stream_err || !s_hdr_done) && s_http_done;
    if ((finished || aborted) && !s_done) {
        s_done = true;
        char b[80];
        if (finished) {
            Debug.printf("\n*** RESTORE VERIFY DONE: %u/%u verified, %u failed, NO WEDGE ***\n",
                         (unsigned)s_verified, (unsigned)s_hdr.sector_count, (unsigned)s_failed);
            snprintf(b, sizeof b, (s_failed == 0) ? "VERIFIED %u/%u OK" : "DONE %u/%u (%u FAILED)",
                     (unsigned)s_verified, (unsigned)s_hdr.sector_count, (unsigned)s_failed);
        } else {
            snprintf(b, sizeof b, "ERROR: invalid/short backup");
        }
        if (!s_resp_sent) {
          http_respond(b);
          s_resp_sent = true;
        }
        if (finished)
          restore_draw_progress(100);
        restore_ui_status(b);
        http_close();

        // After a CLEAN real restore: clear the restore flag, show a countdown,
        // wait ~5 s (lets the HTTP reply reach the browser), then reboot NORMALLY
        // into the freshly restored image.
        if (finished && s_failed == 0) {
            watchdog_hw->scratch[RESTORE_FLAG_REG] = 0;   // ensure next boot is normal
            for (int s = 5; s > 0; s--) {
                char m[48]; snprintf(m, sizeof m, "Restore complete - rebooting in %d", s); restore_ui_status(m);
                delay(1000);
            }
            Debug.println("restore: rebooting into restored image");
            rp2040.reboot();   // normal warm reboot (flag cleared)
        }
    }

    ui_tick();   // self-throttled — the pump owns its own repaint cadence

    static uint32_t last = 0;
    if ((uint32_t)(millis() - last) >= 2000) {
        last = millis();
        // link legend: 3=UP 2=NOIP 1=JOIN 0=DOWN -1=FAIL -2=NONET -3=BADAUTH.
        // If link<3 in steady state, the association dropped after DHCP (device-side);
        // if link==3 but the LAN still can't ARP us, frames aren't reaching the radio
        // (AP/client isolation, network-side). polls = cyw43_arch_poll() calls/2s.
        int ls = cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA);
        if (s_fw_mode)
            Debug.printf("[fw alive] code=%s ip=%s rx=%u/%u link=%d polls=%u\n",
                         s_code, s_ipstr, (unsigned)s_fw_rx, (unsigned)s_fw_clen, ls, (unsigned)s_polls);
        else
            Debug.printf("[restore alive] code=%s ip=%s rx=%u idx=%u verified=%u failed=%u\n",
                         s_code, s_ipstr, (unsigned)s_total_rx, (unsigned)s_rec_idx,
                         (unsigned)s_verified, (unsigned)s_failed);
        s_polls = 0;
    }
    cyw43_arch_wait_for_work_until(make_timeout_time_ms(20));
}
