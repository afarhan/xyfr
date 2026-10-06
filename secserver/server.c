#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <ctype.h>
#include "net.h"
#include "wg.h"
#include "db.h"
#include "relay_tunnel.h"
#include "logstamp.h"

#define MAX_RELAYS 128

static char str_server_ip[100];
static uint8_t my_static_public[KEY_LEN];

// Verbose per-packet tunnel tracing (off by default; error paths always print).
int tunnel_debug = 0;

// Admission context threaded to validate_public_key via peer_handshake_request_
// process's void *ctx: a DIRECT msg1 is a relay's own login (accept only
// authorized relays); a msg1 unwrapped from a relay's tunnel is a client login
// (accept any valid subscriber).
enum admit_ctx {
  ADMIT_DIRECT_RELAY,
  ADMIT_TUNNELED_CLIENT
};

// A relay's retained wg session. Direct relay logins land here; the kept
// receiving_key + replay window let us rx_data the tunneled client traffic
// that follows. Rebuilt from scratch on restart — relays re-login within
// REKEY_AFTER_TIME, so the fleet self-heals in ~2 min.
struct relay {
  struct peer peer;      // the live relay<->server session
  uint32_t partkey;
  uint32_t ip;
  uint16_t port;
  int      in_use;
  time_t   last_seen;
};
static struct relay relays[MAX_RELAYS];

// Authorized relay static public keys, loaded from server.conf `relay_key=` lines
// at boot. Only these may complete a DIRECT login (and thus tunnel client traffic).
static uint8_t relay_authz[MAX_RELAYS][KEY_LEN];
static int     relay_authz_count = 0;

static int is_authorized_relay(const uint8_t *pub){
  int i;
  for (i = 0; i < relay_authz_count; i++)
    if (memcmp(relay_authz[i], pub, KEY_LEN) == 0)
      return 1;
  return 0;
}

static struct relay *relay_find_by_ep(uint32_t ip, uint16_t port){
  int i;
  for (i = 0; i < MAX_RELAYS; i++)
    if (relays[i].in_use && relays[i].ip == ip && relays[i].port == port)
      return &relays[i];
  return NULL;
}

// Find the slot for this relay's partkey (a re-login updates it in place) or
// claim a free one. NULL only if the table is full.
static struct relay *relay_upsert(uint32_t partkey){
  int i, freei = -1;
  for (i = 0; i < MAX_RELAYS; i++){
    if (relays[i].in_use && relays[i].partkey == partkey)
      return &relays[i];
    if (!relays[i].in_use && freei < 0)
      freei = i;
  }
  if (freei < 0)
    return NULL;
  relays[freei].in_use  = 1;
  relays[freei].partkey = partkey;
  return &relays[freei];
}

static void print_key(const uint8_t *key, int length){
    while(length--)
        printf("%02x", *key++);
    printf("\n");
}

void delay (unsigned int howLong){
  struct timespec sleeper, dummy ;

  sleeper.tv_sec  = (time_t)(howLong / 1000) ;
  sleeper.tv_nsec = (long)(howLong % 1000) * 1000000 ;

  nanosleep (&sleeper, &dummy) ;
}

time_t get_current_time_seconds(){
    return time(NULL);
}

// Admission gate. ctx picks the policy (see enum admit_ctx): a DIRECT msg1 must
// be an authorized relay; a TUNNELED inner msg1 must be a valid subscriber. A
// NULL ctx defaults to the subscriber check (conservative).
int validate_public_key(const uint8_t *public_key, void *ctx){
  // Check for all-zero public key
  bool all_zero = true;
  int i;
  for (i = 0; i < KEY_LEN; i++) {
    if (public_key[i] != 0) {
      all_zero = false;
      break;
    }
  }
  if (all_zero) {
    return 0; // Invalid key
  }

  enum admit_ctx mode = ctx ? *(enum admit_ctx *)ctx : ADMIT_TUNNELED_CLIENT;
  if (mode == ADMIT_DIRECT_RELAY)
    return is_authorized_relay(public_key);   // only authorized relays log in directly

  // Tunneled client login: existing subscriber check.
  if(!db_validate_user(public_key))
    return 1; // Valid key
  return 0;
}

// Read config file (server.conf) to set key_hex and str_server_ip
// Format: key_hex=<hex_string> and server_ip=<ip_address>
static void read_config(char *key_hex, char *server_ip) {
    FILE *fp = fopen("server.conf", "r");
    char line[256];
    char key[32], value[128];
    
    // No built-in defaults: the key and the address come from server.conf (or
    // the command line), never from the source. See server.conf.example.
    key_hex[0] = '\0';
    server_ip[0] = '\0';
    
    if (!fp) {
        printf("server.conf not found\n");
        return;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n') continue;
        
        // Parse key=value
        if (sscanf(line, "%31[^=]=%127s", key, value) == 2) {
            if (strcmp(key, "key_hex") == 0) {
                strncpy(key_hex, value, 99);
                key_hex[99] = '\0';
                printf("Loaded key_hex from config\n");
            } else if (strcmp(key, "server_ip") == 0) {
                strncpy(server_ip, value, 99);
                server_ip[99] = '\0';
                printf("Loaded server_ip from config\n");
            } else if (strcmp(key, "relay_key") == 0) {
                // An authorized relay's static public key (64 hex). Repeat the
                // line per relay. Only these may complete a direct login and
                // tunnel client traffic.
                if (relay_authz_count < MAX_RELAYS && strlen(value) >= (size_t)(KEY_LEN * 2)) {
                    hex2bytes(value, relay_authz[relay_authz_count], KEY_LEN * 2);
                    relay_authz_count++;
                    printf("Authorized relay key #%d loaded\n", relay_authz_count);
                } else {
                    printf("relay_key ignored (table full or malformed)\n");
                }
            }
        }
    }
    fclose(fp);
}


// ---- direct path: a relay's own login -------------------------------------
// A DIRECT msg1 is only ever an authorized relay logging in. On success we
// RETAIN the session in the relay table (a re-login rekeys it in place) so the
// tunneled client traffic that follows can be decrypted against it.
static void handle_relay_login(struct msg1 *m1, uint32_t ip, uint16_t port, int socket){
  uint8_t src[6];
  memcpy(src, &ip, 4);
  memcpy(src + 4, &port, 2);
  enum admit_ctx mode = ADMIT_DIRECT_RELAY;
  struct peer a;
  int e = peer_handshake_request_process(&a, m1, src, sizeof(src), &mode);
  if (e == 0){
    uint32_t pk = get_part_key(a.remote_static_public);
    struct relay *rl = relay_upsert(pk);
    if (!rl){
      printf("relay table full — dropping relay %08x\n", pk);
      return;
    }
    struct msg2 m2;
    peer_response_generate(&a, &m2);
    a.src_ip = ip; a.src_port = port;
    rl->peer = a;                       // retain the finalized session (rekey-in-place)
    rl->ip = ip; rl->port = port;
    rl->last_seen = time(NULL);
    udp_write(socket, &m2, sizeof(m2), ip, port);
    printf("relay %08x logged in from %s:%u\n", pk, ip2string(ip), port);
  } else if (e == REQUEST_MAC2_REQUIRED){
    struct msg3 m3;
    peer_create_cookie_reply(&m3, my_static_public, m1->mac1, m1->sender_index, m1->session_id,
                             src, sizeof(src));
    udp_write(socket, &m3, sizeof(m3), ip, port);
  }
  // else: not an authorized relay / bad handshake — drop silently.
}

// ---- tunneled path: client control packets unwrapped from a relay ----------
// ep_ip/ep_port is the RELAY's endpoint: the client is reachable through it,
// so that's what we record in the DB and where a peer lookup will point.
// Each handler writes its reply datagram into `reply` and returns 1, or 0 for
// "no reply". The caller wraps the reply back into the relay's tunnel.

static int handle_client_login(struct msg1 *m1, uint32_t ep_ip, uint16_t ep_port,
                               uint8_t *reply, int *reply_len){
  uint8_t src[6];
  memcpy(src, &ep_ip, 4);
  memcpy(src + 4, &ep_port, 2);
  enum admit_ctx mode = ADMIT_TUNNELED_CLIENT;
  struct peer a;
  int e = peer_handshake_request_process(&a, m1, src, sizeof(src), &mode);
  if (e != 0)
    return 0;                          // relay already ran the cookie gate; no server-side cookie
  struct msg2 *m2 = (struct msg2 *)reply;
  peer_response_generate(&a, m2);
  *reply_len = sizeof(struct msg2);
  // Hand the relay B's full static public key alongside the login reply, so it
  // can issue a return-routability cookie on peer calls to B (THREAT_MODEL J-4).
  // Appended AFTER the msg2 in the relay<->server tunnel framing -- NOT a field
  // inside msg2 -- so no handshake struct changes.
  memcpy(reply + sizeof(struct msg2), a.remote_static_public, KEY_LEN);
  *reply_len += KEY_LEN;
  a.src_ip = ep_ip; a.src_port = ep_port;
  db_update_user(a.remote_static_public, ep_ip, ep_port);
  return 1;
}

static int handle_activation(struct msg1 *m1, uint32_t ep_ip, uint16_t ep_port,
                             uint8_t *reply, int *reply_len){
  char activation_code[17];
  memcpy(activation_code, m1->mac2, 16);
  activation_code[16] = '\0';
  memset(m1->mac2, 0, COOKIE_LEN);

  bool code_ok = true;
  int i;
  for (i = 0; i < 16; i++){
    if (activation_code[i] < 'a' || activation_code[i] > 'z'){ code_ok = false; break; }
  }

  // Cheap pre-DH gate (THREAT_MODEL M-5 / J-7 amplifier). Grade the code with
  // one indexed DB probe BEFORE the expensive Curve25519 DH in
  // peer_handshake_extract_static. A malformed, unknown, or SPENT code is
  // rejected with no DH -- so a flood of random codes costs a B-tree lookup, not
  // a scalar-mult, AND a replayed already-used code (bought or sniffed) grants
  // no DH either: each code is worth one DH and is consumed by that activation.
  // Only an unused code (or a just-used one inside the retransmit window, i.e. a
  // legitimate lost-reply retry) falls through to the DH + db_activate_user.
  uint8_t reason = 0;
  if (!code_ok) {
    reason = ACTIVATION_REASON_UNKNOWN_CODE;
  } else {
    int valid = db_code_valid(activation_code);
    if (valid == 0)      reason = ACTIVATION_REASON_UNKNOWN_CODE;
    else if (valid == 2) reason = ACTIVATION_REASON_CODE_USED;
    else if (valid < 0)  reason = ACTIVATION_REASON_INTERNAL;
  }

  uint8_t new_user_key[KEY_LEN];
  if (reason == 0) {
    int extract = peer_handshake_extract_static(m1, new_user_key);
    if (extract != 0) {
      reason = ACTIVATION_REASON_INTERNAL;
    } else {
      int rc = db_activate_user(new_user_key, activation_code, m1->session_id, time(NULL) + 31557600);
      if (rc == 1)        reason = 0;
      else if (rc == 2)   reason = ACTIVATION_REASON_UNKNOWN_CODE;   // no such code (typo/race)
      else if (rc == 0)   reason = ACTIVATION_REASON_CODE_USED;      // real code, already spent
      else                reason = ACTIVATION_REASON_INTERNAL;
    }
  }

  if (reason != 0){
    struct msg_activation_failed *mf = (struct msg_activation_failed *)reply;
    memset(mf, 0, sizeof(*mf));
    mf->msg_type = MSG_ACTIVATION_FAILED;
    mf->reason = reason;
    mf->session_id = m1->session_id;
    mf->receiver_index = m1->sender_index;
    *reply_len = sizeof(*mf);
    return 1;
  }

  // User is in the DB now; run the standard handshake and reply msg2.
  uint8_t src[6];
  memcpy(src, &ep_ip, 4);
  memcpy(src + 4, &ep_port, 2);
  enum admit_ctx mode = ADMIT_TUNNELED_CLIENT;
  struct peer a;
  int e = peer_handshake_request_process(&a, m1, src, sizeof(src), &mode);
  if (e != 0)
    return 0;
  struct msg2 *m2 = (struct msg2 *)reply;
  peer_response_generate(&a, m2);
  *reply_len = sizeof(struct msg2);
  // Hand the relay B's full static public key alongside the login reply, so it
  // can issue a return-routability cookie on peer calls to B (THREAT_MODEL J-4).
  // Appended AFTER the msg2 in the relay<->server tunnel framing -- NOT a field
  // inside msg2 -- so no handshake struct changes.
  memcpy(reply + sizeof(struct msg2), a.remote_static_public, KEY_LEN);
  *reply_len += KEY_LEN;
  a.src_ip = ep_ip; a.src_port = ep_port;
  db_update_user(a.remote_static_public, ep_ip, ep_port);
  return 1;
}

static int handle_lookup(const uint8_t *pkt, int len, uint8_t *reply, int *reply_len){
  if (len != (int)sizeof(struct msg_contact_request))
    return 0;
  struct query q;
  memset(&q, 0, sizeof(q));
  uint8_t payload[QUERY_REQUEST_PAYLOAD_LEN];
  size_t  payload_len = 0;
  int rc = peer_query_process(&q, pkt, len, NULL, 0, payload, &payload_len);
  if (rc != REQUEST_SUCCESS)
    return 0;

  uint32_t partkey = ((uint32_t)payload[0] << 24) | ((uint32_t)payload[1] << 16) |
                     ((uint32_t)payload[2] <<  8) |  (uint32_t)payload[3];

  uint8_t resp[QUERY_RESPONSE_PAYLOAD_LEN];
  memset(resp, 0, sizeof(resp));
  uint32_t relay_ip4 = 0;
  uint16_t relay_port = 0;
  if (db_get_endpoint_by_partkey(partkey, resp + 1, &relay_ip4, &relay_port)) {
    resp[0] = 0;
    memcpy(resp + 1 + KEY_LEN, &relay_ip4, sizeof(relay_ip4));
    resp[1 + KEY_LEN + 4] = (uint8_t)(relay_port >> 8);
    resp[1 + KEY_LEN + 5] = (uint8_t)(relay_port & 0xff);
  } else {
    resp[0] = 1;
  }

  const struct msg_contact_request *m7 = (const struct msg_contact_request *)pkt;
  struct msg_contact_response *m8 = (struct msg_contact_response *)reply;
  peer_query_generate(&q, MSG_CONTACT_RESPONSE, m7->session_id,
                      get_part_key(my_static_public), resp, sizeof(resp), m8);
  *reply_len = sizeof(struct msg_contact_response);
  return 1;
}

// A msg4 from an authenticated relay: unwrap, process the inner client packet,
// and wrap the reply back into the same relay session.
static void handle_tunnel(struct msg4 *m4, int r, uint32_t ip, uint16_t port, int socket){
  struct relay *rl = relay_find_by_ep(ip, port);
  if (!rl){
    printf("tunnel: msg4 from %s:%u with no relay session; dropping\n", ip2string(ip), port);
    return;                            // only authenticated relays tunnel to us
  }

  uint8_t plain[MAX_PACKET_LEN];
  int pl = rx_data(plain, &rl->peer, m4, r);
  if (pl <= 0){
    printf("tunnel: rx_data failed (%d) from relay %08x %s:%u\n", pl, rl->partkey, ip2string(ip), port);
    return;
  }
  const uint8_t *inner; size_t ilen;
  if (!relay_tunnel_unwrap(plain, (size_t)pl, &inner, &ilen) || ilen < 1){
    printf("tunnel: unwrap failed (plain_len=%d) from relay %08x\n", pl, rl->partkey);
    return;
  }
  rl->last_seen = time(NULL);
  if (tunnel_debug)
    printf("tunnel: relay %08x inner type=%u len=%zu\n", rl->partkey, inner[0], ilen);

  // Copy the inner datagram out — handlers mutate it (e.g. zero mac2).
  uint8_t innerbuf[MAX_PACKET_LEN];
  if (ilen > sizeof(innerbuf))
    return;
  memcpy(innerbuf, inner, ilen);

  uint8_t reply[MAX_PACKET_LEN];
  int reply_len = 0;
  int have_reply = 0;
  switch (innerbuf[0]){
    case MSG_REQUEST_CONNECT:
      if (ilen == sizeof(struct msg1))
        have_reply = handle_client_login((struct msg1 *)innerbuf, ip, port, reply, &reply_len);
      break;
    case MSG_REQUEST_ACTIVATE:
      if (ilen == sizeof(struct msg1))
        have_reply = handle_activation((struct msg1 *)innerbuf, ip, port, reply, &reply_len);
      break;
    case MSG_CONTACT_REQUEST:
      have_reply = handle_lookup(innerbuf, (int)ilen, reply, &reply_len);
      break;
    default:
      break;
  }

  if (have_reply && reply_len > 0){
    uint8_t wbuf[MAX_PACKET_LEN];
    size_t wl = relay_tunnel_wrap(wbuf, sizeof(wbuf), reply, (size_t)reply_len);
    if (wl){
      uint8_t m4buf[MAX_PACKET_LEN];
      int n = tx_data((struct msg4 *)m4buf, &rl->peer, wbuf, wl);
      if (n > 0){
        udp_write(socket, m4buf, n, ip, port);
        if (tunnel_debug)
          printf("tunnel: wrapped reply type=%u (%d B) -> relay %08x\n", reply[0], reply_len, rl->partkey);
      }
    }
  } else if (tunnel_debug){
    printf("tunnel: no reply for inner type=%u\n", innerbuf[0]);
  }
}

void loop(){
    int socket = udp_socket_open(str_server_ip, PUBLIC_PORT);
    uint32_t ip;
    uint16_t port;
    uint8_t buff_in[MAX_PACKET_LEN];

  db_init();

  while(1){
    int r = udp_read(socket, buff_in, sizeof(buff_in), &ip, &port);
    if (r <= 0)
      continue;
    
    //printf("loop: received %d bytes from %s:%u\n", r, ip2string(ip), port);
    switch(buff_in[0]){
      case MSG_REQUEST_CONNECT:
        // A DIRECT msg1 is only a relay's own login. Client logins now arrive
        // TUNNELED (case MSG_DATA); validate_public_key(ADMIT_DIRECT_RELAY)
        // rejects anything that isn't an authorized relay.
        if (r != sizeof(struct msg1))     // reject short/oversized msg1 (M-3)
          break;
        handle_relay_login((struct msg1 *)buff_in, ip, port, socket);
        break;

      case MSG_DATA:
        // The only msg4 the server accepts is a relay tunnel. Find the relay
        // by endpoint, decrypt against its retained session, dispatch the
        // inner client packet, and wrap the reply back. (No more decrypting
        // against an uninitialized peer — closes the old M-2 footgun.)
        if (r < (int)(sizeof(struct msg4) + AUTHTAG_LEN))
          break;
        handle_tunnel((struct msg4 *)buff_in, r, ip, port, socket);
        break;

      // Client control traffic (login / activation / lookup) is accepted ONLY
      // tunneled through an authenticated relay now, so a DIRECT msg5 / msg7 —
      // and a client msg2 / msg3 — are dropped.
      default:
        break;
    }
  }
}

int main (int argc, char **argv){
  char key_hex[100];

  logstamp_install();   // timestamp every stdout/stderr line from here on

  read_config(key_hex, str_server_ip);

  // Command-line arguments override config file
  if (argc >= 3){
      strncpy(str_server_ip, argv[1], 99);
      str_server_ip[99] = '\0';
      strncpy(key_hex, argv[2], 99);
      key_hex[99] = '\0';
      printf("Using command-line args: ip=%s\n", str_server_ip);
  }

  if (strlen(key_hex) != KEY_LEN * 2 || !str_server_ip[0]) {
      fprintf(stderr, "server: key_hex (%d hex chars) and server_ip must be set in server.conf; "
                      "copy server.conf.example\n", KEY_LEN * 2);
      return 1;
  }

  uint8_t my_private_key[KEY_LEN];
  hex2bytes(key_hex, my_private_key, KEY_LEN * 2); 
    
  //generating public key
  wireguard_init(my_private_key);
  wireguard_ask_mac2(false);
  wireguard_my_static_public(my_static_public);
  printf("server static public:"); print_key(my_static_public, KEY_LEN);

  loop(); //spin many loops

  return 0;
}

