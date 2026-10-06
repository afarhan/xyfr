#include "debug.h"
#include <Arduino.h>
#include <WiFi.h>
#include "bootstrap.h"
#include "device_record.h"
#include "ui.h"
#include "DoHResolver.h"

#define BOOTSTRAP_HOSTNAME "config.xyfr.net"

// Parse "v=1;ips=A.B.C.D:PORT,A.B.C.D:PORT,...;exp=...;" into device_record.endpoints.
static int parse_endpoints(const char* txt) {
	memset(device_record.endpoints, 0, sizeof(device_record.endpoints));
	const char* p = strstr(txt, "ips=");
	if (!p)
		return 0;
	p += 4;
	int n = 0;
	while (n < MAX_SERVER_ENDPOINTS) {
		uint32_t ip = 0;
		for (int oct = 0; oct < 4; oct++) {
			if (oct > 0) {
				if (*p != '.')
					return n;
				p++;
			}
			char* next;
			unsigned long v = strtoul(p, &next, 10);
			if (next == p || v > 255)
				return n;
			ip |= (v & 0xFF) << (oct * 8);
			p = next;
		}
		if (*p != ':')
			return n;
		p++;
		char* next;
		unsigned long port = strtoul(p, &next, 10);
		if (next == p || port == 0 || port > 65535)
			return n;
		device_record.endpoints[n].ip4  = ip;
		device_record.endpoints[n].port = (uint16_t)port;
		n++;
		p = next;
		if (*p != ',')
			break;
		p++;
	}
	return n;
}

// Parse a single manually-typed "A.B.C.D" or "A.B.C.D:PORT" into ip4 (octet-0 in
// the low byte, matching struct server_endpoint) + port. If no ":PORT" is given,
// *port is left untouched so the caller can supply a default. Rejects out-of-range
// octets/port and trailing junk. Same octet logic as parse_endpoints above.
bool parse_ip_port(const char *s, uint32_t *ip4, uint16_t *port) {
	if (!s)
		return false;
	while (*s == ' ')
		s++;
	uint32_t ip = 0;
	const char *p = s;
	for (int oct = 0; oct < 4; oct++) {
		if (oct > 0) {
			if (*p != '.')
				return false;
			p++;
		}
		char *next;
		unsigned long v = strtoul(p, &next, 10);
		if (next == p || v > 255)
			return false;
		ip |= (v & 0xFF) << (oct * 8);
		p = next;
	}
	if (*p == ':') {
		p++;
		char *next;
		unsigned long pt = strtoul(p, &next, 10);
		if (next == p || pt == 0 || pt > 65535)
			return false;
		*port = (uint16_t)pt;
		p = next;
	}
	while (*p == ' ')
		p++;
	if (*p != 0)  // trailing junk after the address
		return false;
	*ip4 = ip;
	return true;
}

bool fetch_new_ip(){
	if (WiFi.status() != WL_CONNECTED)
		return false;

	DoHResolver resolver;
	char buff[MAX_DOH_ENDPOINTS];
	if (resolver.resolveTXT(BOOTSTRAP_HOSTNAME, buff, sizeof(buff)) != DoHResolver::OK)
		return false;

	strncpy(device_record.doh_endpoints, buff, sizeof(device_record.doh_endpoints) - 1);
	device_record.doh_endpoints[sizeof(device_record.doh_endpoints) - 1] = 0;
	int n = parse_endpoints(device_record.doh_endpoints);
	Debug.printf("fetch_new_ip: %s -> %d endpoint(s)\n", device_record.doh_endpoints, n);
	flag_save_block = 1;
	return true;
}

static volatile bool resolve_last_ok = false;

volatile int doh_result = 0;   // 0 = pending, 1 = ok, 2 = failed (see bootstrap.h)
volatile int doh_stage  = DOH_IDLE;

// The steady-state login pump's deadline (kernel.c). Setting it to 0 forces a
// re-login on the next tick -- how we reconnect to the freshly-set relay once the
// endpoints change. Plain global (no name mangling) so this C++ TU can poke it.
#include "netif.h"   // netif_relogin

void request_fetch_new_ip(){
	doh_stage = DOH_FETCHING;
	phone_state_set(PS_UNBLOCKING);
}

bool fetch_new_ip_pending(){ return doh_stage == DOH_FETCHING || doh_stage == DOH_RECEIVED; }
bool fetch_new_ip_last_ok(){ return resolve_last_ok; }

// One step per call so the UI renders each stage between calls (the DoH itself
// blocks core 0, so the screen freezes on DOH_FETCHING while it runs). Called
// from wifi_poll() on core 0.
void bootstrap_pump(){
	switch (doh_stage){
	case DOH_FETCHING: {
		if (WiFi.status() != WL_CONNECTED){
			resolve_last_ok = false; doh_result = 2; doh_stage = DOH_FAILED;
			phone_state_set(PS_WIFI_CONNECTED);
			return;
		}
		char buff[MAX_DOH_ENDPOINTS];
		// Single-core build: the UI and the network are time-sliced on core 0 and
		// never allocate concurrently, so the old dual-core idleOtherCore() guard
		// around the resolve is unnecessary here and is omitted.
		DoHResolver resolver;
		bool ok = (resolver.resolveTXT(BOOTSTRAP_HOSTNAME, buff, sizeof(buff)) == DoHResolver::OK);
		if (!ok){
			resolve_last_ok = false; doh_result = 2; doh_stage = DOH_FAILED;
			phone_state_set(PS_WIFI_CONNECTED);
			return;
		}
		strncpy(device_record.doh_endpoints, buff, sizeof(device_record.doh_endpoints) - 1);
		device_record.doh_endpoints[sizeof(device_record.doh_endpoints) - 1] = 0;
		doh_stage = DOH_RECEIVED;   // render "Relay list received" before parsing
		return;
	}
	case DOH_RECEIVED: {
		int n = parse_endpoints(device_record.doh_endpoints);
		Debug.printf("fetch_new_ip: %s -> %d endpoint(s)\n", device_record.doh_endpoints, n);
		if (n > 0){
			flag_save_block  = 1;
			resolve_last_ok  = true;
			doh_result       = 1;
			doh_stage        = DOH_APPLIED;
			netif_relogin();            // our ingress changed: re-join via the new relay
		} else {
			resolve_last_ok = false; doh_result = 2; doh_stage = DOH_FAILED;
		}
		phone_state_set(PS_WIFI_CONNECTED);
		return;
	}
	default:
		return;   // IDLE / APPLIED / FAILED -- nothing to pump
	}
}

void bootstrap_invalidate(){
	device_record.doh_endpoints[0] = 0;
	memset(device_record.endpoints, 0, sizeof(device_record.endpoints));
}
