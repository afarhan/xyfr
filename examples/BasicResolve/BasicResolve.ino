// BasicResolve -- DoHResolver demo for Raspberry Pi Pico W.
// Connects to WiFi, then resolves an A record at boot and re-resolves
// (A and TXT) every 30 seconds.

#include <WiFi.h>
#include "DoHResolver.h"

#define WIFI_SSID     "your-ssid"
#define WIFI_PASSWORD "your-password"

DoHResolver resolver;
unsigned long last_resolve_ms = 0;

static void resolveOnce() {
    IPAddress ip;
    DoHResolver::Status st = resolver.resolveA("example.com", ip);
    Serial.printf("resolveA(example.com) -> %s",
                  DoHResolver::statusToString(st));
    if (st == DoHResolver::OK) {
        Serial.printf(" %s", ip.toString().c_str());
    }
    Serial.printf(" (ep=%u)\n", (unsigned)resolver.lastEndpointIndex());

    char txt[256];
    st = resolver.resolveTXT("cloudflare.com", txt, sizeof(txt));
    Serial.printf("resolveTXT(cloudflare.com) -> %s",
                  DoHResolver::statusToString(st));
    if (st == DoHResolver::OK) {
        Serial.printf(" \"%s\"", txt);
    }
    Serial.printf(" (ep=%u)\n", (unsigned)resolver.lastEndpointIndex());
}

void setup() {
    Serial.begin(115200);
    while (!Serial && millis() < 3000) {}

    Serial.print("Connecting to WiFi");
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.printf("\nWiFi up, IP=%s\n", WiFi.localIP().toString().c_str());

    randomSeed(micros());

    // To test endpoint failover, uncomment to put a broken endpoint first:
    // static const DoHResolver::Endpoint eps[] = {
    //     { "2.2.2.2", "cloudflare-dns.com", "/dns-query" },  // broken
    //     { "1.1.1.1", "cloudflare-dns.com", "/dns-query" },
    // };
    // resolver.setEndpoints(eps, sizeof(eps) / sizeof(eps[0]));

    resolveOnce();
    last_resolve_ms = millis();
}

void loop() {
    if (millis() - last_resolve_ms >= 30000) {
        resolveOnce();
        last_resolve_ms = millis();
    }
}
