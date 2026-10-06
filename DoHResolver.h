// DoHResolver -- DNS-over-HTTPS resolver for Raspberry Pi Pico W
// (RP2040 / RP2350) on Earle Philhower's arduino-pico core.
//
// Limited to A and TXT record types. Extend by adding a TYPE=28 (16-byte
// IPv6) branch in parseAnswers() for AAAA support.
//
// Designed for short-lived per-call queries: each resolve constructs a
// fresh WiFiClientSecure (BearSSL), connects, queries, and tears down.
// Suitable for a censorship-circumvention bootstrap where each query is
// independent.
//
// Production deployments MUST call setCACert() with a pinned root CA.
// The setInsecure() fallback exists only for development bring-up and
// prints a one-time warning on first use.

#pragma once

#include <Arduino.h>
#include <WiFi.h>
#include <IPAddress.h>

class DoHResolver {
public:
    enum Status {
        OK = 0,
        ERR_WIFI_NOT_CONNECTED,
        ERR_TLS_CONNECT_FAILED,
        ERR_HTTP_REQUEST_FAILED,
        ERR_HTTP_BAD_RESPONSE,
        ERR_DNS_PARSE_FAILED,
        ERR_DNS_NO_ANSWER,
        ERR_DNS_RCODE_ERROR,
        ERR_TIMEOUT,
        ERR_INVALID_ARGUMENT
    };

    struct Endpoint {
        const char* ip;    // dotted-quad IPv4, e.g. "1.1.1.1"
        const char* sni;   // TLS SNI / Host header, e.g. "cloudflare-dns.com"
        const char* path;  // request path, e.g. "/dns-query"
    };

    DoHResolver();

    // Override the default endpoint list
    // (1.1.1.1 / 1.0.0.1 / 8.8.8.8 / 8.8.4.4).
    void setEndpoints(const Endpoint* endpoints, size_t count);

    // Pin a root CA in PEM form. Strongly recommended in production.
    // If never called, setInsecure() is used and a warning is printed on
    // the first resolve.
    void setCACert(const char* pem_cert);

    // Total per-endpoint timeout in milliseconds (default 5000).
    void setTimeout(uint32_t ms);

    // BearSSL TLS RX/TX buffer sizes (default 2048, 512). Smaller values
    // save heap but may break the handshake for large server certificates.
    void setTLSBufferSizes(uint16_t rx, uint16_t tx);

    // Redirect debug output. Default is &Serial; pass nullptr to silence.
    void setDebugStream(Stream* s);

    // Resolve an A record. Tries each endpoint until one succeeds or all
    // fail. On OK, writes the IPv4 address to out_ip.
    Status resolveA(const char* hostname, IPAddress& out_ip);

    // Resolve a TXT record. Copies the first character-string into out_buf
    // (NUL-terminated). Returns ERR_DNS_PARSE_FAILED if out_buf_size is
    // too small to hold the string.
    Status resolveTXT(const char* hostname, char* out_buf, size_t out_buf_size);

    // Index of the last endpoint attempted (for diagnostics).
    size_t lastEndpointIndex() const { return last_endpoint_; }

    // Human-readable Status.
    static const char* statusToString(Status s);

private:
    Status resolveCommon(const char* host, uint16_t qtype,
                         uint8_t* rdata, uint16_t rdata_cap,
                         uint16_t& rdata_len);

    const Endpoint* endpoints_;
    size_t          endpoint_count_;
    const char*     ca_pem_;
    uint32_t        timeout_ms_;
    uint16_t        tls_rx_;
    uint16_t        tls_tx_;
    Stream*         dbg_;
    size_t          last_endpoint_;
    bool            warned_insecure_;
};
