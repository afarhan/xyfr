#include "DoHResolver.h"
#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <string.h>
#include <stdlib.h>

static const DoHResolver::Endpoint kDefaultEndpoints[] = {
    { "1.1.1.1", "cloudflare-dns.com", "/dns-query" },
    { "1.0.0.1", "cloudflare-dns.com", "/dns-query" },
    { "8.8.8.8", "dns.google",         "/dns-query" },
    { "8.8.4.4", "dns.google",         "/dns-query" },
};
static const size_t kDefaultEndpointCount =
    sizeof(kDefaultEndpoints) / sizeof(kDefaultEndpoints[0]);

DoHResolver::DoHResolver()
    : endpoints_(kDefaultEndpoints), endpoint_count_(kDefaultEndpointCount),
      ca_pem_(nullptr), timeout_ms_(5000), tls_rx_(2048), tls_tx_(512),
      dbg_(&Serial), last_endpoint_(0), warned_insecure_(false) {}

void DoHResolver::setEndpoints(const Endpoint* eps, size_t count) {
    if (eps && count > 0) {
      endpoints_ = eps;
      endpoint_count_ = count;
    }
}
void DoHResolver::setCACert(const char* pem)        { ca_pem_ = pem; }
void DoHResolver::setTimeout(uint32_t ms)           { timeout_ms_ = ms; }
void DoHResolver::setTLSBufferSizes(uint16_t rx, uint16_t tx) { tls_rx_ = rx; tls_tx_ = tx; }
void DoHResolver::setDebugStream(Stream* s)         { dbg_ = s; }

const char* DoHResolver::statusToString(Status s) {
    switch (s) {
    case OK:                      return "OK";
    case ERR_WIFI_NOT_CONNECTED:  return "ERR_WIFI_NOT_CONNECTED";
    case ERR_TLS_CONNECT_FAILED:  return "ERR_TLS_CONNECT_FAILED";
    case ERR_HTTP_REQUEST_FAILED: return "ERR_HTTP_REQUEST_FAILED";
    case ERR_HTTP_BAD_RESPONSE:   return "ERR_HTTP_BAD_RESPONSE";
    case ERR_DNS_PARSE_FAILED:    return "ERR_DNS_PARSE_FAILED";
    case ERR_DNS_NO_ANSWER:       return "ERR_DNS_NO_ANSWER";
    case ERR_DNS_RCODE_ERROR:     return "ERR_DNS_RCODE_ERROR";
    case ERR_TIMEOUT:             return "ERR_TIMEOUT";
    case ERR_INVALID_ARGUMENT:    return "ERR_INVALID_ARGUMENT";
    }
    return "ERR_UNKNOWN";
}

static size_t encodeName(const char* host, uint8_t* out, size_t out_cap) {
    if (!host || !*host)
      return 0;
    size_t out_off = 0;
    const char* label = host;
    while (true) {
        const char* dot = strchr(label, '.');
        size_t lab_len = dot ? (size_t)(dot - label) : strlen(label);
        if (lab_len == 0 || lab_len > 63)
          return 0;
        if (out_off + 1 + lab_len + 1 > out_cap)
          return 0;
        out[out_off++] = (uint8_t)lab_len;
        memcpy(out + out_off, label, lab_len);
        out_off += lab_len;
        if (!dot)
          break;
        label = dot + 1;
        if (!*label)
          return 0;
    }
    out[out_off++] = 0;
    if (out_off > 255)
      return 0;
    return out_off;
}

static size_t buildQuery(uint16_t txn_id, uint16_t qtype, const char* host,
                         uint8_t* out, size_t out_cap) {
    if (out_cap < 12 + 5)
      return 0;
    out[0]  = (uint8_t)(txn_id >> 8);
    out[1]  = (uint8_t)(txn_id & 0xFF);
    out[2]  = 0x01; out[3]  = 0x00;   // RD set
    out[4]  = 0x00; out[5]  = 0x01;   // QDCOUNT = 1
    out[6]  = 0x00; out[7]  = 0x00;   // ANCOUNT
    out[8]  = 0x00; out[9]  = 0x00;   // NSCOUNT
    out[10] = 0x00; out[11] = 0x00;   // ARCOUNT
    size_t off = 12;
    size_t name_len = encodeName(host, out + off, out_cap - off - 4);
    if (name_len == 0)
      return 0;
    off += name_len;
    out[off++] = (uint8_t)(qtype >> 8);
    out[off++] = (uint8_t)(qtype & 0xFF);
    out[off++] = 0x00; out[off++] = 0x01; // QCLASS = IN
    return off;
}

static size_t b64urlEncode(const uint8_t* in, size_t n,
                           char* out, size_t out_cap) {
    static const char alpha[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t out_off = 0;
    size_t i = 0;
    while (i + 3 <= n) {
        uint32_t v = ((uint32_t)in[i]   << 16)
                   | ((uint32_t)in[i+1] <<  8)
                   |  (uint32_t)in[i+2];
        if (out_off + 4 >= out_cap)
          return 0;
        out[out_off++] = alpha[(v >> 18) & 0x3F];
        out[out_off++] = alpha[(v >> 12) & 0x3F];
        out[out_off++] = alpha[(v >>  6) & 0x3F];
        out[out_off++] = alpha[ v        & 0x3F];
        i += 3;
    }
    size_t rem = n - i;
    if (rem == 1) {
        if (out_off + 2 >= out_cap)
          return 0;
        uint32_t v = (uint32_t)in[i] << 16;
        out[out_off++] = alpha[(v >> 18) & 0x3F];
        out[out_off++] = alpha[(v >> 12) & 0x3F];
    } else if (rem == 2) {
        if (out_off + 3 >= out_cap)
          return 0;
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8);
        out[out_off++] = alpha[(v >> 18) & 0x3F];
        out[out_off++] = alpha[(v >> 12) & 0x3F];
        out[out_off++] = alpha[(v >>  6) & 0x3F];
    }
    out[out_off] = '\0';
    return out_off;
}

static void hexDump(Stream* s, const char* tag, const uint8_t* d, size_t n) {
    if (!s)
      return;
    s->printf("[DoH] %s (%u bytes):", tag, (unsigned)n);
    for (size_t i = 0; i < n; i++) {
        if ((i & 0x0F) == 0)
          s->print("\n  ");
        s->printf("%02x ", d[i]);
    }
    s->println();
}

// Walk past a DNS-encoded name. On return off points one byte past the
// terminator (either past 0x00 or past the 2-byte compression pointer).
static DoHResolver::Status skipName(const uint8_t* buf, size_t len, size_t& off) {
    uint8_t hops = 0;
    size_t cur = off;
    bool advanced_off = false;
    while (true) {
        if (cur >= len)
          return DoHResolver::ERR_DNS_PARSE_FAILED;
        uint8_t b = buf[cur];
        if (b == 0) {
            cur++;
            if (!advanced_off)
              off = cur;
            return DoHResolver::OK;
        }
        if ((b & 0xC0) == 0xC0) {
            if (cur + 1 >= len)
              return DoHResolver::ERR_DNS_PARSE_FAILED;
            uint16_t target = ((uint16_t)(b & 0x3F) << 8) | buf[cur + 1];
            if (!advanced_off) {
              off = cur + 2;
              advanced_off = true;
            }
            if (target >= cur)
              return DoHResolver::ERR_DNS_PARSE_FAILED;
            if (++hops > 8)
              return DoHResolver::ERR_DNS_PARSE_FAILED;
            cur = target;
            continue;
        }
        if ((b & 0xC0) != 0)
          return DoHResolver::ERR_DNS_PARSE_FAILED;
        if (b > 63)
          return DoHResolver::ERR_DNS_PARSE_FAILED;
        cur += 1 + b;
    }
}

static DoHResolver::Status parseAnswers(
    const uint8_t* buf, size_t len, uint16_t want_type, uint16_t txn_id,
    uint8_t* rdata_out, uint16_t rdata_cap, uint16_t& rdata_len)
{
    if (len < 12)
      return DoHResolver::ERR_DNS_PARSE_FAILED;
    uint16_t rid = ((uint16_t)buf[0] << 8) | buf[1];
    if (rid != txn_id)
      return DoHResolver::ERR_DNS_PARSE_FAILED;
    if (buf[2] & 0x02)  // TC
      return DoHResolver::ERR_DNS_PARSE_FAILED;
    uint8_t rcode = buf[3] & 0x0F;
    if (rcode != 0)
      return DoHResolver::ERR_DNS_RCODE_ERROR;
    uint16_t qd = ((uint16_t)buf[4] << 8) | buf[5];
    uint16_t an = ((uint16_t)buf[6] << 8) | buf[7];
    if (qd != 1)
      return DoHResolver::ERR_DNS_PARSE_FAILED;
    if (an == 0)
      return DoHResolver::ERR_DNS_NO_ANSWER;

    size_t off = 12;
    DoHResolver::Status st = skipName(buf, len, off);
    if (st != DoHResolver::OK)
      return st;
    if (off + 4 > len)
      return DoHResolver::ERR_DNS_PARSE_FAILED;
    off += 4; // QTYPE + QCLASS

    for (uint16_t i = 0; i < an; i++) {
        st = skipName(buf, len, off);
        if (st != DoHResolver::OK)
          return st;
        if (off + 10 > len)
          return DoHResolver::ERR_DNS_PARSE_FAILED;
        uint16_t type  = ((uint16_t)buf[off]     << 8) | buf[off + 1];
        uint16_t cls   = ((uint16_t)buf[off + 2] << 8) | buf[off + 3];
        uint16_t rdlen = ((uint16_t)buf[off + 8] << 8) | buf[off + 9];
        off += 10;
        if (off + rdlen > len)
          return DoHResolver::ERR_DNS_PARSE_FAILED;
        if (type == want_type && cls == 1) {
            uint16_t copy_len = rdlen;
            if (copy_len > rdata_cap)
              copy_len = rdata_cap;
            memcpy(rdata_out, buf + off, copy_len);
            rdata_len = copy_len;
            return DoHResolver::OK;
        }
        off += rdlen;
    }
    return DoHResolver::ERR_DNS_NO_ANSWER;
}

DoHResolver::Status DoHResolver::resolveCommon(
    const char* host, uint16_t qtype,
    uint8_t* rdata, uint16_t rdata_cap, uint16_t& rdata_len)
{
    if (!host || !*host || !rdata || rdata_cap == 0)
      return ERR_INVALID_ARGUMENT;
    if (WiFi.status() != WL_CONNECTED)
      return ERR_WIFI_NOT_CONNECTED;

    uint8_t query[512], response[512];
    char    b64[768];
    uint16_t txn_id = (uint16_t)random(1, 0x10000);
    size_t qlen = buildQuery(txn_id, qtype, host, query, sizeof(query));
    if (qlen == 0)
      return ERR_INVALID_ARGUMENT;
    if (b64urlEncode(query, qlen, b64, sizeof(b64)) == 0)
      return ERR_HTTP_REQUEST_FAILED;
    if (dbg_)
      hexDump(dbg_, "query", query, qlen);

    Status last_err = ERR_TLS_CONNECT_FAILED;
    for (size_t i = 0; i < endpoint_count_; i++) {
        last_endpoint_ = i;
        const Endpoint& ep = endpoints_[i];
        if (dbg_)
          dbg_->printf("[DoH] ep=%u sni=%s\n", (unsigned)i, ep.sni);

        // Use HTTPClient -- much more reliable than hand-rolling
        // BearSSL::WiFiClientSecure on this platform.
        HTTPClient https;
        if (ca_pem_) {
            https.setCACert(ca_pem_);
        } else {
            https.setInsecure();
            if (!warned_insecure_ && dbg_) {
                dbg_->println("[DoH] WARNING: TLS in INSECURE mode -- set a pinned CA for production");
                warned_insecure_ = true;
            }
        }
        https.setTimeout(timeout_ms_);

        char url[256];
        snprintf(url, sizeof(url), "https://%s%s?dns=%s", ep.sni, ep.path, b64);
        if (dbg_)
          dbg_->printf("[DoH] >begin %s\n", url);
        if (!https.begin(url)) {
            if (dbg_)
              dbg_->println("[DoH] begin failed");
            last_err = ERR_TLS_CONNECT_FAILED;
            continue;
        }
        https.addHeader("Accept", "application/dns-message");
        https.addHeader("User-Agent", "DoHResolver/1.0");

        if (dbg_)
          dbg_->println("[DoH] >GET");
        int code = https.GET();
        if (dbg_)
          dbg_->printf("[DoH] <GET code=%d\n", code);
        if (code != HTTP_CODE_OK) {
            https.end();
            if ((code <= 0))
              last_err = ERR_TLS_CONNECT_FAILED;
            else
              last_err = ERR_HTTP_BAD_RESPONSE;
            continue;
        }

        WiFiClient* stream = https.getStreamPtr();
        size_t resp_len = 0;
        int total = https.getSize();   // -1 if unknown (chunked)
        uint32_t deadline = millis() + timeout_ms_;
        while (resp_len < sizeof(response) &&
               (total < 0 || resp_len < (size_t)total) &&
               (int32_t)(deadline - millis()) > 0) {
            if (stream->available()) {
                int b = stream->read();
                if (b < 0)
                  break;
                response[resp_len++] = (uint8_t)b;
            } else if (!stream->connected() && !stream->available()) {
                break;
            } else {
                delay(1);
            }
        }
        https.end();

        if (resp_len == 0) {
            if (dbg_)
              dbg_->println("[DoH] empty response");
            last_err = ERR_HTTP_BAD_RESPONSE;
            continue;
        }
        if (dbg_)
          hexDump(dbg_, "response", response, resp_len);

        Status parse_st = parseAnswers(response, resp_len, qtype, txn_id, rdata, rdata_cap, rdata_len);
        if (parse_st == OK)
          return OK;
        if (parse_st == ERR_DNS_RCODE_ERROR || parse_st == ERR_DNS_NO_ANSWER)
          return parse_st;
        last_err = parse_st;
    }
    return last_err;
}

DoHResolver::Status DoHResolver::resolveA(const char* host, IPAddress& out_ip) {
    uint8_t rdata[16];
    uint16_t rdlen = 0;
    Status st = resolveCommon(host, 1, rdata, sizeof(rdata), rdlen);
    if (st != OK)
      return st;
    if (rdlen != 4)
      return ERR_DNS_PARSE_FAILED;
    out_ip = IPAddress(rdata[0], rdata[1], rdata[2], rdata[3]);
    if (dbg_)
      dbg_->printf("[DoH] parsed: A=%u.%u.%u.%u\n",
                           rdata[0], rdata[1], rdata[2], rdata[3]);
    return OK;
}

DoHResolver::Status DoHResolver::resolveTXT(const char* host,
                                            char* out, size_t out_size) {
    if (!out || out_size < 1)
      return ERR_INVALID_ARGUMENT;
    uint8_t rdata[512];
    uint16_t rdlen = 0;
    Status st = resolveCommon(host, 16, rdata, sizeof(rdata), rdlen);
    if (st != OK)
      return st;
    if (rdlen < 1)
      return ERR_DNS_PARSE_FAILED;
    uint8_t sublen = rdata[0];
    if ((uint16_t)sublen + 1 > rdlen)
      return ERR_DNS_PARSE_FAILED;
    if ((size_t)sublen + 1 > out_size) {
        size_t copy = out_size - 1;
        memcpy(out, rdata + 1, copy);
        out[copy] = '\0';
        return ERR_DNS_PARSE_FAILED;
    }
    memcpy(out, rdata + 1, sublen);
    out[sublen] = '\0';
    if (dbg_)
      dbg_->printf("[DoH] parsed: TXT=\"%s\"\n", out);
    return OK;
}
