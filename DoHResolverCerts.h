// Trust anchors for the default DoH endpoints in DoHResolver.cpp:
//
//   cloudflare-dns.com (1.1.1.1, 1.0.0.1) -> ISRG Root X1 (Let's Encrypt)
//   dns.google         (8.8.8.8, 8.8.4.4) -> GTS Root R1 (Google Trust Services)
//
// Both are RSA-4096 roots valid through 2035/2036. The DoH servers send
// their intermediate cert in the handshake; BearSSL builds the chain from
// leaf -> intermediate -> one of these roots.
//
// Usage in your sketch:
//     #include "DoHResolverCerts.h"
//     resolver.setCACert(kDoHRootCAs);
//     resolver.setTLSBufferSizes(4096, 512);   // still recommended
//
// If BearSSL rejects either cert (e.g. if a root rolls over), fetch fresh
// PEMs from the canonical sources and replace the strings below:
//   https://letsencrypt.org/certs/isrgrootx1.pem
//   https://pki.goog/repo/certs/gtsr1.pem

#pragma once

extern const char kDoHRootCAs[];
