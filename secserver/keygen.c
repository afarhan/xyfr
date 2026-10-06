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
#include "hal.h"    // hal_rand() — platform CSPRNG (getrandom on Linux)
#include "bip39.h"  // bip39_encode — the 24-word recovery phrase (== the private key)

// Generate (or accept) a Curve25519 keypair and print the public key, private key,
// user id (partkey), and the 24-word BIP-39 recovery phrase.
//
//   ./keygen                     -> fresh random key
//   ./keygen <64-hex-privatekey> -> derive from the supplied private key
//
// The phrase is what the device's "Sign In" import screen accepts (bip39_decode of
// the phrase yields the same 32-byte private key), so this is how you provision a
// wiped device with a known identity.
//
// Entropy for the random path comes from hal_rand() (kernel CSPRNG), NOT libc
// rand() — a key seeded from srand(time()) is trivially predictable (threat-model
// J-1). hal_rand() is provided by hal_posix.o, linked by the Makefile. keygen
// links only crypto.o + hal_posix.o + bip39*, so it uses local helpers instead of
// pulling in full wg.o.
static void fill_random_local(uint8_t *buff, int length){
  int i;
  for(i = 0; i < length; i++)
    buff[i] = (uint8_t)hal_rand();
}

static void print_key_local(const uint8_t *key, int length){
  while(length--) printf("%02x", *key++);
  printf("\n");
}

static int hexval(char c){
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Parse exactly 64 hex chars (case-insensitive, ignoring surrounding whitespace)
// into a 32-byte key. Returns false on any non-hex char or a wrong length.
static bool parse_hex32(const char *s, uint8_t out[KEY_LEN]){
  while (*s == ' ' || *s == '\t') s++;
  for (int n = 0; n < KEY_LEN; n++){
    int hi = hexval(s[2*n]);
    int lo = hexval(s[2*n + 1]);
    if (hi < 0 || lo < 0) return false;
    out[n] = (uint8_t)((hi << 4) | lo);
  }
  const char *t = s + 2 * KEY_LEN;
  while (*t == ' ' || *t == '\t' || *t == '\n' || *t == '\r') t++;
  return *t == 0;   // nothing but whitespace after the 64 hex digits
}

static const unsigned char local_basepoint[KEY_LEN] = {9};

static void print_usage(const char *prog){
  printf("keygen - generate or inspect a Curve25519 identity\n\n"
         "usage:\n"
         "  %s                     generate a fresh random keypair\n"
         "  %s <64-hex-private>    derive from an existing private key\n"
         "  %s -h | --help         this help\n\n"
         "prints the public key, private key, user id (partkey), and the 24-word\n"
         "BIP-39 recovery phrase (type the phrase into the device's 'Sign In').\n",
         prog, prog, prog);
}

int main(int argc, char **argv){
  uint8_t public_key[KEY_LEN];
  uint8_t private_key[KEY_LEN];
  bool supplied = false;

  if (argc >= 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))){
    print_usage(argv[0]);
    return 0;
  }

  if (argc >= 2){
    if (!parse_hex32(argv[1], private_key)){
      fprintf(stderr, "usage: %s [<private_key_64hex>]\n"
                      "  no arg : generate a fresh keypair\n"
                      "  1 arg  : derive from the given 64-hex private key\n", argv[0]);
      return 1;
    }
    supplied = true;
  } else {
    fill_random_local(private_key, KEY_LEN);
  }

  curve25519(public_key, private_key, local_basepoint);

  uint32_t userid = ((uint32_t)public_key[0] << 24) | ((uint32_t)public_key[1] << 16)
                  | ((uint32_t)public_key[2] <<  8) |  (uint32_t)public_key[3];

  char phrase[BIP39_MNEMONIC_BUFSZ];
  int rc = bip39_encode(private_key, phrase, sizeof phrase);   // returns phrase length, or <0 on error

  printf("%s\n", supplied ? "Key pair (from supplied private key):"
                          : "Generated new key pair:");
  printf("Public key:  "); print_key_local(public_key, KEY_LEN);
  printf("Private key: "); print_key_local(private_key, KEY_LEN);
  printf("User ID:     %08x\n", userid);
  if (rc > 0)
    printf("Recovery phrase (24 words - type this into 'Sign In'):\n%s\n", phrase);
  else
    printf("bip39_encode failed (%d)\n", rc);
  return 0;
}
