// policy.c — inbound admission logic (see policy.h). Portable C, core 0.

#include "policy.h"
#include <string.h>
#include "hal.h"        // hal_debug — the admission telemetry
#include "device_record.h"    // device_record, struct contact_record, KEY_LEN, PRESENCE_*, ALLOW_*, CONTACT_*
#include "contacts.h"   // contact_get, contact_key_status, CONTACT_KEY_VALID

// partkey = first 4 bytes of a public key as a big-endian uint32 (same
// derivation as wg's get_part_key; inlined so this TU pulls in nothing from
// wg.h, which would otherwise drag the whole transport in for four bytes).
static uint32_t partkey_of(const uint8_t *k) {
	return ((uint32_t)k[0] << 24) | ((uint32_t)k[1] << 16)
	     | ((uint32_t)k[2] <<  8) |  (uint32_t)k[3];
}

static bool settings_bit(uint32_t partkey, uint32_t bit) {
	struct contact_record c;
	if (!contact_get(&c, partkey))
		return false;
	return (c.settings & bit) != 0;
}

bool contact_is_star(uint32_t partkey) {
	return settings_bit(partkey, CONTACT_STAR);
}

bool contact_is_blocked(uint32_t partkey) {
	return settings_bit(partkey, CONTACT_BLOCKED);
}

int admit_handshake(const uint8_t *public_key) {
	// Naming the caller here is what separates "no handshake arrived" from
	// "one arrived and was refused" in the log.
	uint32_t from_pk = ((uint32_t)public_key[0] << 24) | ((uint32_t)public_key[1] << 16) |
	                   ((uint32_t)public_key[2] << 8)  |  (uint32_t)public_key[3];
	hal_debug(LOG_EVERYTHING, "policy: admit_handshake from %08x\n", (unsigned)from_pk);
	// Offline: reject every inbound handshake, calls and messages alike.
	if (device_record.presence == PRESENCE_OFFLINE)
		return 0;

	// Reject the all-zero key defensively (a peer that never ran keygen).
	bool nonzero = false;
	for (int i = 0; i < KEY_LEN; i++)
		if (public_key[i]) {
			nonzero = true;
			break;
		}
	if (!nonzero)
		return 0;

	uint32_t userid = partkey_of(public_key);
	struct contact_record c;
	bool got = contact_get(&c, userid);

	// A Blocked contact is always refused, regardless of allow policy.
	if (got && (c.settings & CONTACT_BLOCKED))
		return 0;

	// Allow Contacts: only a valid contact whose full 32-byte key matches may
	// handshake, so a partkey prefix collision cannot slip through. A stranger
	// is refused outright, with no lookup and no response.
	if (device_record.allow_policy == ALLOW_CONTACTS) {
		if (!got)
			return 0;
		if (contact_key_status(&c) != CONTACT_KEY_VALID)
			return 0;
		if (memcmp(c.key, public_key, KEY_LEN) != 0)
			return 0;
		return 1;
	}

	// Open policy: a contact passes, and a non-contact is still refused. A
	// stranger never gets a session, so nothing it sends can reach storage, but
	// the knock is filed for the user to review ("Requests from (N) users").
	// contact_knock neither blocks nor replies: it records the partkey and lets
	// the lookup pump verify it out of band (contacts.h).
	if (got)
		return 1;
	contact_knock(public_key);
	return 0;
}

int admit_media(uint32_t partkey) {
	// Contacts only, in all cases; see policy.h. This is the second gate for the
	// contacts admit_handshake already let through — a contact may be blocked or
	// presence-gated out of ringing us even though its messages are accepted.
	// The contact test comes before presence, so a non-contact is refused even
	// in Normal.
	struct contact_record c;
	if (!contact_get(&c, partkey))
		return ADMIT_REJECT;
	if (c.settings & CONTACT_BLOCKED)
		return ADMIT_REJECT;

	switch (device_record.presence) {
	case PRESENCE_NOCALLS:
		return ADMIT_SILENT;                                   // never ring, not even a Star contact
	case PRESENCE_BUSY:
		if (contact_is_star(partkey))
			return ADMIT_RING;
		return ADMIT_SILENT;
	case PRESENCE_OFFLINE:
		return ADMIT_SILENT;                                   // admit_handshake already rejected it; this is the backstop
	default:
		return ADMIT_RING;                                     // PRESENCE_NORMAL
	}
}
