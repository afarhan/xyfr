#include "debug.h"
#include <Arduino.h>
#include <string.h>
#include "contacts.h"
#include "device_record.h"

extern "C" time_t get_current_time_seconds();

static int passed = 0, failed = 0;

#define CHECK(cond, msg) do { \
	if (cond) { Debug.printf("  PASS  %s\n", msg); passed++; } \
	else      { Debug.printf("  FAIL  %s\n", msg); failed++; } \
} while (0)

static void dump_contact(const char *label, const struct contact_record *c) {
	uint8_t version = (c->flag & CONTACT_VERSION_MASK) >> CONTACT_VERSION_SHIFT;
	uint8_t flags   =  c->flag & CONTACT_FLAG_MASK;
	Debug.printf("    %s: userid=%08x v=%u flags=%02x name=\"%s\" "
	              "key[0..3]=%02x%02x%02x%02x\n",
		label, (unsigned)contact_userid(c), version, flags, c->name,
		c->key[0], c->key[1], c->key[2], c->key[3]);
}


static void make_contact(struct contact_record *c, uint32_t uid,
                         const char *name, uint8_t kseed) {
	memset(c, 0, sizeof(*c));
	c->flag = 0;   // version 0, no app flags
	strncpy(c->name, name, MAX_NAME - 1);
	// Pack uid as the leading 4 bytes of the key (big-endian) so that
	// get_part_key(c->key) == uid; rest of the key is uniquely seeded.
	c->key[0] = (uint8_t)(uid >> 24);
	c->key[1] = (uint8_t)(uid >> 16);
	c->key[2] = (uint8_t)(uid >>  8);
	c->key[3] = (uint8_t)(uid >>  0);
	for (int i = 4; i < KEY_LEN; i++)
		c->key[i] = (uint8_t)(i * kseed + 1);
}

void test_contacts() {
	delay(5000); //wait for the serial port to be initialized
	Debug.println();
	Debug.println("================================================");
	Debug.println("=== test_contacts: storage API tests          ===");
	Debug.println("=== Note: NTP not synced yet; epochs reflect  ===");
	Debug.println("=== millis()/1000 (small values, not unix).   ===");
	Debug.println("================================================");
	passed = 0; failed = 0;

	Debug.println("test: calling contacts_wipe_all (clean slate)");
	contacts_wipe_all();
	Debug.println("test: calling contacts_init");
	contacts_init();
	Debug.println("test: init done");

	const uint32_t U_ALICE = 0xa1b2c3d4;
	const uint32_t U_BOB   = 0xb2c3d4e5;
	const uint32_t U_CHARL = 0xc3d4e5f6;

	struct contact_record c, got;

	Debug.println("\n--- [1] contact_get on missing userid");
	CHECK(contact_get(&got, U_ALICE) == false, "missing userid returns false");

	Debug.println("\n--- [2] contact_save Alice");
	make_contact(&c, U_ALICE, "Alice", 7);
	CHECK(contact_save(&c) == true, "save Alice");

	Debug.println("\n--- [3] contact_get round-trip");
	memset(&got, 0, sizeof(got));
	CHECK(contact_get(&got, U_ALICE) == true, "get Alice");
	CHECK(contact_userid(&got) == U_ALICE, "userid derives from key");
	CHECK(strcmp(got.name, "Alice") == 0, "name round-trip");
	CHECK(memcmp(got.key, c.key, KEY_LEN) == 0, "key round-trip");
	CHECK((got.flag & CONTACT_VERSION_MASK) == 0, "flag version is 0");
	CHECK((got.flag & CONTACT_FLAG_MASK) == 0, "flag bits are zero on save");
	dump_contact("got", &got);

	Debug.println("\n--- [4] save Bob and Charlie");
	make_contact(&c, U_BOB, "Bob", 11);
	CHECK(contact_save(&c) == true, "save Bob");
	make_contact(&c, U_CHARL, "Charlie", 13);
	CHECK(contact_save(&c) == true, "save Charlie");

	Debug.println("\n--- [5] contact_ls iterates all 3");
	int found = 0;
	bool got_a=false, got_b=false, got_c=false;
	for (int i = 0; ; i++) {
		uint32_t ls_id = 0;
		if (!contact_ls(i, &got, &ls_id))
			break;
		found++;
		Debug.printf("    ls[%d]: userid=%08x (derived=%08x) name=\"%s\"\n",
			i, (unsigned)ls_id, (unsigned)contact_userid(&got), got.name);
		CHECK(ls_id == contact_userid(&got), "ls out_userid matches derived");
		if (ls_id == U_ALICE)
			got_a = true;
		if (ls_id == U_BOB)
			got_b = true;
		if (ls_id == U_CHARL)
			got_c = true;
	}
	CHECK(found == 3, "ls returned 3 entries");
	CHECK(got_a && got_b && got_c, "all 3 contacts listed");

	Debug.println("\n--- [6] re-save Alice as \"Alice2\"");
	make_contact(&c, U_ALICE, "Alice2", 7);
	CHECK(contact_save(&c) == true, "re-save Alice");
	CHECK(contact_get(&got, U_ALICE) == true, "get Alice2");
	CHECK(strcmp(got.name, "Alice2") == 0, "name updated");

	Debug.println("\n--- [7] contact_delete Bob");
	CHECK(contact_delete(U_BOB) == true, "delete Bob");
	CHECK(contact_get(&got, U_BOB) == false, "Bob is gone");

	Debug.println("\n--- [8] contact_ls now shows 2");
	found = 0;
	for (int i = 0; ; i++) {
		uint32_t ls_id = 0;
		if (!contact_ls(i, &got, &ls_id))
			break;
		found++;
		Debug.printf("    ls[%d]: userid=%08x name=\"%s\"\n",
			i, (unsigned)ls_id, got.name);
	}
	CHECK(found == 2, "ls returned 2 entries");

	Debug.println("\n--- [9] contact_delete on missing");
	CHECK(contact_delete(U_BOB) == false, "delete-missing returns false");


	Debug.println("\n--- cleanup");
	contact_delete(U_ALICE);
	contact_delete(U_CHARL);

	Debug.println();
	Debug.println("================================================");
	Debug.printf( "=== test_contacts: %d passed, %d failed       ===\n",
		passed, failed);
	Debug.println("================================================");
	Debug.println();
}
