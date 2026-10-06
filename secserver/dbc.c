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

/*
Test functions for database operations
1. test activation code addition, with db_add_activation, it should reject duplicate codes, and accept new ones
2. test user validation with db_validate_user, it should accept existing valid keys, and reject non-existing keys
*/

// main processes the following command line arguments:
// 1. code <code> - adds a new activation code to the database
// 2. validate <hex_key> - validates if the given public key (hex string) exists in the database and is valid
int main(int argc, char *argv[]) {
    // Initialize database connection
    if (db_init() != 0) {
        printf("Database initialization failed.\n");
        return 1;
    }

    if (argc < 3) {
        printf("Usage:\n");
        printf("  %s code <code>\n", argv[0]);
        printf("  %s validate <hex_key>\n", argv[0]);
        return 0;
    }

    if (strcmp(argv[1], "code") == 0) {
        char *code = argv[2];
        if (db_add_activation(code)) {
            printf("Added activation code: %s\n", code);
        } else {
            printf("Failed to add activation code: %s\n", code);
        }
    } else if (strcmp(argv[1], "validate") == 0) {
        char *hex_key = argv[2];
        uint8_t key[KEY_LEN];
        hex2bytes(hex_key, key, strlen(hex_key));
        int result = db_validate_user(key);
        if (result == 0) {
            printf("User is valid: %s\n", hex_key);
        } else if (result == -2) {
            printf("User does not exist or is expired: %s\n", hex_key);
        } else {
            printf("Failed to validate user with key: %s\n", hex_key);
        }
    } else {
        printf("Unknown command: %s\n", argv[1]);
    }
    return 0;
}