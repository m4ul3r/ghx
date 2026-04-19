/*
 * Challenge 3: authd
 *
 * A fake authentication check against a hardcoded user table. Exercises
 * string inspection, imports analysis, control-flow recovery, and
 * flag-bit field-xrefs.
 *
 * NOT A REAL AUTH SYSTEM. The "hashing" is XOR + rotation for reversibility
 * in an RE exercise. Do not copy this pattern into anything real.
 *
 * Build with:  gcc -O2 -fno-inline -o authd authd.c
 * Strip with:  strip --strip-all authd
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define USER_FLAG_ENABLED   0x01u
#define USER_FLAG_ADMIN     0x02u
#define USER_FLAG_LOCKED    0x04u
#define USER_FLAG_MFA       0x08u

struct UserRecord {
    char      username[32];
    uint8_t   salt[8];
    uint8_t   hash[32];
    uint32_t  flags;
    uint32_t  fail_count;
};

static uint32_t rotl32(uint32_t x, int n) { n &= 31; return (x << n) | (x >> (32 - n)); }

static void toy_hash(const char *input, const uint8_t salt[8], uint8_t out[32]) {
    uint32_t state[8] = {
        0xdeadbeef, 0x0badc0de, 0xfeedface, 0xcafebabe,
        0x01234567, 0x89abcdef, 0xdecafbad, 0x0ddba11c,
    };
    for (int i = 0; i < 8; ++i) {
        state[i] ^= (uint32_t)salt[i];
        state[i] = rotl32(state[i], 7);
    }
    for (size_t i = 0; input[i]; ++i) {
        state[i & 7] = rotl32(state[i & 7] ^ (uint8_t)input[i], 11);
        state[(i + 3) & 7] += state[i & 7];
    }
    for (int i = 0; i < 8; ++i) {
        state[i] = rotl32(state[i], 13) ^ 0xa5a5a5a5;
    }
    for (int i = 0; i < 8; ++i) {
        out[i * 4 + 0] = (uint8_t)(state[i]);
        out[i * 4 + 1] = (uint8_t)(state[i] >> 8);
        out[i * 4 + 2] = (uint8_t)(state[i] >> 16);
        out[i * 4 + 3] = (uint8_t)(state[i] >> 24);
    }
}

static struct UserRecord users[] = {
    { "admin",   {0x5a, 0x37, 0x01, 0xff, 0x17, 0x8c, 0x21, 0x44},
                 {0}, USER_FLAG_ENABLED | USER_FLAG_ADMIN | USER_FLAG_MFA, 0 },
    { "alice",   {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
                 {0}, USER_FLAG_ENABLED, 0 },
    { "bob",     {0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06, 0x17},
                 {0}, USER_FLAG_ENABLED, 0 },
    { "guest",   {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                 {0}, USER_FLAG_ENABLED | USER_FLAG_LOCKED, 0 },
};
static const size_t user_count = sizeof(users) / sizeof(users[0]);

static void seed_hashes(void) {
    toy_hash("hunter2",      users[0].salt, users[0].hash);
    toy_hash("correct horse",users[1].salt, users[1].hash);
    toy_hash("password",     users[2].salt, users[2].hash);
    toy_hash("",             users[3].salt, users[3].hash);
}

static struct UserRecord *find_user(const char *name) {
    for (size_t i = 0; i < user_count; ++i) {
        if (strncmp(users[i].username, name, sizeof(users[i].username)) == 0) {
            return &users[i];
        }
    }
    return NULL;
}

static int user_is_allowed(const struct UserRecord *u) {
    if (!(u->flags & USER_FLAG_ENABLED))  return 0;
    if (  u->flags & USER_FLAG_LOCKED )   return 0;
    if (u->fail_count >= 5)               return 0;
    return 1;
}

static int check_password(struct UserRecord *u, const char *attempt) {
    uint8_t digest[32];
    toy_hash(attempt, u->salt, digest);
    int match = memcmp(digest, u->hash, sizeof(digest)) == 0;
    if (!match) {
        u->fail_count += 1;
        if (u->fail_count >= 5) u->flags |= USER_FLAG_LOCKED;
    } else {
        u->fail_count = 0;
    }
    return match;
}

static int authenticate(const char *name, const char *attempt) {
    struct UserRecord *u = find_user(name);
    if (!u) {
        fprintf(stderr, "authd: no such user\n");
        return 1;
    }
    if (!user_is_allowed(u)) {
        fprintf(stderr, "authd: account unavailable (flags=0x%x, fails=%u)\n",
                u->flags, u->fail_count);
        return 2;
    }
    if (!check_password(u, attempt)) {
        fprintf(stderr, "authd: invalid credentials (fails=%u)\n", u->fail_count);
        return 3;
    }
    printf("authd: welcome %s%s\n",
           u->username,
           (u->flags & USER_FLAG_ADMIN) ? " (admin)" : "");
    if (u->flags & USER_FLAG_MFA) {
        printf("authd: mfa challenge required\n");
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <username> <password>\n", argv[0]);
        return 64;
    }
    seed_hashes();
    return authenticate(argv[1], argv[2]);
}
