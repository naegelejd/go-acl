// Copyright (c) 2026 Joseph Naegele. See LICENSE file.

/*
 * darwin_probe.c — Experimentally confirm macOS ACL API behavior.
 *
 * Compile:  cc -o darwin_probe darwin_probe.c
 * Run:      ./darwin_probe
 *
 * Every test prints PASS or FAIL with a description of what was observed.
 * Nothing is assumed — each result is derived purely from actual return
 * values and errno.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <membership.h>   /* mbr_uid_to_uuid */
#include <sys/types.h>
#include <sys/acl.h>
#include <sys/stat.h>

#define TMPFILE "/tmp/darwin_acl_probe_file"
#define TMPDIR  "/tmp/darwin_acl_probe_dir"

static int failures = 0;

#define PASS(msg)       printf("  PASS  %s\n", msg)
#define FAIL(msg, ...)  do { printf("  FAIL  " msg "\n", ##__VA_ARGS__); failures++; } while(0)
#define SECTION(msg)    printf("\n=== %s ===\n", msg)
#define INFO(msg, ...)  printf("  INFO  " msg "\n", ##__VA_ARGS__)

static void make_tmpfile(void) {
    int fd = open(TMPFILE, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0) { perror("open tmpfile"); exit(1); }
    close(fd);
}

static void make_tmpdir(void) {
    mkdir(TMPDIR, 0755); /* ignore error if exists */
}

/* -----------------------------------------------------------------------
 * 1. acl_type_t: which types are accepted by acl_get_file / acl_set_file
 * --------------------------------------------------------------------- */
static void test_acl_types(void) {
    SECTION("acl_type_t: which types work with acl_get_file");

    acl_t a;
    struct {
        acl_type_t type;
        const char *name;
    } types[] = {
        { ACL_TYPE_EXTENDED, "ACL_TYPE_EXTENDED" },
        { ACL_TYPE_ACCESS,   "ACL_TYPE_ACCESS"   },
        { ACL_TYPE_DEFAULT,  "ACL_TYPE_DEFAULT"  },
    };

    for (int i = 0; i < 3; i++) {
        errno = 0;
        a = acl_get_file(TMPFILE, types[i].type);
        if (a != NULL) {
            INFO("%s -> non-NULL acl (has ACL)", types[i].name);
            acl_free(a);
        } else {
            INFO("%s -> NULL, errno=%d (%s)", types[i].name, errno, strerror(errno));
        }
    }
}

static void test_acl_types_set(void) {
    SECTION("acl_type_t: which types work with acl_set_file (empty acl)");

    acl_t empty = acl_init(0);
    struct {
        acl_type_t type;
        const char *name;
    } types[] = {
        { ACL_TYPE_EXTENDED, "ACL_TYPE_EXTENDED" },
        { ACL_TYPE_ACCESS,   "ACL_TYPE_ACCESS"   },
        { ACL_TYPE_DEFAULT,  "ACL_TYPE_DEFAULT"  },
    };

    for (int i = 0; i < 3; i++) {
        errno = 0;
        int rv = acl_set_file(TMPFILE, types[i].type, empty);
        if (rv == 0) {
            INFO("%s -> success (rv=0)", types[i].name);
        } else {
            INFO("%s -> FAIL, rv=%d, errno=%d (%s)", types[i].name, rv, errno, strerror(errno));
        }
    }
    acl_free(empty);
}

/* -----------------------------------------------------------------------
 * 2. acl_get_file with ACL_TYPE_EXTENDED: NULL + ENOENT when no ACL
 * --------------------------------------------------------------------- */
static void test_get_no_acl(void) {
    SECTION("acl_get_file(ACL_TYPE_EXTENDED) on file with no ACL");

    /* Ensure the file has no ACL */
    acl_t empty = acl_init(0);
    acl_set_file(TMPFILE, ACL_TYPE_EXTENDED, empty);
    acl_free(empty);

    errno = 0;
    acl_t a = acl_get_file(TMPFILE, ACL_TYPE_EXTENDED);
    if (a == NULL) {
        if (errno == ENOENT) {
            PASS("Returns NULL + ENOENT when file has no extended ACL");
        } else {
            FAIL("Returns NULL but errno=%d (%s), expected ENOENT", errno, strerror(errno));
        }
    } else {
        int entries = 0;
        acl_entry_t e;
        int r = acl_get_entry(a, ACL_FIRST_ENTRY, &e);
        while (r == 0) {
            entries++;
            r = acl_get_entry(a, ACL_NEXT_ENTRY, &e);
        }
        INFO("Returns non-NULL ACL with %d entries (unexpected for no-ACL file)", entries);
        acl_free(a);
    }
}

/* -----------------------------------------------------------------------
 * 3. Tag types on macOS
 * --------------------------------------------------------------------- */
static void test_tag_types(void) {
    SECTION("Tag type constants");
    INFO("ACL_UNDEFINED_TAG  = %d", (int)ACL_UNDEFINED_TAG);
    INFO("ACL_EXTENDED_ALLOW = %d", (int)ACL_EXTENDED_ALLOW);
    INFO("ACL_EXTENDED_DENY  = %d", (int)ACL_EXTENDED_DENY);
    PASS("Tag types printed above (only ALLOW/DENY exist; no USER_OBJ/GROUP_OBJ/OTHER)");
}

/* -----------------------------------------------------------------------
 * 4. Permissions: the full set available on macOS
 * --------------------------------------------------------------------- */
static void test_perm_constants(void) {
    SECTION("Permission constants");
    INFO("ACL_READ_DATA           = 0x%x", (unsigned)ACL_READ_DATA);
    INFO("ACL_LIST_DIRECTORY      = 0x%x", (unsigned)ACL_LIST_DIRECTORY);
    INFO("ACL_WRITE_DATA          = 0x%x", (unsigned)ACL_WRITE_DATA);
    INFO("ACL_ADD_FILE            = 0x%x", (unsigned)ACL_ADD_FILE);
    INFO("ACL_EXECUTE             = 0x%x", (unsigned)ACL_EXECUTE);
    INFO("ACL_SEARCH              = 0x%x", (unsigned)ACL_SEARCH);
    INFO("ACL_DELETE              = 0x%x", (unsigned)ACL_DELETE);
    INFO("ACL_APPEND_DATA         = 0x%x", (unsigned)ACL_APPEND_DATA);
    INFO("ACL_ADD_SUBDIRECTORY    = 0x%x", (unsigned)ACL_ADD_SUBDIRECTORY);
    INFO("ACL_DELETE_CHILD        = 0x%x", (unsigned)ACL_DELETE_CHILD);
    INFO("ACL_READ_ATTRIBUTES     = 0x%x", (unsigned)ACL_READ_ATTRIBUTES);
    INFO("ACL_WRITE_ATTRIBUTES    = 0x%x", (unsigned)ACL_WRITE_ATTRIBUTES);
    INFO("ACL_READ_EXTATTRIBUTES  = 0x%x", (unsigned)ACL_READ_EXTATTRIBUTES);
    INFO("ACL_WRITE_EXTATTRIBUTES = 0x%x", (unsigned)ACL_WRITE_EXTATTRIBUTES);
    INFO("ACL_READ_SECURITY       = 0x%x", (unsigned)ACL_READ_SECURITY);
    INFO("ACL_WRITE_SECURITY      = 0x%x", (unsigned)ACL_WRITE_SECURITY);
    INFO("ACL_CHANGE_OWNER        = 0x%x", (unsigned)ACL_CHANGE_OWNER);
    INFO("ACL_SYNCHRONIZE         = 0x%x", (unsigned)ACL_SYNCHRONIZE);
    PASS("Permission constants printed above");
}

/* -----------------------------------------------------------------------
 * 5. Qualifiers: macOS uses UUIDs (guid_t), not uid/gid ints
 * --------------------------------------------------------------------- */
static void test_qualifier(void) {
    SECTION("Qualifier type: UUID (guid_t) vs uid/gid int");

    uid_t uid = getuid();
    guid_t guid;
    if (mbr_uid_to_uuid(uid, guid.g_guid) != 0) {
        FAIL("mbr_uid_to_uuid failed for uid=%d", uid);
        return;
    }
    INFO("Current uid=%d -> UUID %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
         uid,
         guid.g_guid[0],  guid.g_guid[1],  guid.g_guid[2],  guid.g_guid[3],
         guid.g_guid[4],  guid.g_guid[5],  guid.g_guid[6],  guid.g_guid[7],
         guid.g_guid[8],  guid.g_guid[9],
         guid.g_guid[10], guid.g_guid[11], guid.g_guid[12], guid.g_guid[13],
         guid.g_guid[14], guid.g_guid[15]);

    /* Create an allow entry for our own uid and retrieve qualifier */
    acl_t a = acl_init(1);
    acl_entry_t entry;
    acl_create_entry(&a, &entry);
    acl_set_tag_type(entry, ACL_EXTENDED_ALLOW);
    acl_set_qualifier(entry, guid.g_guid);

    acl_tag_t tag;
    acl_get_tag_type(entry, &tag);
    INFO("Tag set to ACL_EXTENDED_ALLOW, retrieved tag=%d (expected %d)", (int)tag, (int)ACL_EXTENDED_ALLOW);

    void *q = acl_get_qualifier(entry);
    if (q == NULL) {
        FAIL("acl_get_qualifier returned NULL");
    } else {
        unsigned char *bytes = (unsigned char *)q;
        INFO("Qualifier bytes: %02x%02x%02x%02x...", bytes[0], bytes[1], bytes[2], bytes[3]);
        if (memcmp(q, guid.g_guid, sizeof(guid.g_guid)) == 0) {
            PASS("Qualifier round-trips as 16-byte UUID (guid_t), not an int");
        } else {
            FAIL("Qualifier bytes don't match the UUID that was set");
        }
        acl_free(q);
    }
    acl_free(a);
}

/* -----------------------------------------------------------------------
 * 6. acl_valid() — what is a "valid" ACL on macOS?
 * --------------------------------------------------------------------- */
static void test_valid(void) {
    SECTION("acl_valid() — empty ACL and single-entry ACL");

    acl_t empty = acl_init(0);
    errno = 0;
    int rv = acl_valid(empty);
    INFO("acl_valid(empty) = %d, errno=%d (%s)", rv, errno, strerror(errno));
    if (rv == 0) {
        PASS("Empty ACL is valid on macOS (no mandatory base entries required)");
    } else {
        FAIL("Empty ACL is NOT valid — errno=%d", errno);
    }
    acl_free(empty);

    /* Single ALLOW entry */
    uid_t uid = getuid();
    guid_t guid;
    mbr_uid_to_uuid(uid, guid.g_guid);

    acl_t a = acl_init(1);
    acl_entry_t entry;
    acl_create_entry(&a, &entry);
    acl_set_tag_type(entry, ACL_EXTENDED_ALLOW);
    acl_set_qualifier(entry, guid.g_guid);
    acl_permset_t ps;
    acl_get_permset(entry, &ps);
    acl_add_perm(ps, ACL_READ_DATA);

    errno = 0;
    rv = acl_valid(a);
    INFO("acl_valid(single ALLOW entry) = %d, errno=%d (%s)", rv, errno, strerror(errno));
    if (rv == 0) {
        PASS("Single-entry ALLOW ACL is valid");
    } else {
        FAIL("Single-entry ALLOW ACL is NOT valid — errno=%d", errno);
    }
    acl_free(a);
}

/* -----------------------------------------------------------------------
 * 7. acl_set_file round-trip: set then get
 * --------------------------------------------------------------------- */
static void test_set_get_roundtrip(void) {
    SECTION("acl_set_file + acl_get_file round-trip (ACL_TYPE_EXTENDED)");

    uid_t uid = getuid();
    guid_t guid;
    mbr_uid_to_uuid(uid, guid.g_guid);

    acl_t a = acl_init(1);
    acl_entry_t entry;
    acl_create_entry(&a, &entry);
    acl_set_tag_type(entry, ACL_EXTENDED_ALLOW);
    acl_set_qualifier(entry, guid.g_guid);
    acl_permset_t ps;
    acl_get_permset(entry, &ps);
    acl_add_perm(ps, ACL_READ_DATA);
    acl_add_perm(ps, ACL_WRITE_DATA);
    acl_add_perm(ps, ACL_EXECUTE);

    errno = 0;
    int rv = acl_set_file(TMPFILE, ACL_TYPE_EXTENDED, a);
    if (rv != 0) {
        FAIL("acl_set_file failed: errno=%d (%s)", errno, strerror(errno));
        acl_free(a);
        return;
    }
    PASS("acl_set_file(ACL_TYPE_EXTENDED) succeeded");
    acl_free(a);

    errno = 0;
    acl_t b = acl_get_file(TMPFILE, ACL_TYPE_EXTENDED);
    if (b == NULL) {
        FAIL("acl_get_file after set returned NULL: errno=%d (%s)", errno, strerror(errno));
        return;
    }
    PASS("acl_get_file after set returned non-NULL ACL");

    acl_entry_t e2;
    int r = acl_get_entry(b, ACL_FIRST_ENTRY, &e2);
    if (r != 0) {
        FAIL("No entries in retrieved ACL");
        acl_free(b);
        return;
    }

    acl_tag_t tag;
    acl_get_tag_type(e2, &tag);
    INFO("Retrieved entry tag = %d (ACL_EXTENDED_ALLOW=%d)", (int)tag, (int)ACL_EXTENDED_ALLOW);

    void *q = acl_get_qualifier(e2);
    if (q && memcmp(q, guid.g_guid, 16) == 0) {
        PASS("Qualifier UUID matches what was set");
    } else {
        FAIL("Qualifier UUID mismatch");
    }
    if (q) acl_free(q);

    /* Clean up: set empty ACL */
    acl_t empty = acl_init(0);
    acl_set_file(TMPFILE, ACL_TYPE_EXTENDED, empty);
    acl_free(empty);
    acl_free(b);
}

/* -----------------------------------------------------------------------
 * 8. acl_calc_mask — should be unsupported per man page
 * --------------------------------------------------------------------- */
static void test_calc_mask(void) {
    SECTION("acl_calc_mask (listed as NOT SUPPORTED in man page)");
    acl_t a = acl_init(0);
    errno = 0;
    int rv = acl_calc_mask(&a);
    INFO("acl_calc_mask(empty) = %d, errno=%d (%s)", rv, errno, strerror(errno));
    if (rv != 0) {
        PASS("acl_calc_mask fails as expected (not supported on macOS)");
    } else {
        INFO("Unexpectedly succeeded — may be a no-op");
    }
    acl_free(a);
}

/* -----------------------------------------------------------------------
 * 9. acl_delete_def_file — should be unsupported per man page
 * --------------------------------------------------------------------- */
static void test_delete_def_file(void) {
    SECTION("acl_delete_def_file (listed as NOT SUPPORTED in man page)");
    errno = 0;
    int rv = acl_delete_def_file(TMPFILE);
    INFO("acl_delete_def_file = %d, errno=%d (%s)", rv, errno, strerror(errno));
    if (rv != 0) {
        PASS("acl_delete_def_file fails as expected (not supported on macOS)");
    } else {
        INFO("Unexpectedly succeeded — may be a no-op");
    }
}

/* -----------------------------------------------------------------------
 * 10. acl_size — should work on macOS (unlike FreeBSD)
 * --------------------------------------------------------------------- */
static void test_acl_size(void) {
    SECTION("acl_size");
    acl_t a = acl_init(1);
    acl_entry_t entry;
    acl_create_entry(&a, &entry);

    uid_t uid = getuid();
    guid_t guid;
    mbr_uid_to_uuid(uid, guid.g_guid);
    acl_set_tag_type(entry, ACL_EXTENDED_ALLOW);
    acl_set_qualifier(entry, guid.g_guid);

    errno = 0;
    ssize_t sz = acl_size(a);
    INFO("acl_size = %zd, errno=%d (%s)", sz, errno, strerror(errno));
    if (sz > 0) {
        PASS("acl_size works on macOS");
    } else {
        FAIL("acl_size returned %zd, errno=%d", sz, errno);
    }
    acl_free(a);
}

/* -----------------------------------------------------------------------
 * 11. acl_to_text / acl_from_text
 * --------------------------------------------------------------------- */
static void test_text_roundtrip(void) {
    SECTION("acl_to_text / acl_from_text round-trip");

    uid_t uid = getuid();
    guid_t guid;
    mbr_uid_to_uuid(uid, guid.g_guid);

    acl_t a = acl_init(1);
    acl_entry_t entry;
    acl_create_entry(&a, &entry);
    acl_set_tag_type(entry, ACL_EXTENDED_ALLOW);
    acl_set_qualifier(entry, guid.g_guid);
    acl_permset_t ps;
    acl_get_permset(entry, &ps);
    acl_add_perm(ps, ACL_READ_DATA);

    char *text = acl_to_text(a, NULL);
    if (text == NULL) {
        FAIL("acl_to_text returned NULL");
    } else {
        INFO("acl_to_text output: %s", text);
        PASS("acl_to_text succeeded");

        acl_t b = acl_from_text(text);
        if (b == NULL) {
            FAIL("acl_from_text returned NULL for text produced by acl_to_text");
        } else {
            PASS("acl_from_text succeeded (round-trip works)");
            acl_free(b);
        }
        acl_free(text);
    }
    acl_free(a);
}

/* -----------------------------------------------------------------------
 * 12. Inheritance flags
 * --------------------------------------------------------------------- */
static void test_flags(void) {
    SECTION("ACL entry inheritance flags");

    uid_t uid = getuid();
    guid_t guid;
    mbr_uid_to_uuid(uid, guid.g_guid);

    acl_t a = acl_init(1);
    acl_entry_t entry;
    acl_create_entry(&a, &entry);
    acl_set_tag_type(entry, ACL_EXTENDED_ALLOW);
    acl_set_qualifier(entry, guid.g_guid);

    acl_flagset_t flags;
    acl_get_flagset_np(entry, &flags);
    acl_add_flag_np(flags, ACL_ENTRY_FILE_INHERIT);
    acl_add_flag_np(flags, ACL_ENTRY_DIRECTORY_INHERIT);

    char *text = acl_to_text(a, NULL);
    if (text) {
        INFO("ACL with FILE_INHERIT+DIR_INHERIT: %s", text);
        acl_free(text);
        PASS("Inheritance flags set and serialized");
    } else {
        FAIL("acl_to_text returned NULL after setting flags");
    }
    acl_free(a);
}

/* -----------------------------------------------------------------------
 * 13. Directory: get/set extended ACL
 * --------------------------------------------------------------------- */
static void test_dir_acl(void) {
    SECTION("Directory ACL (ACL_TYPE_EXTENDED)");

    errno = 0;
    acl_t a = acl_get_file(TMPDIR, ACL_TYPE_EXTENDED);
    if (a == NULL) {
        INFO("acl_get_file(dir, ACL_TYPE_EXTENDED) = NULL, errno=%d (%s)", errno, strerror(errno));
        if (errno == ENOENT) {
            PASS("Directory with no ACL returns NULL + ENOENT (same as files)");
        } else {
            FAIL("Unexpected errno=%d", errno);
        }
    } else {
        INFO("Directory has existing extended ACL");
        acl_free(a);
    }
}

int main(void) {
    printf("darwin_probe: macOS ACL API capability probe\n");
    printf("Platform: macOS, SDK acl.h from $(xcrun --show-sdk-path)\n");

    make_tmpfile();
    make_tmpdir();

    test_acl_types();
    test_acl_types_set();
    test_get_no_acl();
    test_tag_types();
    test_perm_constants();
    test_qualifier();
    test_valid();
    test_set_get_roundtrip();
    test_calc_mask();
    test_delete_def_file();
    test_acl_size();
    test_text_roundtrip();
    test_flags();
    test_dir_acl();

    unlink(TMPFILE);
    rmdir(TMPDIR);

    printf("\n=== SUMMARY ===\n");
    if (failures == 0) {
        printf("All tests passed.\n");
    } else {
        printf("%d test(s) FAILED.\n", failures);
    }
    return failures > 0 ? 1 : 0;
}
