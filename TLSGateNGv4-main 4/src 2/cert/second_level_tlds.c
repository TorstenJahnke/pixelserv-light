/* TLS-Gate NX - Second-Level TLD Management Implementation
 * Copyright (C) 2025 Torsten Jahnke
 */

#include "second_level_tlds.h"
#include "../util/logger.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>

/* Hash table configuration */
#define HASH_TABLE_SIZE 4096  /* Power of 2 for fast modulo */
#define MAX_TLD_LENGTH 128    /* Max length of a TLD string */

/* Hash table entry (linked list for collision resolution) */
typedef struct tld_entry {
    char *tld;                  /* TLD string (without leading dot) */
    struct tld_entry *next;     /* Next entry in collision chain */
} tld_entry_t;

/* TLD set structure */
struct tld_set {
    tld_entry_t *buckets[HASH_TABLE_SIZE];  /* Hash table buckets */
    size_t count;                            /* Number of TLDs loaded */
};

/* djb2 hash function (fast and good distribution) */
static unsigned long hash_string(const char *str) {
    unsigned long hash = 5381;
    int c;

    while ((c = *str++)) {
        /* Convert to lowercase for case-insensitive comparison */
        c = tolower(c);
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    return hash;
}

/* Normalize TLD string (remove leading dot, convert to lowercase) */
static void normalize_tld(const char *input, char *output, size_t output_size) {
    /* Skip leading dot if present */
    if (input[0] == '.') {
        input++;
    }

    /* Copy and convert to lowercase */
    size_t i;
    for (i = 0; i < output_size - 1 && input[i] != '\0'; i++) {
        output[i] = tolower(input[i]);
    }
    output[i] = '\0';
}

/* Create TLD set */
tld_set_t* tld_set_create(size_t initial_capacity) {
    (void)initial_capacity;  /* Unused - we use fixed hash table size */

    tld_set_t *set = calloc(1, sizeof(tld_set_t));
    if (!set) {
        LOG_ERROR("Failed to allocate TLD set");
        return NULL;
    }

    /* Buckets are already zeroed by calloc */
    set->count = 0;

    return set;
}

/* Destroy TLD set */
void tld_set_destroy(tld_set_t *set) {
    if (!set) return;

    /* Free all entries in all buckets */
    for (size_t i = 0; i < HASH_TABLE_SIZE; i++) {
        tld_entry_t *entry = set->buckets[i];
        while (entry) {
            tld_entry_t *next = entry->next;
            free(entry->tld);
            free(entry);
            entry = next;
        }
    }

    free(set);
}

/* Add TLD to set */
bool tld_set_add(tld_set_t *set, const char *tld) {
    if (!set || !tld) {
        return false;
    }

    /* Normalize TLD */
    char normalized[MAX_TLD_LENGTH];
    normalize_tld(tld, normalized, sizeof(normalized));

    /* Skip empty strings */
    if (normalized[0] == '\0') {
        return true;  /* Not an error, just skip */
    }

    /* Calculate hash and bucket */
    unsigned long hash = hash_string(normalized);
    size_t bucket = hash % HASH_TABLE_SIZE;

    /* Check if TLD already exists in bucket (avoid duplicates) */
    tld_entry_t *entry = set->buckets[bucket];
    while (entry) {
        if (strcmp(entry->tld, normalized) == 0) {
            return true;  /* Already exists */
        }
        entry = entry->next;
    }

    /* Create new entry */
    tld_entry_t *new_entry = malloc(sizeof(tld_entry_t));
    if (!new_entry) {
        LOG_ERROR("Failed to allocate TLD entry");
        return false;
    }

    new_entry->tld = strdup(normalized);
    if (!new_entry->tld) {
        LOG_ERROR("Failed to allocate TLD string");
        free(new_entry);
        return false;
    }

    /* Insert at head of bucket */
    new_entry->next = set->buckets[bucket];
    set->buckets[bucket] = new_entry;
    set->count++;

    return true;
}

/* Load TLDs from file */
int tld_set_load_from_file(tld_set_t *set, const char *filepath) {
    if (!set || !filepath) {
        return -1;
    }

    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        LOG_ERROR("Failed to open TLD file %s: %s", filepath, strerror(errno));
        return -1;
    }

    size_t loaded = 0;
    size_t skipped_1st_level = 0;
    char line[MAX_TLD_LENGTH + 10];

    while (fgets(line, sizeof(line), fp)) {
        /* Remove trailing newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }
        if (len > 0 && line[len - 1] == '\r') {
            line[len - 1] = '\0';
            len--;
        }

        /* Skip empty lines and comments */
        if (len == 0 || line[0] == '#') {
            continue;
        }

        /* Filter: Only load 2nd-level TLDs (containing dot after normalization)
         * This allows using the full tld-liste directly without manual filtering.
         *
         * Examples:
         *   .com      → com      (no dot) → skip ❌
         *   .co.uk    → co.uk    (has dot) → load ✅
         *   .com.au   → com.au   (has dot) → load ✅
         */
        char normalized[MAX_TLD_LENGTH];
        normalize_tld(line, normalized, sizeof(normalized));

        if (strchr(normalized, '.') == NULL) {
            /* Skip 1st-level TLDs (e.g., "com", "org", "net") */
            skipped_1st_level++;
            continue;
        }

        /* Add 2nd-level TLD to set */
        if (tld_set_add(set, line)) {
            loaded++;
        }
    }

    fclose(fp);

    LOG_INFO("Loaded %zu 2nd-level TLDs from %s (skipped %zu 1st-level TLDs)",
            loaded, filepath, skipped_1st_level);
    return (int)loaded;
}

/* Check if TLD is in set */
bool tld_set_contains(const tld_set_t *set, const char *tld) {
    if (!set || !tld) {
        return false;
    }

    /* Normalize TLD */
    char normalized[MAX_TLD_LENGTH];
    normalize_tld(tld, normalized, sizeof(normalized));

    if (normalized[0] == '\0') {
        return false;
    }

    /* Calculate hash and bucket */
    unsigned long hash = hash_string(normalized);
    size_t bucket = hash % HASH_TABLE_SIZE;

    /* Search in bucket */
    tld_entry_t *entry = set->buckets[bucket];
    while (entry) {
        if (strcmp(entry->tld, normalized) == 0) {
            return true;
        }
        entry = entry->next;
    }

    return false;
}

/* Check if domain has a 2nd-level TLD */
bool tld_set_is_second_level_domain(const tld_set_t *set, const char *domain) {
    if (!set || !domain) {
        return false;
    }

    /* Find the last two segments of the domain
     * Example: www.example.co.uk → extract "co.uk"
     */
    const char *last_dot = strrchr(domain, '.');
    if (!last_dot) {
        return false;  /* No dots, can't be 2nd-level */
    }

    /* Find second-to-last dot */
    const char *second_last_dot = NULL;
    for (const char *p = domain; p < last_dot; p++) {
        if (*p == '.') {
            second_last_dot = p;
        }
    }

    if (!second_last_dot) {
        return false;  /* Only one dot, can't be 2nd-level */
    }

    /* Extract last two segments (e.g., "co.uk") */
    const char *tld_start = second_last_dot + 1;  /* Skip the dot */
    return tld_set_contains(set, tld_start);
}

/* Get count */
size_t tld_set_count(const tld_set_t *set) {
    return set ? set->count : 0;
}

/* Load TLDs from SHM data buffer */
int tld_set_load_from_shm(tld_set_t *set, const char *data, int data_len) {
    if (!set || !data || data_len <= 0) {
        return -1;
    }

    size_t loaded = 0;
    size_t skipped_1st_level = 0;
    char line[MAX_TLD_LENGTH + 10];
    const char *p = data;
    const char *end = data + data_len;

    while (p < end) {
        /* Find end of line */
        const char *line_end = p;
        while (line_end < end && *line_end != '\n') {
            line_end++;
        }

        /* Copy line to buffer */
        size_t line_len = (size_t)(line_end - p);
        if (line_len > MAX_TLD_LENGTH) {
            line_len = MAX_TLD_LENGTH;
        }

        memcpy(line, p, line_len);
        line[line_len] = '\0';

        /* Move to next line */
        p = (line_end < end) ? line_end + 1 : end;

        /* Remove trailing whitespace/CR */
        while (line_len > 0 && (line[line_len - 1] == '\r' ||
                                 line[line_len - 1] == ' ' ||
                                 line[line_len - 1] == '\t')) {
            line[--line_len] = '\0';
        }

        /* Skip empty lines and comments */
        if (line_len == 0 || line[0] == '#') {
            continue;
        }

        /* Filter: Only load 2nd-level TLDs (containing dot after normalization) */
        char normalized[MAX_TLD_LENGTH];
        normalize_tld(line, normalized, sizeof(normalized));

        if (strchr(normalized, '.') == NULL) {
            /* Skip 1st-level TLDs (e.g., "com", "org", "net") */
            skipped_1st_level++;
            continue;
        }

        /* Add 2nd-level TLD to set */
        if (tld_set_add(set, line)) {
            loaded++;
        }
    }

    LOG_INFO("Loaded %zu 2nd-level TLDs from SHM (skipped %zu 1st-level TLDs)",
            loaded, skipped_1st_level);
    return (int)loaded;
}
