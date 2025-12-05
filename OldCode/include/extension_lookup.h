/* extension_lookup.h */
#ifndef EXTENSION_LOOKUP_H
#define EXTENSION_LOOKUP_H

/* Use existing ultra-fast extension_hash_table.h */
#include "extension_hash_table.h"

/* Public functions that work with existing hash table */
void extension_lookup_init(void);
void extension_lookup_cleanup(void);

/* Main lookup function - uses existing ultra-fast binary search */
const extension_entry_t* extension_lookup_get(const char *extension);

/* AdBlock detection helpers */
int extension_needs_randomization(const char *extension);
int extension_get_cache_time(const char *extension);

/* CSP/Security helpers */
csp_policy_type_t extension_get_csp_policy(const char *extension);
const char* extension_get_content_type(const char *extension);

#endif /* EXTENSION_LOOKUP_H */
