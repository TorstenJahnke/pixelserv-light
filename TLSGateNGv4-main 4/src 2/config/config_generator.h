/* TLSGateNX - Interactive Configuration Generator
 * Copyright (C) 2025 Torsten Jahnke
 */

#ifndef CONFIG_GENERATOR_H
#define CONFIG_GENERATOR_H

#include <stdbool.h>

/* Configuration types */
typedef enum {
    CONFIG_TYPE_MASTER,     /* Master config: /etc/tlsgateNG/tlsgateNG.conf */
    CONFIG_TYPE_INSTANCE    /* Instance config: custom path */
} config_type_t;

/* Interactive configuration generator
 *
 * Walks user through all configuration options and generates a complete config file.
 *
 * Features:
 * - Master config: Global settings (prime pool, keypool, version)
 * - Instance config: Per-instance settings (ports, CA, certs, etc.)
 * - Default value suggestions
 * - Input validation
 * - Directory existence checks
 * - Automatic permission detection
 *
 * Returns:
 *   0 on success (config file created)
 *   1 on error or user abort
 */
int generate_config_interactive(void);

#endif /* CONFIG_GENERATOR_H */
