/*
 * TLSGateNGv4 - Address Validation Utility
 * Copyright (C) 2025 Torsten Jahnke
 *
 * IPv4/IPv6 address validation - centralized, reusable validation functions
 */

#ifndef ADDRESS_VALIDATION_H
#define ADDRESS_VALIDATION_H

#include <stdbool.h>
#include <netinet/in.h>

/**
 * Validate IPv4 address and convert to binary network form
 *
 * @param addr     - Null-terminated IPv4 address string (e.g., "192.168.1.1")
 * @param result   - Pointer to struct in_addr to receive binary form
 * @return         - true if valid IPv4 address, false otherwise
 */
bool is_valid_ipv4(const char *addr, struct in_addr *result);

/**
 * Validate IPv6 address and convert to binary network form
 *
 * @param addr     - Null-terminated IPv6 address string (e.g., "::1" or "fe80::1")
 * @param result   - Pointer to struct in6_addr to receive binary form
 * @return         - true if valid IPv6 address, false otherwise
 */
bool is_valid_ipv6(const char *addr, struct in6_addr *result);

#endif /* ADDRESS_VALIDATION_H */
