/*
 * TLSGateNGv4 - Address Validation Utility Implementation
 * Copyright (C) 2025 Torsten Jahnke
 */

#include "address_validation.h"
#include <arpa/inet.h>
#include <string.h>

bool is_valid_ipv4(const char *addr, struct in_addr *result) {
    if (!addr || !result) {
        return false;
    }

    return inet_pton(AF_INET, addr, result) == 1;
}

bool is_valid_ipv6(const char *addr, struct in6_addr *result) {
    if (!addr || !result) {
        return false;
    }

    return inet_pton(AF_INET6, addr, result) == 1;
}
