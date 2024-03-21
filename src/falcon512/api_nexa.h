// Copyright (c) 2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef API_NEXA_H
#define API_NEXA_H

#include <api.h>

#include <stddef.h>
#include <stdint.h>
#include <vector>


/*
 * Generate a new deterministic key pair. Public key goes into pk[], private key in sk[].
 * Key sizes are exact (in bytes):
 *   public (pk): PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES
 *   private (sk): PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES
 *
 * seed is a 48 byte unsigned char array, len is the size of this array
 *
 * Return value: 0 on success, -1 on error.
 */
int falcon_create_deterministic_keypair(uint8_t *pk, uint8_t *sk, uint8_t *seed, uint16_t len);


#endif
