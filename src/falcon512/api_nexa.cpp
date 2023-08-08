// Copyright (c) 2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cassert>
#include <stddef.h>
#include <string.h>

#include "api_nexa.h"
#include "inner.h"
#include "uint256.h"

int falcon_create_deterministic_keypair(uint8_t *pk, uint8_t *sk, uint8_t *seed, uint16_t len)
{
    assert(len >= 48);

    // Begin key pair section using the seed deteministic seed we created.
    union {
        uint8_t b[FALCON_KEYGEN_TEMP_9];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    int8_t f[512], g[512], F[512];
    uint16_t h[512];
    inner_shake256_context rng;
    size_t u, v;

    /*
     * Generate key pair.
     */
    inner_shake256_init(&rng);
    inner_shake256_inject(&rng, seed, sizeof seed);
    inner_shake256_flip(&rng);
    PQCLEAN_FALCON512_CLEAN_keygen(&rng, f, g, F, NULL, h, 9, tmp.b);
    inner_shake256_ctx_release(&rng);

    /*
     * Encode private key.
     */
    sk[0] = 0x50 + 9;
    u = 1;
    v = PQCLEAN_FALCON512_CLEAN_trim_i8_encode(
            sk + u, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES - u,
            f, 9, PQCLEAN_FALCON512_CLEAN_max_fg_bits[9]);
    if (v == 0) {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON512_CLEAN_trim_i8_encode(
            sk + u, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES - u,
            g, 9, PQCLEAN_FALCON512_CLEAN_max_fg_bits[9]);
    if (v == 0) {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON512_CLEAN_trim_i8_encode(
            sk + u, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES - u,
            F, 9, PQCLEAN_FALCON512_CLEAN_max_FG_bits[9]);
    if (v == 0) {
        return -1;
    }
    u += v;
    if (u != PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES) {
        return -1;
    }

    /*
     * Encode public key.
     */
    pk[0] = 0x00 + 9;
    v = PQCLEAN_FALCON512_CLEAN_modq_encode(
            pk + 1, PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES - 1,
            h, 9);
    if (v != PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES - 1) {
        return -1;
    }

    return 0;
}
