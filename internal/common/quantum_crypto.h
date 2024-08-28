#ifndef QUANTUM_CRYPTO_H
#define QUANTUM_CRYPTO_H

#include <stdint.h>

int generate_keypair(uint8_t *public_key, uint8_t *secret_key);
int encapsulate(const uint8_t *public_key, uint8_t *ciphertext, uint8_t *shared_secret);
int decapsulate(const uint8_t *secret_key, const uint8_t *ciphertext, uint8_t *shared_secret);

#endif // QUANTUM_CRYPTO_H