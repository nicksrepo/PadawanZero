#include <oqs/oqs.h>
#include <string.h>

int generate_keypair(uint8_t *public_key, uint8_t *secret_key) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == NULL) {
        return 0;
    }

    OQS_STATUS result = OQS_KEM_keypair(kem, public_key, secret_key);
    OQS_KEM_free(kem);

    return (result == OQS_SUCCESS) ? 1 : 0;
}

int encapsulate(const uint8_t *public_key, uint8_t *ciphertext, uint8_t *shared_secret) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == NULL) {
        return 0;
    }

    OQS_STATUS result = OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);
    OQS_KEM_free(kem);

    return (result == OQS_SUCCESS) ? 1 : 0;
}

int decapsulate(const uint8_t *secret_key, const uint8_t *ciphertext, uint8_t *shared_secret) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == NULL) {
        return 0;
    }

    OQS_STATUS result = OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key);
    OQS_KEM_free(kem);

    return (result == OQS_SUCCESS) ? 1 : 0;
}