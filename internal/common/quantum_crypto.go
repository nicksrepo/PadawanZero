package common

/*
#cgo CFLAGS: -I/usr/local/include
#cgo LDFLAGS: -L/usr/local/lib -loqs
#include <stdlib.h>
#include "quantum_crypto.h"
*/
import "C"
import (
	"crypto/sha256"
	"fmt"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"unsafe"
)

const (
	PublicKeySize    = 800
	SecretKeySize    = 1632
	CiphertextSize   = 768
	SharedSecretSize = 32
)

func GenerateQuantumKeyPair() ([]byte, []byte, error) {
	publicKey := make([]byte, PublicKeySize)
	secretKey := make([]byte, SecretKeySize)

	result := C.generate_keypair((*C.uint8_t)(unsafe.Pointer(&publicKey[0])), (*C.uint8_t)(unsafe.Pointer(&secretKey[0])))
	if result == 0 {
		return nil, nil, fmt.Errorf("failed to generate key pair")
	}

	return publicKey, secretKey, nil
}

func Encapsulate(publicKey []byte) ([]byte, []byte, error) {
	if len(publicKey) != PublicKeySize {
		return nil, nil, fmt.Errorf("invalid public key size")
	}

	ciphertext := make([]byte, CiphertextSize)
	sharedSecret := make([]byte, SharedSecretSize)

	result := C.encapsulate((*C.uint8_t)(unsafe.Pointer(&publicKey[0])), (*C.uint8_t)(unsafe.Pointer(&ciphertext[0])), (*C.uint8_t)(unsafe.Pointer(&sharedSecret[0])))
	if result == 0 {
		return nil, nil, fmt.Errorf("encapsulation failed")
	}

	return ciphertext, sharedSecret, nil
}

func Decapsulate(secretKey, ciphertext []byte) ([]byte, error) {
	if len(secretKey) != SecretKeySize {
		return nil, fmt.Errorf("invalid secret key size")
	}
	if len(ciphertext) != CiphertextSize {
		return nil, fmt.Errorf("invalid ciphertext size")
	}

	sharedSecret := make([]byte, SharedSecretSize)

	result := C.decapsulate((*C.uint8_t)(unsafe.Pointer(&secretKey[0])), (*C.uint8_t)(unsafe.Pointer(&ciphertext[0])), (*C.uint8_t)(unsafe.Pointer(&sharedSecret[0])))
	if result == 0 {
		return nil, fmt.Errorf("decapsulation failed")
	}

	return sharedSecret, nil
}

func QuantumPointMul(point, scalar []byte) ([]byte, error) {
	if len(point) != PublicKeySize || len(scalar) != SecretKeySize {
		return nil, fmt.Errorf("invalid input lengths")
	}

	// Use encapsulation as a replacement for point multiplication
	_, sharedSecret, err := Encapsulate(point)
	if err != nil {
		return nil, err
	}

	// Use the shared secret and scalar to derive a new point
	h := sha256.New()
	h.Write(sharedSecret)
	h.Write(scalar)
	derivedPoint := h.Sum(nil)

	// Pad the derived point to match the public key size
	result := make([]byte, PublicKeySize)
	copy(result, derivedPoint)

	return result, nil
}

func QuantumDeriveEdwardsPoint(quantumPublicKey, quantumPrivateKey []byte) (kyber.Point, error) {
	if len(quantumPublicKey) != PublicKeySize || len(quantumPrivateKey) != SecretKeySize {
		return nil, fmt.Errorf("invalid input lengths")
	}

	// Use encapsulation to generate a shared secret
	_, sharedSecret, err := Encapsulate(quantumPublicKey)
	if err != nil {
		return nil, err
	}

	// Combine shared secret with private key to derive a new seed
	h := sha256.New()
	h.Write(sharedSecret)
	h.Write(quantumPrivateKey)
	seed := h.Sum(nil)

	// Use the seed to generate an Edwards25519 point
	suite := edwards25519.NewBlakeSHA256Ed25519()
	point := suite.Point().Pick(suite.XOF(seed))

	return point, nil
}
