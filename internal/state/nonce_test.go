package state

import (
	"bytes"
	"testing"
	"time"
)

func TestGenerateOrUpdateNonce(t *testing.T) {
	address := "test_address"

	// Generate a new nonce
	nonce1 := GenerateOrUpdateNonce(address)
	if nonce1 == nil {
		t.Fatal("Failed to generate nonce")
	}

	// Check if the nonce is stored correctly
	if !ValidateNonce(address, *nonce1) {
		t.Error("Generated nonce is not valid")
	}

	// Generate another nonce for the same address
	nonce2 := GenerateOrUpdateNonce(address)
	if nonce2 == nil {
		t.Fatal("Failed to generate second nonce")
	}

	// Check if the second nonce is the same as the first one (not expired)
	if !bytes.Equal(nonce1.Value, nonce2.Value) {
		t.Error("Second nonce should be the same as the first one")
	}
}

func TestValidateNonce(t *testing.T) {
	address := "test_address"
	nonce := GenerateOrUpdateNonce(address)
	if nonce == nil {
		t.Fatal("Failed to generate nonce")
	}

	// Valid nonce
	if !ValidateNonce(address, *nonce) {
		t.Error("Valid nonce not recognized")
	}

	// Invalid address
	if ValidateNonce("wrong_address", *nonce) {
		t.Error("Nonce should not be valid for wrong address")
	}

	// Invalid nonce value
	invalidNonce := *nonce
	invalidNonce.Value = make([]byte, nonceSize)
	invalidNonce.Hash = generateNonceHash("wrong_address", invalidNonce.Value)
	if ValidateNonce(address, invalidNonce) {
		t.Error("Invalid nonce value not detected")
	}
}

func TestPruneExpiredNonces(t *testing.T) {
	address1 := "address1"
	address2 := "address2"

	// Generate nonces
	nonce1 := GenerateOrUpdateNonce(address1)
	nonce2 := GenerateOrUpdateNonce(address2)

	// Manually expire the first nonce
	nonces[address1] = Nonce{
		Address:   address1,
		Value:     nonce1.Value,
		Hash:      nonce1.Hash,
		Timestamp: time.Now().Unix() - nonceLifetime - 1,
	}

	// Prune expired nonces
	PruneExpiredNonces()

	// Check if the expired nonce was removed
	if ValidateNonce(address1, *nonce1) {
		t.Error("Expired nonce should have been pruned")
	}

	// Check if the non-expired nonce is still valid
	if !ValidateNonce(address2, *nonce2) {
		t.Error("Non-expired nonce should still be valid")
	}
}
