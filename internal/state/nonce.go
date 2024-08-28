package state

import (
	"bytes"
	"crypto/rand"
	"sync"
	"time"

	"github.com/zeebo/blake3"
)

const (
	nonceLifetime = 3600 // Define a suitable nonce lifetime in seconds
	nonceSize     = 32   // Size of the nonce in bytes
)

type Nonce struct {
	Address   string
	Value     []byte
	Hash      []byte
	Timestamp int64
}

var (
	nonces      = make(map[string]Nonce)
	noncesMutex sync.RWMutex
	hashContext = blake3.New()
)

// GenerateOrUpdateNonce creates or updates a nonce for the given address.
func GenerateOrUpdateNonce(address string) *Nonce {
	noncesMutex.Lock()
	defer noncesMutex.Unlock()

	// Check if a nonce already exists for the address
	if nonce, exists := nonces[address]; exists {
		// If nonce exists and is not expired, return it
		if time.Now().Unix()-nonce.Timestamp <= nonceLifetime {
			return &nonce
		}
	}

	// Generate a new nonce for the address
	value := make([]byte, nonceSize)
	_, err := rand.Read(value)
	if err != nil {
		return nil
	}

	hash := generateNonceHash(address, value)
	timestamp := time.Now().Unix()

	nonce := Nonce{
		Address:   address,
		Value:     value,
		Hash:      hash,
		Timestamp: timestamp,
	}

	nonces[address] = nonce

	return &nonce
}

// ValidateNonce checks if a nonce associated with the address is valid.
func ValidateNonce(address string, nonce Nonce) bool {
	noncesMutex.RLock()
	defer noncesMutex.RUnlock()

	if storedNonce, exists := nonces[address]; exists {
		return bytes.Equal(nonce.Value, storedNonce.Value) &&
			bytes.Equal(nonce.Hash, storedNonce.Hash) &&
			time.Now().Unix()-storedNonce.Timestamp <= nonceLifetime
	}
	return false
}

// PruneExpiredNonces removes expired nonces from the map.
func PruneExpiredNonces() {
	noncesMutex.Lock()
	defer noncesMutex.Unlock()

	currentTimestamp := time.Now().Unix()
	for address, nonce := range nonces {
		if currentTimestamp-nonce.Timestamp > nonceLifetime {
			delete(nonces, address)
		}
	}
}

// generateNonceHash generates a hash for a given nonce value using Blake3 context.
func generateNonceHash(address string, value []byte) []byte {
	hashContext.Reset()
	hashContext.Write([]byte(address))
	hashContext.Write(value)
	return hashContext.Sum(nil)
}
