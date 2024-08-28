package account

import (
	"PadawanZero/internal/common"
	"PadawanZero/internal/state"
	libzk13 "PadawanZero/zero-knowledge"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"sync"

	lru "github.com/hashicorp/golang-lru"
	jsoniter "github.com/json-iterator/go"
	"github.com/kr/pretty"
	"github.com/zeebo/blake3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/util/random"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// SafeLatitudeLongitude represents an anonymized geographical location.
type SafeLatitudeLongitude []int

// NetworkAddress includes cryptographic elements and an anonymized location.
type NetworkAddress struct {
	AnonGeoLocation    SafeLatitudeLongitude
	LocationCommitment kyber.Point   `json:"locationCommitment"`
	ZKP                *libzk13.ZK13 `json:"-"`
	PrivateKey         kyber.Scalar  `json:"-"`
	PublicKey          kyber.Point   `json:"public_key"`
	r, P               *big.Int
	Suite              kyber.Group
	Nonce              *state.Nonce
}

// AddressInfo provides a serializable and usable representation of NetworkAddress.
type AddressInfo struct {
	PublicKey          string `json:"publicKey"`
	LocationCommitment string `json:"locationCommitment"`
	ZKPProof           string `json:"zkpProof"`
	NonceValue         string
	NonceHash          string
}

var (
	suitePool = sync.Pool{
		New: func() interface{} {
			return edwards25519.NewBlakeSHA256Ed25519()
		},
	}
	addressInfoPool = sync.Pool{
		New: func() interface{} {
			return &AddressInfo{}
		},
	}
	addressCache, _ = lru.New(100) // Cache size of 1000
)

func getSuite() kyber.Group {
	return suitePool.Get().(kyber.Group)
}

func putSuite(suite kyber.Group) {
	suitePool.Put(suite)
}

func getAddressInfo() *AddressInfo {
	return addressInfoPool.Get().(*AddressInfo)
}

func putAddressInfo(ai *AddressInfo) {
	ai.PublicKey = ""
	ai.LocationCommitment = ""
	ai.ZKPProof = ""
	addressInfoPool.Put(ai)
}

func GenerateCryptoKeys() (kyber.Group, kyber.Scalar, kyber.Point, error) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Generate classical keys
	classicalPrivateKey := suite.Scalar().Pick(suite.RandomStream())
	classicalPublicKey := suite.Point().Mul(classicalPrivateKey, nil)

	// Generate quantum keys
	quantumPublicKey, quantumPrivateKey, err := common.GenerateQuantumKeyPair()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate quantum key pair: %v", err)
	}

	// Derive an Edwards25519 point from the quantum keys
	quantumDerivedPoint, err := common.QuantumDeriveEdwardsPoint(quantumPublicKey, quantumPrivateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to derive Edwards point: %v", err)
	}

	// Combine classical and quantum-derived public keys
	combinedPublicKey := suite.Point().Add(classicalPublicKey, quantumDerivedPoint)

	return suite, classicalPrivateKey, combinedPublicKey, nil
}

// NewNetworkAddress initializes a NetworkAddress with given latitude and longitude.
func NewNetworkAddress(lat, lon float64) (*NetworkAddress, error) {
	// Validate latitude and longitude
	if lat < -90 || lat > 90 {
		return nil, fmt.Errorf("invalid latitude: %f, must be between -90 and 90", lat)
	}
	if lon < -180 || lon > 180 {
		return nil, fmt.Errorf("invalid longitude: %f, must be between -180 and 180", lon)
	}

	suite, privateKey, publicKey, err := GenerateCryptoKeys()
	if err != nil {
		return nil, fmt.Errorf("error generating crypto keys: %w", err)
	}

	precision, err := GetDynamicPrecision()
	if err != nil {
		return nil, fmt.Errorf("error getting dynamic precision: %w", err)
	}

	anonGeoLocation, err := ConvertToPrecisionGrid(lat, lon, precision)
	if err != nil {
		return nil, fmt.Errorf("error converting to precision grid: %w", err)
	}

	anonGeoBytes, err := anonGeoLocation.Bytes()
	if err != nil {
		return nil, fmt.Errorf("error converting anon geo location to bytes: %w", err)
	}

	_, locationCommitment, err := CommitLocation(privateKey, anonGeoBytes)
	if err != nil {
		return nil, fmt.Errorf("error creating location commitment: %w", err)
	}

	key := fmt.Sprintf("%f,%f", lat, lon)
	n := state.GenerateOrUpdateNonce(key)

	na := &NetworkAddress{
		AnonGeoLocation:    anonGeoLocation,
		LocationCommitment: locationCommitment,
		PrivateKey:         privateKey,
		PublicKey:          publicKey,
		Suite:              suite,
		Nonce:              n,
	}

	return na, nil
}

// GenerateZKP generates a Zero-Knowledge Proof for the NetworkAddress.
func (na *NetworkAddress) GenerateZKP(bits int) error {
	if na.AnonGeoLocation == nil || len(na.AnonGeoLocation) == 0 {
		return fmt.Errorf("AnonGeoLocation is empty. Cannot generate ZKP")
	}

	secretBaggage := fmt.Sprintf("%v", na.AnonGeoLocation)
	h := blake3.New()
	h.Write([]byte(secretBaggage))
	hash := h.Sum(nil)

	na.ZKP = libzk13.NewZK13(string(hash), bits)
	r, _ := na.ZKP.Prover(new(big.Int).SetBytes(hash))
	na.r = r.R
	na.P = r.P

	pretty.Logf("zkp: %v", na.ZKP)

	return nil
}

// GenerateAddress creates a new NetworkAddress and encapsulates it into AddressInfo.
func GenerateAddress(lat, lon float64, bits int) (*AddressInfo, error) {
	if bits <= 0 {
		return nil, fmt.Errorf("bits must be positive")
	}

	// Validate latitude and longitude
	if lat < -90 || lat > 90 {
		return nil, fmt.Errorf("invalid latitude: %f, must be between -90 and 90", lat)
	}
	if lon < -180 || lon > 180 {
		return nil, fmt.Errorf("invalid longitude: %f, must be between -180 and 180", lon)
	}

	key := fmt.Sprintf("%f,%f", lat, lon)
	if cached, ok := addressCache.Get(key); ok {
		return cached.(*AddressInfo), nil
	}

	var wg sync.WaitGroup
	wg.Add(4)

	var publicKey, locationCommitment kyber.Point
	var zkpProofStr string
	var nonce *state.Nonce
	var errs [4]error

	go func() {
		defer wg.Done()
		_, _, pk, err := GenerateCryptoKeys()
		publicKey = pk
		errs[0] = err
	}()

	go func() {
		defer wg.Done()
		precision, err := GetDynamicPrecision()
		if err != nil {
			errs[1] = err
			return
		}
		anonGeoLocation, err := ConvertToPrecisionGrid(lat, lon, precision)
		if err != nil {
			errs[1] = err
			return
		}
		anonGeoBytes, err := anonGeoLocation.Bytes()
		if err != nil {
			errs[1] = err
			return
		}
		_, lc, err := CommitLocation(edwards25519.NewBlakeSHA256Ed25519().Scalar().Pick(random.New()), anonGeoBytes)
		locationCommitment = lc
		errs[1] = err
	}()

	go func() {
		defer wg.Done()
		h := blake3.New()
		h.Write([]byte(fmt.Sprintf("%f,%f", lat, lon)))
		hash := h.Sum(nil)
		zkp := libzk13.NewZK13(string(hash), bits)
		r, _ := zkp.Prover(new(big.Int).SetBytes(hash))
		zkpProofStr = r.R.Text(16) + "|" + r.P.Text(16)
	}()

	go func() {
		defer wg.Done()
		n := state.GenerateOrUpdateNonce(key)
		nonce = n

	}()

	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}

	publicKeyBytes, _ := publicKey.MarshalBinary()
	locationCommitmentBytes, _ := locationCommitment.MarshalBinary()

	ai := &AddressInfo{
		PublicKey:          base64.RawStdEncoding.EncodeToString(publicKeyBytes),
		LocationCommitment: base64.RawStdEncoding.EncodeToString(locationCommitmentBytes),
		ZKPProof:           zkpProofStr,
		NonceValue:         base64.StdEncoding.EncodeToString(nonce.Value),
		NonceHash:          base64.StdEncoding.EncodeToString(nonce.Hash),
	}

	addressCache.Add(key, ai)

	return ai, nil
}

func GenerateAddressesBatch(coords [][2]float64, bits int) ([]*AddressInfo, error) {
	n := len(coords)
	addresses := make([]*AddressInfo, n)
	errs := make([]error, n)

	var wg sync.WaitGroup
	wg.Add(n)

	for i, coord := range coords {
		go func(i int, lat, lon float64) {
			defer wg.Done()
			addresses[i], errs[i] = GenerateAddress(lat, lon, bits)
		}(i, coord[0], coord[1])
	}

	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}

	return addresses, nil
}

func (ai *AddressInfo) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, 1024)
	buf = append(buf, []byte(ai.PublicKey)...)
	buf = append(buf, 0) // separator
	buf = append(buf, []byte(ai.LocationCommitment)...)
	buf = append(buf, 0) // separator
	buf = append(buf, []byte(ai.ZKPProof)...)
	return buf, nil
}

func (ai *AddressInfo) UnmarshalBinary(data []byte) error {
	parts := bytes.Split(data, []byte{0})
	if len(parts) != 3 {
		return errors.New("invalid binary format")
	}
	ai.PublicKey = string(parts[0])
	ai.LocationCommitment = string(parts[1])
	ai.ZKPProof = string(parts[2])
	return nil
}

func GetOrGenerateAddress(lat, lon float64, bits int) (*AddressInfo, error) {
	key := fmt.Sprintf("%f,%f", lat, lon)
	if cached, ok := addressCache.Get(key); ok {
		return cached.(*AddressInfo), nil
	}
	address, err := GenerateAddress(lat, lon, bits)
	if err == nil {
		addressCache.Add(key, address)
	}
	return address, err
}

// MarshalJSON customizes the JSON marshaling for AddressInfo.
func (ai *AddressInfo) MarshalJSON() ([]byte, error) {
	type Alias AddressInfo
	return json.Marshal(&struct {
		*Alias
		PublicKey          string `json:"publicKey"`
		LocationCommitment string `json:"locationCommitment"`
		NonceValue         string `json:"nonceValue"`
		NonceHash          string `json:"nonceHash"`
	}{
		Alias:              (*Alias)(ai),
		PublicKey:          base64.StdEncoding.EncodeToString([]byte(ai.PublicKey)),
		LocationCommitment: base64.StdEncoding.EncodeToString([]byte(ai.LocationCommitment)),
		NonceValue:         base64.StdEncoding.EncodeToString([]byte(ai.NonceValue)),
		NonceHash:          base64.StdEncoding.EncodeToString([]byte(ai.NonceHash)),
	})
}

// UnmarshalJSON customizes the JSON unmarshaling for AddressInfo.
func (ai *AddressInfo) UnmarshalJSON(data []byte) error {
	type Alias AddressInfo
	aux := &struct {
		*Alias
		PublicKey          string `json:"publicKey"`
		LocationCommitment string `json:"locationCommitment"`
		NonceValue         string `json:"nonceValue"`
		NonceHash          string `json:"nonceHash"`
	}{
		Alias: (*Alias)(ai),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	pubKey, err := base64.StdEncoding.DecodeString(aux.PublicKey)
	if err != nil {
		return err
	}
	ai.PublicKey = string(pubKey)

	locCommit, err := base64.StdEncoding.DecodeString(aux.LocationCommitment)
	if err != nil {
		return err
	}
	ai.LocationCommitment = string(locCommit)

	nonceValue, err := base64.StdEncoding.DecodeString(aux.NonceValue)
	if err != nil {
		return err
	}
	ai.NonceValue = string(nonceValue)

	nonceHash, err := base64.StdEncoding.DecodeString(aux.NonceHash)
	if err != nil {
		return err
	}
	ai.NonceHash = string(nonceHash)

	return nil
}
