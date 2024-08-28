package account

import (
	"fmt"
	"math"

	"github.com/nicksrepo/padawanzero/internal/common"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/util/random"
)

// ConvertToPrecisionGrid function converts latitude and longitude into a precision grid.
func ConvertToPrecisionGrid(lat, lon, precision float64) (SafeLatitudeLongitude, error) {
	if precision <= 0 {
		return nil, fmt.Errorf("precision must be greater than zero")
	}

	// Constants for conversion
	const latDegreeToMeter = 111319.9 // meters per degree latitude
	longitudeDegreeToMeter := math.Cos(lat*math.Pi/180) * latDegreeToMeter

	// Convert latitude and longitude to a discrete value based on precision
	latIndex := int(math.Round(lat * latDegreeToMeter / precision))
	longIndex := int(math.Round(lon * longitudeDegreeToMeter / precision))

	return SafeLatitudeLongitude{latIndex, longIndex}, nil
}

// CommitLocation function generates a cryptographic commitment to a location.
func CommitLocation(classicalPrivateKey kyber.Scalar, location []byte) (kyber.Scalar, kyber.Point, error) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Generate a quantum key pair
	quantumPublicKey, quantumPrivateKey, err := common.GenerateQuantumKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate quantum key pair: %v", err)
	}

	// Derive an Edwards25519 point from the quantum keys
	commitment, err := common.QuantumDeriveEdwardsPoint(quantumPublicKey, quantumPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Edwards point: %v", err)
	}

	// Combine the classical private key with the commitment
	combinedCommitment := suite.Point().Mul(classicalPrivateKey, commitment)

	return classicalPrivateKey, combinedCommitment, nil
}

// Set updates the SafeLatitudeLongitude with new latitude and longitude values.
func (s *SafeLatitudeLongitude) Set(lat, lon, precision float64) error {
	converted, err := ConvertToPrecisionGrid(lat, lon, precision)
	if err != nil {
		return err
	}
	*s = converted
	return nil
}

// Bytes serializes the SafeLatitudeLongitude into a byte slice.
func (s SafeLatitudeLongitude) Bytes() ([]byte, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize SafeLatitudeLongitude: %v", err)
	}
	return data, nil
}

// GetDynamicPrecision provides a placeholder function for dynamic precision adjustment.
func GetDynamicPrecision() (float64, error) {
	// In a real scenario, this function would dynamically adjust the precision based on context
	return 100.0, nil // Example precision value in meters
}

func EncodeLocationCommitment(suite kyber.Group, commitment kyber.Point) ([]byte, error) {

	cb, err := commitment.MarshalBinary()

	return cb, err
}

func DecodeLocationCommitment(suite kyber.Group, commitment []byte) kyber.Point {

	point := suite.Point().Pick(random.New())
	err := point.UnmarshalBinary(commitment)
	if err != nil {
		return nil
	}

	return point
}
