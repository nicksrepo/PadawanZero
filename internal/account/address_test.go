package account

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/rand"
	"runtime"
	"sync"
	"testing"
)

func TestGenerateCryptoKeys(t *testing.T) {
	suite, privateKey, publicKey, err := GenerateCryptoKeys()
	require.NoError(t, err)
	assert.NotNil(t, suite)
	assert.NotNil(t, privateKey)
	assert.NotNil(t, publicKey)
}

func TestNewNetworkAddress(t *testing.T) {
	tests := []struct {
		name    string
		lat     float64
		lon     float64
		wantErr bool
		errMsg  string
	}{
		{"Valid coordinates", 40.7128, -74.0060, false, ""},
		{"Invalid latitude (too high)", 91, 0, true, "invalid latitude: 91.000000, must be between -90 and 90"},
		{"Invalid latitude (too low)", -91, 0, true, "invalid latitude: -91.000000, must be between -90 and 90"},
		{"Invalid longitude (too high)", 0, 181, true, "invalid longitude: 181.000000, must be between -180 and 180"},
		{"Invalid longitude (too low)", 0, -181, true, "invalid longitude: -181.000000, must be between -180 and 180"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			na, err := NewNetworkAddress(tt.lat, tt.lon)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, na)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, na)
				assert.NotNil(t, na.AnonGeoLocation)
				assert.NotNil(t, na.LocationCommitment)
				assert.NotNil(t, na.PrivateKey)
				assert.NotNil(t, na.PublicKey)
				assert.NotNil(t, na.Suite)
				assert.NotNil(t, na.Nonce)
			}
		})
	}
}

func TestGenerateZKP(t *testing.T) {
	na, err := NewNetworkAddress(40.7128, -74.0060)
	require.NoError(t, err)

	err = na.GenerateZKP(256)
	assert.NoError(t, err)
	assert.NotNil(t, na.ZKP)
	assert.NotNil(t, na.r)
	assert.NotNil(t, na.P)

	// Test with empty AnonGeoLocation
	naEmpty := &NetworkAddress{}
	err = naEmpty.GenerateZKP(256)
	assert.Error(t, err)
}

func TestGenerateAddress(t *testing.T) {
	ai, err := GenerateAddress(40.7128, -74.0060, 256)
	assert.NoError(t, err)
	assert.NotNil(t, ai)
	assert.NotEmpty(t, ai.PublicKey)
	assert.NotEmpty(t, ai.LocationCommitment)
	assert.NotEmpty(t, ai.ZKPProof)

	// Test caching
	ai2, err := GenerateAddress(40.7128, -74.0060, 256)
	assert.NoError(t, err)
	assert.Equal(t, ai, ai2)
}

func TestGenerateAddressesBatch(t *testing.T) {
	coords := [][2]float64{
		{40.7128, -74.0060},
		{51.5074, -0.1278},
		{35.6762, 139.6503},
	}

	addresses, err := GenerateAddressesBatch(coords, 256)
	assert.NoError(t, err)
	assert.Len(t, addresses, len(coords))
	for _, ai := range addresses {
		assert.NotNil(t, ai)
		assert.NotEmpty(t, ai.PublicKey)
		assert.NotEmpty(t, ai.LocationCommitment)
		assert.NotEmpty(t, ai.ZKPProof)
	}
}

func TestAddressInfoMarshalUnmarshal(t *testing.T) {
	ai := &AddressInfo{
		PublicKey:          "testPublicKey",
		LocationCommitment: "testLocationCommitment",
		ZKPProof:           "testZKPProof",
		NonceValue:         "testNonceValue",
		NonceHash:          "testNonceHash",
	}

	// Test MarshalJSON
	data, err := json.Marshal(ai)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	// Test UnmarshalJSON
	aiNew := &AddressInfo{}
	err = json.Unmarshal(data, aiNew)
	assert.NoError(t, err)
	assert.Equal(t, ai, aiNew)

	// Test invalid JSON data
	err = aiNew.UnmarshalJSON([]byte("invalid"))
	assert.Error(t, err)
}

func BenchmarkGenerateAddress(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lat := rand.Float64()*180 - 90
		lon := rand.Float64()*360 - 180
		_, err := GenerateAddress(lat, lon, 256)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateAddressesBatch(b *testing.B) {
	coords := make([][2]float64, 100)
	for i := range coords {
		coords[i][0] = rand.Float64()*180 - 90
		coords[i][1] = rand.Float64()*360 - 180
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GenerateAddressesBatch(coords, 256)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAddressInfoMarshalBinary(b *testing.B) {
	ai, _ := GenerateAddress(40.7128, -74.0060, 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ai.MarshalBinary()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAddressInfoUnmarshalBinary(b *testing.B) {
	ai, _ := GenerateAddress(40.7128, -74.0060, 256)
	data, _ := ai.MarshalBinary()
	aiNew := &AddressInfo{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := aiNew.UnmarshalBinary(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParallelGenerateAddress(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			lat := rand.Float64()*180 - 90
			lon := rand.Float64()*360 - 180
			_, err := GenerateAddress(lat, lon, 256)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestConcurrentAccess(t *testing.T) {
	var wg sync.WaitGroup
	numGoroutines := 100

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			lat := rand.Float64()*180 - 90
			lon := rand.Float64()*360 - 180
			_, err := GenerateAddress(lat, lon, 256)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
}
func TestMemoryUsage(t *testing.T) {
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)

	// Generate a smaller number of addresses
	for i := 0; i < 1000; i++ {
		lat := rand.Float64()*180 - 90
		lon := rand.Float64()*360 - 180
		_, err := GenerateAddress(lat, lon, 256)
		assert.NoError(t, err)
	}

	runtime.ReadMemStats(&m2)

	// Check if memory usage is within acceptable limits
	memUsage := m2.TotalAlloc - m1.TotalAlloc
	t.Logf("Memory usage: %d bytes", memUsage)
	assert.True(t, memUsage < uint64(1024*1024*1024), "Memory usage is too high: %d bytes", memUsage)
}

func TestAddressCache(t *testing.T) {
	// Clear the cache before testing
	addressCache.Purge()

	// Generate an address
	lat, lon := 40.7128, -74.0060
	ai1, err := GenerateAddress(lat, lon, 256)
	require.NoError(t, err)

	// Generate the same address again
	ai2, err := GenerateAddress(lat, lon, 256)
	require.NoError(t, err)

	// Check if the cached version is returned
	assert.Equal(t, ai1, ai2)

	// Check cache size
	assert.Equal(t, 1, addressCache.Len())

	// Generate addresses until cache is full
	for i := 0; i < 90; i++ {
		_, err := GenerateAddress(float64(i), float64(i), 256)
		require.NoError(t, err)
	}

	// Check that cache size is capped at 100 (91 for lat lon in the purpose of this test)
	assert.Equal(t, 91, addressCache.Len())
}

func TestEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		lat     float64
		lon     float64
		bits    int
		wantErr bool
		errMsg  string
	}{
		{"Valid extreme coordinates", 90, 180, 256, false, ""},
		{"Valid extreme negative coordinates", -90, -180, 256, false, ""},
		{"Invalid latitude (too high)", 91, 0, 256, true, "invalid latitude"},
		{"Invalid latitude (too low)", -91, 0, 256, true, "invalid latitude"},
		{"Invalid longitude (too high)", 0, 181, 256, true, "invalid longitude"},
		{"Invalid longitude (too low)", 0, -181, 256, true, "invalid longitude"},
		{"Invalid bits (zero)", 0, 0, 0, true, "bits must be positive"},
		{"Invalid bits (negative)", 0, 0, -1, true, "bits must be positive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ai, err := GenerateAddress(tt.lat, tt.lon, tt.bits)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, ai)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, ai)
				assert.NotEmpty(t, ai.PublicKey)
				assert.NotEmpty(t, ai.LocationCommitment)
				assert.NotEmpty(t, ai.ZKPProof)
				assert.NotEmpty(t, ai.NonceValue)
				assert.NotEmpty(t, ai.NonceHash)
			}
		})
	}
}
