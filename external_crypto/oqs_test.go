package oqs
import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const libPath = "/usr/local/lib/liboqs.dylib"

func TestRoundTrip(t *testing.T) {

	sigs := []SigType{
		SigqTESLAI,
		SigqTESLAIIIspeed,
		SigqTESLAIIIsize,

		SigPicnicL1FS,
		SigPicnicL1UR,
		SigPicnicL3FS,
		SigPicnicL3UR,
		SigPicnicL5FS,
		SigPicnicL5UR,
		SigPicnic2L1FS,
		SigPicnic2L3FS,
		SigPicnic2L5FS,

		SigDilithium_2,
		SigDilithium_3,
		SigDilithium_4,

		SigMqdss_31_48,
		SigMqdss_31_64,
		SigSphincs_haraka_128f_robust,

	}

	// Load original libOQS shared C library
	lib, err := LoadLib(libPath)

	require.NoError(t, err)
	defer func() { require.NoError(t, lib.Close()) }()

	// Make random number generation deterministic in order to test against
	// the C library results
	lib.SetRandomAlg(AlgNistKat)

	// The message will repeat in different invocations if random number
	// generation is deterministic 
	message, err := lib.GetRandomBytes(100)

	fmt.Println("Message to sign:")
	h12 := strings.ToUpper(hex.EncodeToString(message))
	fmt.Printf("%s\n", h12)

	for _, sigAlg := range sigs {
		t.Run(string(sigAlg), func(t *testing.T) {

			testSIG, err := lib.GetSign(sigAlg)
			if err == errAlgDisabledOrUnknown {
				t.Skipf("Skipping disabled/unknown algorithm %q", sigAlg)
			}
			require.NoError(t, err)
			defer func() { require.NoError(t, testSIG.Close()) }()

			publicKey, secretKey, err := testSIG.KeyPair()
			require.NoError(t, err)
			
			signature, err := testSIG.Sign(secretKey, message)
			require.NoError(t, err)

			result, err := testSIG.Verify(publicKey, signature, message)
			require.NoError(t, err)

			assert.Equal(t, result, true)
		})
	}
}


func TestBadLibrary(t *testing.T) {
	_, err := LoadLib("bad")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to load module")
}


func TestReEntrantLibrary(t *testing.T) {
	s1, err := LoadLib(libPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, s1.Close()) }()

	s2, err := LoadLib(libPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, s2.Close()) }()
}


func TestLibraryClosed(t *testing.T) {
	s, err := LoadLib(libPath)
	require.NoError(t, err)
	require.NoError(t, s.Close())

	const expectedMsg = "library closed"

	t.Run("GetSIG", func(t *testing.T) {
		_, err := s.GetSign(SigPicnicL1FS)
		require.Error(t, err)
		assert.Contains(t, err.Error(), expectedMsg)
	})

	t.Run("Close", func(t *testing.T) {
		err := s.Close()
		require.Error(t, err)
		assert.Contains(t, err.Error(), expectedMsg)
	})
}


func TestSIGClosed(t *testing.T) {
	s, err := LoadLib(libPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, s.Close()) }()

	testSIG, err := s.GetSign(SigqTESLAI)
	require.NoError(t, err)

	require.NoError(t, testSIG.Close())

	t.Run("KeyPair", func(t *testing.T) {
		_, _, err := testSIG.KeyPair()
		assert.Equal(t, errAlreadyClosed, err)
	})

	t.Run("Sign", func(t *testing.T) {
		_, err := testSIG.Sign(SecretKey{}, nil)
		assert.Equal(t, errAlreadyClosed, err)
	})

	t.Run("Verify", func(t *testing.T) {
		_, err := testSIG.Verify(PublicKey{}, nil, nil)
		assert.Equal(t, errAlreadyClosed, err)
	})

	t.Run("Close", func(t *testing.T) {
		err := testSIG.Close()
		assert.Equal(t, errAlreadyClosed, err)
	})
}


func TestInvalidSIGAlg(t *testing.T) {
	s, err := LoadLib(libPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, s.Close()) }()

	_, err = s.GetSign(SigType("this will never be valid"))
	assert.Equal(t, errAlgDisabledOrUnknown, err)
}


func TestLibErr(t *testing.T) {
	err := libError(operationFailed, "test%d", 123)
	assert.EqualError(t, err, "test123")
}
