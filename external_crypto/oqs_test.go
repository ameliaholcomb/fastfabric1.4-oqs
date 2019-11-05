package oqs
import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var libPath = "liboqs.so"

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

	InitLib()
	// Make random number generation deterministic in order to test against
	// the C library results
	SetRandomAlg(packageLib, AlgNistKat)

	// The message will repeat in different invocations if random number
	// generation is deterministic 
	message, _ := GetRandomBytes(100)

	fmt.Println("Message to sign:")
	h12 := strings.ToUpper(hex.EncodeToString(message))
	fmt.Printf("%s\n", h12)

	for _, sigAlg := range sigs {
		t.Run(string(sigAlg), func(t *testing.T) {
			// re-initialize Sig with new algorithm
			DestroySig()
			InitSig(sigAlg)

			var err error
			if err == errAlgDisabledOrUnknown {
				t.Skipf("Skipping disabled/unknown algorithm %q", sigAlg)
			}
			require.NoError(t, err)

			publicKey, secretKey, err := KeyPair()
			assert.Equal(t, publicKey.Sig.Algorithm, sigAlg)
			require.NoError(t, err)
			
			signature, err := Sign(secretKey, message)
			require.NoError(t, err)

			result, err := Verify(publicKey, signature, message)
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
	l1, err := LoadLib(libPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, CloseLib(l1)) }()

	l2, err := LoadLib(libPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, CloseLib(l2)) }()
}


func TestLibraryClosed(t *testing.T) {
	l, err := LoadLib(libPath)
	require.NoError(t, err)
	require.NoError(t, CloseLib(l))

	const expectedMsg = "library closed"

	t.Run("GetSIG", func(t *testing.T) {
		_, err := GetSign(l, SigPicnicL1FS)
		require.Error(t, err)
		assert.Contains(t, err.Error(), expectedMsg)
	})

	t.Run("Close", func(t *testing.T) {
		err := CloseLib(l)
		require.Error(t, err)
		assert.Contains(t, err.Error(), expectedMsg)
	})
}

func TestInvalidSIGAlg(t *testing.T) {
	l, err := LoadLib(libPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, CloseLib(l)) }()

	_, err = GetSign(l, SigType("this will never be valid"))
	assert.Equal(t, errAlgDisabledOrUnknown, err)
}


func TestLibErr(t *testing.T) {
	err := libError(operationFailed, "test%d", 123)
	assert.EqualError(t, err, "test123")
}
