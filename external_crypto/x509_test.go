package oqs

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestMarshalPKIXPublicKeySuccess(t *testing.T) {
	pk, _, err := KeyPair()
	require.NoError(t, err)
	_, err = MarshalPKIXPublicKey(&pk)
	require.NoError(t, err)
}

func TestMarshalPKIXPublicKeyError(t *testing.T) {
	// An incorrect keytype passed should compile,
	// but return an error.
	ecdsaK := ecdsa.PublicKey{}
	_, err := MarshalPKIXPublicKey(&ecdsaK)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a known OQS key type")

	// A correct keytype with an unknown algorithm
	// should return an error.
	pk, _, err := KeyPair()
	require.NoError(t, err)
	pk.Sig.Algorithm = "I am not a real OQS Algorithm"
	_, err = MarshalPKIXPublicKey(&pk)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown OQS algorithm name")
}

func TestParsePKIXPublicKeySuccess(t *testing.T) {
	pk, _, err := KeyPair()
	require.NoError(t, err)

	for sigAlg, _ := range(oidMap) {
		t.Run(string(sigAlg), func(t *testing.T) {
			// In general, changing the key algorithm results in an invalid key.
			// However, nothing in the marshalling/unmarshalling should check that Pk is
			// valid for its algorithm.
			// Thus, we can test all the algorithms without generating a new keypair
			// for each by simply changing the SigInfo algorithm name.
			pk.Sig.Algorithm = sigAlg
			derBytes, err := MarshalPKIXPublicKey(&pk)
			require.NoError(t, err)
			key, err := ParsePKIXPublicKey(derBytes)
			require.NoError(t, err)
			oqsKey, ok := key.(*PublicKey)
			require.True(t, ok)
			require.Equal(t, oqsKey.Pk, pk.Pk)
			// require.Equal *can* compare SigType objects, but it gives much more useful error messages
			// for comparing string types.
			require.Equal(t, string(oqsKey.Sig.Algorithm), string(pk.Sig.Algorithm))
		})
	}
}

var pemRSAPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3VoPN9PKUjKFLMwOge6+
wnDi8sbETGIx2FKXGgqtAKpzmem53kRGEQg8WeqRmp12wgp74TGpkEXsGae7RS1k
enJCnma4fii+noGH7R0qKgHvPrI2Bwa9hzsH8tHxpyM3qrXslOmD45EH9SxIDUBJ
FehNdaPbLP1gFyahKMsdfxFJLUvbUycuZSJ2ZnIgeVxwm4qbSvZInL9Iu4FzuPtg
fINKcbbovy1qq4KvPIrXzhbY3PWDc6btxCf3SE0JdE1MCPThntB62/bLMSQ7xdDR
FF53oIpvxe/SCOymfWq/LW849Ytv3Xwod0+wzAP8STXG4HSELS4UedPYeHJJJYcZ
+QIDAQAB
-----END PUBLIC KEY-----
`
func TestParsePKIXPublicKeyError(t *testing.T) {
	block, _ := pem.Decode([]byte(pemRSAPublicKey))
	_, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	// The non-OQS key should return an error from the oqs parse function:
	// use the normal x509 functions for classical crypto, which should have worked above.
	_, err = ParsePKIXPublicKey(block.Bytes)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown OQS public key algorithm")
}
