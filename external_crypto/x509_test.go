package oqs

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
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

func TestMarshalPKIXPrivateKeySuccess(t *testing.T) {
	_, sk, err := KeyPair()
	require.NoError(t, err)
	_, err = MarshalPKIXPrivateKey(&sk)
	require.NoError(t, err)
}

func TestMarshalPKIXSecretKeyError(t *testing.T) {
	// An incorrect keytype passed should compile,
	// but return an error.
	ecdsaK := ecdsa.PrivateKey{}
	_, err := MarshalPKIXPrivateKey(&ecdsaK)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a known OQS key type")

	// A correct keytype with an unknown algorithm
	// should return an error.
	_, sk, err := KeyPair()
	require.NoError(t, err)
	sk.Sig.Algorithm = "I am not a real OQS Algorithm"
	_, err = MarshalPKIXPrivateKey(&sk)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown OQS algorithm name")
}

func TestParsePKIXPrivateKeySuccess(t *testing.T) {
	_, sk, err := KeyPair()
	require.NoError(t, err)

	for sigAlg, _ := range(oidMap) {
		t.Run(string(sigAlg), func(t *testing.T) {
			// In general, changing the key algorithm results in an invalid key.
			// However, nothing in the marshalling/unmarshalling should check that Pk is
			// valid for its algorithm.
			// Thus, we can test all the algorithms without generating a new keypair
			// for each by simply changing the SigInfo algorithm name.
			sk.Sig.Algorithm = sigAlg
			derBytes, err := MarshalPKIXPrivateKey(&sk)
			require.NoError(t, err)
			key, err := ParsePKIXPrivateKey(derBytes)
			require.NoError(t, err)
			oqsKey, ok := key.(*SecretKey)
			require.True(t, ok)
			require.Equal(t, oqsKey.Sk, sk.Sk)
			require.Equal(t, oqsKey.Pk, sk.Pk)
			// require.Equal *can* compare SigType objects, but it gives much more useful error messages
			// for comparing string types.
			require.Equal(t, string(oqsKey.Sig.Algorithm), string(sk.Sig.Algorithm))
		})
	}
}

func TestBuildAltPublicKeyInfoExtensionsSuccess(t *testing.T) {
	pk, _, err := KeyPair()
	require.NoError(t, err)
	_, err = BuildAltPublicKeyExtensions(&pk)
	require.NoError(t, err)
}

func TestBuildAltPublicKeyInfoExtensionsError(t *testing.T) {
	// An incorrect keytype passed should compile,
	// but return an error.
	ecdsaK := ecdsa.PublicKey{}
	_, err := BuildAltPublicKeyExtensions(&ecdsaK)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a known OQS key type")

	// A correct keytype with an unknown algorithm
	// should return an error.
	pk, _, err := KeyPair()
	require.NoError(t, err)
	pk.Sig.Algorithm = "I am not a real OQS Algorithm"
	_, err = BuildAltPublicKeyExtensions(&pk)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown OQS algorithm name")
}

func TestParseAltPublicKeyExtensions(t *testing.T) {
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
			extensions, err := BuildAltPublicKeyExtensions(&pk)
			require.NoError(t, err)
			key, err := ParseAltPublicKeyExtensions(extensions)
			require.NotNil(t, key)
			require.NoError(t, err)
			oqsKey, ok := key.(*PublicKey)
			require.True(t, ok)
			require.Equal(t, oqsKey.Pk, pk.Pk)
			// require.Equal *can* compare SigType objects, but it gives much more useful error messages
			// for comparing string types.
			require.Equal(t, string(oqsKey.Sig.Algorithm), string(pk.Sig.Algorithm))
		})
	}

	// In the case that extensions do not contain an alternate public key,
	// the parser should return a nil key without raising an error.
	extensions := []pkix.Extension{
		{
			Id:    []int{1, 2, 3, 4},
			Value: []byte("some other extension"),
		},
	}
	key, err := ParseAltPublicKeyExtensions(extensions)
	require.NoError(t, err)
	require.Nil(t, key)
}
