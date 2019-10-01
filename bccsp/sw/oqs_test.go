package sw

import (
	oqs "github.com/hyperledger/fabric/external_crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestOqsSigner_Sign(t *testing.T) {
	signer := &oqsSigner{}
	privateKeyVerifier := &oqsPrivateKeyVerifier{}
	publicKeyVerifier := &oqsPublicKeyKeyVerifier{}

	// Generate keypair, message digest
	// This should become bccsp.KeyGen
	lib, err := oqs.LoadDefaultLib()
	assert.NoError(t, err)
	defer lib.Close()
	sig, err := lib.GetSign(oqsAlg)
	assert.NoError(t, err)
	defer sig.Close()
	publicKey, privateKey, err := sig.KeyPair()
	pub := &oqsPublicKey{pubKey: &publicKey}
	priv := &oqsPrivateKey{privKey: &privateKey}
	digest := []byte("Hello world")

	// Sign and verify signature
	signature, err := signer.Sign(priv, digest, nil)
	assert.NoError(t, err)
	verify, err := publicKeyVerifier.Verify(pub, signature, digest, nil)
	assert.NoError(t, err)
	assert.True(t, verify)
	verify, err = privateKeyVerifier.Verify(priv, signature, digest, nil)
	assert.NoError(t, err)
	assert.True(t, verify)

}

func TestOqsKeySigner_SignError(t *testing.T) {

	// mock low-level verification error
	// assert false and error returned

}

func TestOqsKeyVerifier_VerifyError(t *testing.T) {

	// mock low-level verification error
	// assert false and error returned

}

