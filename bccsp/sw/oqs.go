package sw

import (
	"github.com/hyperledger/fabric/bccsp"
	oqs "github.com/hyperledger/fabric/external_crypto"
)

const oqsAlg = oqs.SigqTESLAI

// TODO:
// When to choose the algorithm to make it configurable? Presumably MSP should load it, but then how to pass it through
// with the key/signature?
// Way to cache the OQSSig and library, so we don't have to load them every time? But still must free/close each.

func signOQS(k *oqs.SecretKey, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	lib, err := oqs.LoadDefaultLib()
	if err != nil {
		return nil, err
	}
	defer lib.Close()
	sig, err := lib.GetSign(oqsAlg)
	if err != nil {
		return nil, err
	}
	defer sig.Close()
	return sig.Sign(*k, digest)
}

func verifyOQS(k *oqs.PublicKey, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	lib, err := oqs.LoadDefaultLib()
	if err != nil {
		return false, err
	}
	defer lib.Close()
	sig, err := lib.GetSign(oqsAlg)
	if err != nil {
		return false, err
	}
	defer sig.Close()
	return sig.Verify(*k, signature, digest)
}

type oqsSigner struct{}

func (s *oqsSigner) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return signOQS(k.(*oqsPrivateKey).privKey, digest, opts)
}

type oqsPrivateKeyVerifier struct{}

func (v *oqsPrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifyOQS(&(k.(*oqsPrivateKey).privKey.PublicKey), signature, digest, opts)
}
type oqsPublicKeyKeyVerifier struct{}

func (v *oqsPublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifyOQS(k.(*oqsPublicKey).pubKey, signature, digest, opts)
}
