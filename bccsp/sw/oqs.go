package sw

import (
	"github.com/hyperledger/fabric/bccsp"
	oqs "github.com/hyperledger/fabric/external_crypto"
)

const oqsAlg = oqs.SigqTESLAI

func signOQS(k *oqs.SecretKey, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return k.Sig.Sign(*k, digest)
}

// Should public keys also have a sig? If so, who is responsible for freeing/closing?
// The one who runs KeyGen in the first place?
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
