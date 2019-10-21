package sw

import (
	"crypto/sha256"
	"errors"
	"github.com/hyperledger/fabric/bccsp"
	oqs "github.com/hyperledger/fabric/external_crypto"
)

// oqsPrivateKey implements a bccsp.Key interface
type oqsPrivateKey struct {
	privKey *oqs.SecretKey
	sigAlg oqs.SigType
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *oqsPrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("Not supported.")
}

// SKI returns the subject key identifier of this key.
func (k *oqsPrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}
	algBytes := []byte(k.sigAlg)

	// Hash public key with algorithm
	hash := sha256.New()
	hash.Write(append(k.privKey.Pk, algBytes...))
	return hash.Sum(nil)
}

func (k *oqsPrivateKey) Symmetric() bool {
	return false
}

func (k *oqsPrivateKey) Private() bool {
	return true
}

func (k *oqsPrivateKey) PublicKey() (bccsp.Key, error) {
	return &oqsPublicKey{&k.privKey.PublicKey, k.sigAlg}, nil
}

// oqsPublicKey implements a bccsp.Key interface
type oqsPublicKey struct {
	pubKey *oqs.PublicKey
	sigAlg oqs.SigType
}

func (k *oqsPublicKey) Bytes() ([]byte, error) {
	if k.pubKey == nil {
		return nil, nil
	}
	return k.pubKey.Pk, nil
}

// SKI returns the subject key identifier of this key.
func (k *oqsPublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}
	algBytes := []byte(k.sigAlg)

	// Hash public key with algorithm
	hash := sha256.New()
	hash.Write(append(k.pubKey.Pk, algBytes...))
	return hash.Sum(nil)
}

func (k *oqsPublicKey) Symmetric() bool {
	return false
}

func (k *oqsPublicKey) Private() bool {
	return false
}

func (k *oqsPublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}




