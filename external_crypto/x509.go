package oqs

import "C"
import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// MVP implementation for marshalling and unmarshalling OQS keys.
// It is assumed that, once specific quantum-safe algorithms become standardized,
// there will be forthcoming RFCs that precisely describe their expected asn1 format, etc.
// Eventually, these should be supported by the Go SDK crypto packages directly.

const UnknownPublicKeyAlgorithm SigType = "UnknownPublicKeyAlgorithm"
type PublicKeyAlgorithm = SigType
var (
	oidPublicKeyPicnicL1FS     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 43}
	oidPublicKeyPicnicL1UR     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 44}
	oidPublicKeyPicnic2L1FS    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 45}
	oidPublicKeyPicnicL3FS     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 46}
	oidPublicKeyPicnicL3UR     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 47}
	oidPublicKeyPicnic2L3FS    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 48}
	oidPublicKeyPicnicL5FS     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 49}
	oidPublicKeyPicnicL5UR     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 50}
	oidPublicKeyPicnic2L5FS    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 51}
	oidPublicKeyqTESLAI        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 53}
	oidPublicKeyqTESLAIIIsize  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 58}
	oidPublicKeyqTESLAIIIspeed = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 59} // ???
	oidPublicKeyDilithium_2    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 21}
	oidPublicKeyDilithium_3    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 22}
	oidPublicKeyDilithium_4    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 23}
	oidPublicKeyMqdss_31_48    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 41}
	oidPublicKeyMqdss_31_64    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 42}
	oidPublicKeySphincs_haraka_128f_robust = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 100} // Haraka not included?
)

var oidMap = map[SigType]asn1.ObjectIdentifier {
	SigPicnicL1FS  : oidPublicKeyPicnicL1FS,
	SigPicnicL1UR  : oidPublicKeyPicnicL1UR,
	SigPicnicL3FS  : oidPublicKeyPicnicL3FS,
	SigPicnicL3UR  : oidPublicKeyPicnicL3UR,
	SigPicnicL5FS  : oidPublicKeyPicnicL5FS,
	SigPicnicL5UR  : oidPublicKeyPicnicL5UR,
	SigPicnic2L1FS  : oidPublicKeyPicnic2L1FS,
	SigPicnic2L3FS  : oidPublicKeyPicnic2L3FS,
	SigPicnic2L5FS  : oidPublicKeyPicnic2L5FS,
	SigqTESLAI  : oidPublicKeyqTESLAI,
	SigqTESLAIIIsize  : oidPublicKeyqTESLAIIIsize,
	SigqTESLAIIIspeed  : oidPublicKeyqTESLAIIIspeed,
	SigDilithium_2  : oidPublicKeyDilithium_2,
	SigDilithium_3  : oidPublicKeyDilithium_3,
	SigDilithium_4  : oidPublicKeyDilithium_4,
	SigMqdss_31_48  : oidPublicKeyMqdss_31_48,
	SigMqdss_31_64  : oidPublicKeyMqdss_31_64,
	SigSphincs_haraka_128f_robust  : oidPublicKeySphincs_haraka_128f_robust,
}

func getPublicKeyAlgorithmFromOID(oid asn1.ObjectIdentifier) PublicKeyAlgorithm {
	for alg, id := range oidMap {
		if oid.Equal(id) {
			return alg
		}
	}
	return UnknownPublicKeyAlgorithm
}

// pkixPublicKey reflects a PKIX public key structure. See SubjectPublicKeyInfo
// in RFC 3280.
type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func MarshalPKIXPublicKey(pub interface{}) ([]byte, error)  {
	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier

	pk, ok := pub.(*PublicKey)
	if !ok {
		return nil, errors.New("key is not a known OQS key type")
	}
	oid, ok := oidMap[pk.Sig.Algorithm]
	if !ok {
		return nil, errors.New("unknown OQS algorithm name")
	}
	publicKeyAlgorithm.Algorithm = oid
	// The OQS public key algorithms do not require parameters,
	// therefore a NULL parameters value is required.
	publicKeyAlgorithm.Parameters = asn1.NullRawValue
	publicKeyBytes = pk.Pk
	pkix := pkixPublicKey{
		Algo: publicKeyAlgorithm,
		BitString: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: 8 * len(publicKeyBytes),
		},
	}
	ret, _ := asn1.Marshal(pkix)
	return ret, nil

}

func ParsePKIXPublicKey(derBytes []byte) (interface{}, error) {
	var pki publicKeyInfo
	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}
	alg := getPublicKeyAlgorithmFromOID(pki.Algorithm.Algorithm)
	if alg == UnknownPublicKeyAlgorithm {
		return nil, errors.New("unknown OQS public key algorithm")
	}
	asn1Data := pki.PublicKey.RightAlign()
	s := OQSSigInfo {
		Algorithm: alg,
		// TODO(amelia): either reconstruct this or remove from OQSSigInfo
		PubKeyLen: 512,
		SecKeyLen: 512,
	}
	publicKey := &PublicKey { Pk: asn1Data, Sig: s}
	return publicKey, nil


}
//func MarshalPKCS1PrivateKey(pub interface{}) ([]byte, error) {}
//func ParsePKCS1PrivateKey(block []byte) (interface{}, error) {}


