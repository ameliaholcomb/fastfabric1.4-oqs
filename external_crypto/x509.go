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

const UnknownKeyAlgorithm SigType = "UnknownKeyAlgorithm"
type Algorithm = SigType
var (
	oidPicnicL1FS     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 43}
	oidPicnicL1UR     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 44}
	oidPicnic2L1FS    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 45}
	oidPicnicL3FS     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 46}
	oidPicnicL3UR     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 47}
	oidPicnic2L3FS    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 48}
	oidPicnicL5FS     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 49}
	oidPicnicL5UR     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 50}
	oidPicnic2L5FS    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 51}
	oidqTESLAI        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 53}
	oidqTESLAIIIsize  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 58}
	oidqTESLAIIIspeed = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 59} // ???
	oidDilithium_2    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 21}
	oidDilithium_3    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 22}
	oidDilithium_4    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 23}
	oidMqdss_31_48    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 41}
	oidMqdss_31_64    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 42}
	oidSphincs_haraka_128f_robust = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 100} // Haraka not included?
)

var oidMap = map[SigType]asn1.ObjectIdentifier {
	SigPicnicL1FS  : oidPicnicL1FS,
	SigPicnicL1UR  : oidPicnicL1UR,
	SigPicnicL3FS  : oidPicnicL3FS,
	SigPicnicL3UR  : oidPicnicL3UR,
	SigPicnicL5FS  : oidPicnicL5FS,
	SigPicnicL5UR  : oidPicnicL5UR,
	SigPicnic2L1FS  : oidPicnic2L1FS,
	SigPicnic2L3FS  : oidPicnic2L3FS,
	SigPicnic2L5FS  : oidPicnic2L5FS,
	SigqTESLAI  : oidqTESLAI,
	SigqTESLAIIIsize  : oidqTESLAIIIsize,
	SigqTESLAIIIspeed  : oidqTESLAIIIspeed,
	SigDilithium_2  : oidDilithium_2,
	SigDilithium_3  : oidDilithium_3,
	SigDilithium_4  : oidDilithium_4,
	SigMqdss_31_48  : oidMqdss_31_48,
	SigMqdss_31_64  : oidMqdss_31_64,
	SigSphincs_haraka_128f_robust  : oidSphincs_haraka_128f_robust,
}

func getAlgorithmFromOID(oid asn1.ObjectIdentifier) Algorithm {
	for alg, id := range oidMap {
		if oid.Equal(id) {
			return alg
		}
	}
	return UnknownKeyAlgorithm
}

// pkixPublicKey reflects a PKIX public key structure. See SubjectPublicKeyInfo
// in RFC 3280.
type pkixPublicKey struct {
	Algorithm      pkix.AlgorithmIdentifier
	PublicKey	   asn1.BitString
}

// asn1.Unmarshal will unmarshal into a data structure like pkixPublicKey, but with RawContent
type pkixPublicKeyUnpack struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func getAlgorithmIdentifier(alg SigType) (ai pkix.AlgorithmIdentifier, err error) {
	oid, ok := oidMap[alg]
	if !ok {
		return ai, errors.New("unknown OQS algorithm name") }
	ai.Algorithm = oid
	// The OQS public key algorithms do not require parameters,
	// therefore a NULL parameters value is required.
	ai.Parameters = asn1.NullRawValue
	return ai, nil
}

func MarshalPKIXPublicKey(pub interface{}) ([]byte, error)  {
	pk, ok := pub.(*PublicKey)
	if !ok {
		return nil, errors.New("key is not a known OQS key type")
	}

	publicKeyAlgorithm, err := getAlgorithmIdentifier(pk.Sig.Algorithm)
	if err != nil {
		return nil, err
	}
	pkix := pkixPublicKey{
		Algorithm: publicKeyAlgorithm,
		PublicKey: asn1.BitString{
			Bytes:     pk.Pk,
			BitLength: 8 * len(pk.Pk),
		},
	}
	ret, _ := asn1.Marshal(pkix)
	return ret, nil
}

func ParsePKIXPublicKey(derBytes []byte) (interface{}, error) {
	var pku pkixPublicKeyUnpack
	if rest, err := asn1.Unmarshal(derBytes, &pku); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}
	alg := getAlgorithmFromOID(pku.Algorithm.Algorithm)
	if alg == UnknownKeyAlgorithm {
		return nil, errors.New("unknown OQS public key algorithm")
	}
	asn1Data := pku.PublicKey.RightAlign()
	s := OQSSigInfo {
		Algorithm: alg,
	}
	publicKey := &PublicKey { Pk: asn1Data, Sig: s}
	return publicKey, nil
}

type pkixPrivateKey struct {
	Algorithm     pkix.AlgorithmIdentifier
	PrivateKey    asn1.BitString
	PublicKey     asn1.BitString
}

type pkixPrivateKeyUnpack struct {
	Raw           asn1.RawContent
	Algorithm     pkix.AlgorithmIdentifier
	PrivateKey    asn1.BitString
	PublicKey     asn1.BitString
}

func MarshalPKIXPrivateKey(pub interface{}) ([]byte, error) {
	sk, ok := pub.(*SecretKey)
	if !ok {
		return nil, errors.New("key is not a known OQS key type")
	}
	privateKeyAlgorithm, err := getAlgorithmIdentifier(sk.Sig.Algorithm)
	if err != nil {
		return nil, err
	}
	pkix := pkixPrivateKey{
		Algorithm: privateKeyAlgorithm,
		PrivateKey: asn1.BitString{
			Bytes:     sk.Sk,
			BitLength: 8 * len(sk.Sk),
		},
		PublicKey: asn1.BitString{
			Bytes:     sk.Pk,
			BitLength: 8 * len(sk.Pk),
		},
	}
	ret, _ := asn1.Marshal(pkix)
	return ret, nil

}

func ParsePKIXPrivateKey(derBytes []byte) (interface{}, error) {
	var pku pkixPrivateKeyUnpack
	if rest, err := asn1.Unmarshal(derBytes, &pku); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of private-key")
	}
	alg := getAlgorithmFromOID(pku.Algorithm.Algorithm)
	if alg == UnknownKeyAlgorithm {
		return nil, errors.New("unknown OQS public key algorithm")
	}
	asn1PrivData := pku.PrivateKey.RightAlign()
	asn1PubData := pku.PublicKey.RightAlign()
	s := OQSSigInfo {
		Algorithm: alg,
	}
	pk := PublicKey{
		Pk: asn1PubData,
		Sig: s,
	}
	privKey := &SecretKey {asn1PrivData, pk}
	return privKey, nil
}


// Encode quantum public keys as X509 Extensions, per
// https://tools.ietf.org/id/draft-truskovsky-lamps-pq-hybrid-x509-00.html
// TODO(amelia): What should these be?
var (
	oidSubjectAltPublicKeyInfo     = asn1.ObjectIdentifier{2, 5, 29, 41}
	oidAltSignatureAlgorithm		   = asn1.ObjectIdentifier{2, 5, 29, 42}
	oidAltSignatureValue			   = asn1.ObjectIdentifier{2, 5, 29, 43}
)


// pkixSubjectAltPublicKeyInfo reflects a PKIX Alternate Public Key Identifier.
// See https://tools.ietf.org/id/draft-truskovsky-lamps-pq-hybrid-x509-00.html
type pkixSubjectAltPublicKeyInfo struct {
	Algorithm              pkix.AlgorithmIdentifier
	SubjectAltPublicKey	   asn1.BitString
}

// asn1.Unmarshal will unmarshal into a data structure like pkixSubjectAltPublicKeyInfo, but with RawContent
type pkixSubjectAltPublicKeyInfoUnpack struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	SubjectAltPublicKey	   asn1.BitString
}

func BuildAltPublicKeyExtensions(pub interface{}) ([]pkix.Extension, error) {
	pk, ok := pub.(*PublicKey)
	if !ok {
		return nil, errors.New("key is not a known OQS key type")
	}
	publicKeyAlgorithm, err := getAlgorithmIdentifier(pk.Sig.Algorithm)
	if err != nil {
		return nil, err
	}
	extensions := make([]pkix.Extension, 2)

	pkix := pkixSubjectAltPublicKeyInfo{
		Algorithm: publicKeyAlgorithm,
		SubjectAltPublicKey: asn1.BitString{
			Bytes:     pk.Pk,
			BitLength: 8 * len(pk.Pk),
		},
	}
	val, _ := asn1.Marshal(pkix)
	extensions[0].Id = oidSubjectAltPublicKeyInfo
	extensions[0].Critical = false
	extensions[0].Value = val

	val, _ = asn1.Marshal(publicKeyAlgorithm)
	extensions[1].Id = oidAltSignatureAlgorithm
	extensions[1].Critical = false
	extensions[1].Value = val

	return extensions, nil
}

func ParseAltPublicKeyExtensions(extensions []pkix.Extension) (interface{}, error) {
	for _, ext := range(extensions) {
		// TODO(amelia): Also parse the algorithm, check that it matches and such.
		if ext.Id.Equal(oidSubjectAltPublicKeyInfo) {
			var pku pkixSubjectAltPublicKeyInfoUnpack
			if rest, err := asn1.Unmarshal(ext.Value, &pku); err != nil {
				return nil, err
			} else if len(rest) != 0 {
				return nil, errors.New("x509: trailing data after ASN.1 of SubjectAltPublicKey")
			}
			alg := getAlgorithmFromOID(pku.Algorithm.Algorithm)
			if alg == UnknownKeyAlgorithm {
				return nil, errors.New("unknown OQS public key algorithm")
			}
			asn1Data := pku.SubjectAltPublicKey.RightAlign()
			s := OQSSigInfo {
				Algorithm: alg,
			}
			publicKey := &PublicKey { Pk: asn1Data, Sig: s}
			return publicKey, nil
		}
	}
	// If no alt public key extensions are found, this is not an error.
	// Caller is responsible for checking that returned key is not nil, if required.
	return nil, nil
}
