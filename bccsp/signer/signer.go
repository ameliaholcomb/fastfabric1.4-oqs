/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package signer

import (
	"crypto"
	"encoding/asn1"
	"github.com/hyperledger/fabric/common/flogging"
	"io"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/pkg/errors"
)

var (
	logger = flogging.MustGetLogger("bccsp_signer")
)

// TODO(amelia): Should there be a hybrid signer and a regular signer?
// We're already separating out signers in msp code ...

// bccspCryptoSigner is the BCCSP-based implementation of a crypto.Signer
type bccspCryptoSigner struct {
	csp bccsp.BCCSP
	// private keys
	classicalKey bccsp.Key
	quantumKey bccsp.Key
	// TODO(amelia): Should this be an interface?
	classicalPk interface{}
	quantumPk interface{}
}

type hybridSignature struct{
	ClassicalSign    asn1.BitString
	QuantumSign	   asn1.BitString
}

// New returns a new BCCSP-based crypto.Signer
// for the given BCCSP instance and key.
func New(csp bccsp.BCCSP, classicalKey bccsp.Key, quantumKey bccsp.Key) (crypto.Signer, error) {
	// Validate arguments
	if csp == nil {
		return nil, errors.New("bccsp instance must be different from nil.")
	}
	if classicalKey == nil {
		return nil, errors.New("classical key must be different from nil.")
	}
	if classicalKey.Symmetric() || (quantumKey != nil && quantumKey.Symmetric()) {
		return nil, errors.New("key must be asymmetric.")
	}

	// Marshall the classical public key as a crypto.PublicKey
	classicalPub, err := classicalKey.PublicKey()
	if err != nil {
		return nil, errors.Wrap(err, "failed getting classical public key")
	}
	classicalRaw, err := classicalPub.Bytes()
	if err != nil {
		return nil, errors.Wrap(err, "failed marshalling public key")
	}
	classicalPk, err := utils.DERToPublicKey(classicalRaw)
	if err != nil {
		return nil, errors.Wrap(err, "failed marshalling der to public key")
	}

	// Marshall the quantum public key as a crypto.PublicKey
	if quantumKey != nil {
		quantumPub, err := quantumKey.PublicKey()
		if err != nil {
			return nil, errors.Wrap(err, "failed getting quantum public key")
		}
		quantumRaw, err := quantumPub.Bytes()
		if err != nil {
			return nil, errors.Wrap(err, "failed marshalling public key")
		}
		quantumPk, err := utils.DERToPublicKey(quantumRaw)
		if err != nil {
			return nil, errors.Wrap(err, "failed marshalling der to public key")
		}
		return &bccspCryptoSigner{
			csp,
			classicalKey,
			quantumKey,
			classicalPk,
			quantumPk,
		}, nil
	}
	return &bccspCryptoSigner{
		csp,
		classicalKey,
		nil,
		classicalPk,
		nil,
	}, nil
}

// Public returns the public key corresponding to the opaque,
// private key.
// TODO(amelia): Make sure no one is actually trying to use this and failing
func (s *bccspCryptoSigner) Public() crypto.PublicKey {
	return s.classicalPk
}

// Sign signs digest with the private key, possibly using entropy from
// rand. For an RSA key, the resulting signature should be either a
// PKCS#1 v1.5 or PSS signature (as indicated by opts). For an (EC)DSA
// key, it should be a DER-serialised, ASN.1 signature structure.
//
// Hash implements the SignerOpts interface and, in most cases, one can
// simply pass in the hash function used as opts. Sign may also attempt
// to type assert opts to other types in order to obtain algorithm
// specific values. See the documentation in each package for details.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest) and the hash function (as opts) to Sign.
func (s *bccspCryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {

	// If there is a quantum key associated with the signer,
	// Follow the strong-nested hybrid signature proposed in
	// https://eprint.iacr.org/2017/460.pdf
	// Note that if there is no quantum key, this function returns
	// an unmodified classical signature.
	var qSign []byte
	var err error
	if s.quantumKey != nil {
		logger.Debug("Preparing to sign with quantum-safe key")
		qSign, err = s.csp.Sign(s.quantumKey, digest, opts)
		if err != nil {
			return nil, err
		}
		digest = append(digest, qSign...)
	}

	cSign, err := s.csp.Sign(s.classicalKey, digest, opts)
	if err != nil {
		return nil, err
	}

	if s.quantumKey != nil {
		signature := hybridSignature{
			ClassicalSign: asn1.BitString{
				Bytes:     cSign,
				BitLength: 8 * len(cSign),
			},
			QuantumSign: asn1.BitString{
				Bytes:     qSign,
				BitLength: 8 * len(qSign),
			},
		}
		ret, err := asn1.Marshal(signature)
		if err != nil {
			return nil, err
		}
		return ret, nil
	} else {
		return cSign, nil
	}
}
