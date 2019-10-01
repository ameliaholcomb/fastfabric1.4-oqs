package oqs
//NOTE: THE COMMENTS BELOW ARE CODE WHICH GETS COMPILED (THEY ARE CALLED PREAMBLE).IT'S A UNIQUE/WEIRD FEATURE IN CGO.

/*
   #cgo CFLAGS: -Iinclude
   #cgo LDFLAGS: -ldl -loqs -lm

   #include <stdio.h>
   #include <stdlib.h>

   typedef enum {
   	ERR_OK,
   	ERR_CANNOT_LOAD_LIB,
   	ERR_CONTEXT_CLOSED,
   	ERR_MEM,
   	ERR_NO_FUNCTION,
   	ERR_OPERATION_FAILED,
   } libResult;

   #include <oqs/oqs.h>
   #include <dlfcn.h>
   #include <stdbool.h>
   #include <stdlib.h>
   #include <string.h>

   typedef struct {
     void *handle;
   } ctx;

   char *errorString(libResult r) {
   	switch (r) {
   	case ERR_CANNOT_LOAD_LIB:
   		return "cannot load library";
   	case ERR_CONTEXT_CLOSED:
   		return "library closed";
   	case ERR_MEM:
   		return "out of memory";
   	case ERR_NO_FUNCTION:
   		return "library missing required function";
   	case ERR_OPERATION_FAILED:

   		return "operation failed";
   	default:
   		return "unknown error";
   	}
   }

   libResult New(const char *path, ctx **c) {
   	*c = malloc(sizeof(ctx));
   	if (!(*c)) {
   		return ERR_MEM;
   	}
   	(*c)->handle = dlopen(path, RTLD_NOW);
   	if (NULL == (*c)->handle) {
   		free(*c);
   		return ERR_CANNOT_LOAD_LIB;
   	}
   	return ERR_OK;
   }

   libResult SetRandomAlg(const ctx *ctx, const char *name) {
   	OQS_STATUS status = OQS_randombytes_switch_algorithm(name);
   	if (status != OQS_SUCCESS) {
   		return ERR_OPERATION_FAILED;
   	}
   	return ERR_OK;
   }

   libResult GetRandomBytes(uint8_t *buf,int nbytes) {
   	OQS_randombytes(buf,nbytes);

   	return ERR_OK;
   }

   libResult GetSign(const ctx *ctx, const char *name, OQS_SIG **sig) {
   	if (!ctx->handle) {
   		return ERR_CONTEXT_CLOSED;
   	}

   	OQS_SIG *(*func)(const char *);
   	*(void **)(&func) = dlsym(ctx->handle, "OQS_SIG_new");
   	if (NULL == func) {
   		return ERR_NO_FUNCTION;
   	}
   	*sig = (*func)(name);
   	return ERR_OK;
   }

   libResult FreeSig(ctx *ctx, OQS_SIG *sig) {
   	if (!ctx->handle) {
   		return ERR_CONTEXT_CLOSED;
   	}
   	void (*func)(OQS_SIG*);
   	*(void **)(&func) = dlsym(ctx->handle, "OQS_SIG_free");
   	if (NULL == func) {
   		return ERR_NO_FUNCTION;
   	}
   	(*func)(sig);
   	return ERR_OK;
   }

   libResult Close(ctx *ctx) {
   	if (!ctx->handle) {
   		return ERR_CONTEXT_CLOSED;
   	}
   	dlclose(ctx->handle);
   	ctx->handle = NULL;
   	return ERR_OK;
   }

   libResult KeyPair(const OQS_SIG *sig, uint8_t *public_key, uint8_t *secret_key) {

   	OQS_STATUS status = OQS_SIG_keypair(sig,public_key, secret_key);
   	if (status != OQS_SUCCESS) {
   		return ERR_OPERATION_FAILED;
   	}
   	return ERR_OK;
   }

   libResult Sign(const OQS_SIG *sig, uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {

   	OQS_STATUS status = OQS_SIG_sign(sig,signature, signature_len, message, message_len, secret_key);
   	if (status != OQS_SUCCESS) {
   		return ERR_OPERATION_FAILED;
   	}
   	return ERR_OK;
   }

   libResult Verify(const OQS_SIG *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {

   	OQS_STATUS status =OQS_SIG_verify(sig,message, message_len, signature, signature_len, public_key);
   	if (status != OQS_SUCCESS) {
   		return ERR_OPERATION_FAILED;
   	}
   	return ERR_OK;
   }
*/
import "C"
import (
"fmt"
"unsafe"

"github.com/pkg/errors"
)

type SigType string

const (
	SigPicnicL1FS SigType = "picnic_L1_FS"

	SigPicnicL1UR SigType = "picnic_L1_UR"

	SigPicnicL3FS SigType = "picnic_L3_FS"

	SigPicnicL3UR SigType = "picnic_L3_UR"

	SigPicnicL5FS SigType = "picnic_L5_FS"

	SigPicnicL5UR SigType = "picnic_L5_UR"

	SigPicnic2L1FS SigType = "picnic2_L1_FS"

	SigPicnic2L3FS SigType = "picnic2_L3_FS"

	SigPicnic2L5FS SigType = "picnic2_L5_FS"

	SigqTESLAI SigType = "qTESLA_I"

	SigqTESLAIIIsize SigType = "qTESLA_III_size"

	SigqTESLAIIIspeed SigType = "qTESLA_III_speed"

	SigDilithium_2 SigType = "DILITHIUM_2"

	SigDilithium_3 SigType = "DILITHIUM_3"

	SigDilithium_4 SigType = "DILITHIUM_4"

	SigMqdss_31_48 SigType = "MQDSS-31-48"

	SigMqdss_31_64 SigType = "MQDSS-31-64"

	SigSphincs_haraka_128f_robust SigType = "SPHINCS+-Haraka-128f-robust"
)

const defaultLibPath = "/usr/local/lib/liboqs.dylib"

type AlgType string

const (
	AlgNistKat AlgType = "NIST-KAT"
)

var errAlreadyClosed = errors.New("already closed")
var errAlgDisabledOrUnknown = errors.New("Signature algorithm is unknown or disabled")

var operationFailed C.libResult = C.ERR_OPERATION_FAILED

type SecretKey struct {
	Sk []byte
	PublicKey
}

type PublicKey struct {
	Pk []byte
}

type OQSSig struct {
	sig *C.OQS_SIG
	ctx *C.ctx
}
type OQSAlg struct {
	alg *C.OQS_STATUS
	ctx *C.ctx
}


func (s *OQSSig) KeyPair() (publicKey PublicKey, secretKey SecretKey, err error) {
	if s.sig == nil {
		return PublicKey{}, SecretKey{}, errAlreadyClosed
	}

	pubKeyLen := C.int(s.sig.length_public_key)
	pk := C.malloc(C.ulong(pubKeyLen))
	defer C.free(unsafe.Pointer(pk))

	secretKeyLen := C.int(s.sig.length_secret_key)
	sk := C.malloc(C.ulong(secretKeyLen))
	defer C.free(unsafe.Pointer(sk))

	res := C.KeyPair(s.sig, (*C.uchar)(pk), (*C.uchar)(sk))
	if res != C.ERR_OK {
		return PublicKey{}, SecretKey{}, libError(res, "key pair generation failed")
	}

	publicKey = PublicKey { Pk: C.GoBytes(pk, pubKeyLen) }
	secretKey = SecretKey{
		C.GoBytes(sk, secretKeyLen),
		publicKey,
	}
	return publicKey, secretKey, nil
}


func (s *OQSSig) Sign(secretKey SecretKey, message []byte) (signature []byte, err error) {
	if s.sig == nil {
		return nil, errAlreadyClosed
	}

	var signatureLen C.ulong

	sig := C.malloc(C.ulong(s.sig.length_signature))
	defer C.free(unsafe.Pointer(sig))

	mes_len := C.size_t(len(message))
	msg := C.CBytes(message)
	defer C.free(msg)

	sk := C.CBytes(secretKey.Sk)
	defer C.free(sk)

	res := C.Sign(s.sig, (*C.uchar)(sig), &signatureLen, (*C.uchar)(msg), mes_len, (*C.uchar)(sk))
	if res != C.ERR_OK {
		return nil, libError(res, "signing failed")
	}

	return C.GoBytes(sig, C.int(signatureLen)), nil
}


func (s *OQSSig) Verify(publicKey PublicKey, signature []byte, message []byte) (assert bool, err error) {
	if s.sig == nil {
		return false, errAlreadyClosed
	}

	mes_len := C.ulong(len(message))
	msg := C.CBytes(message)
	defer C.free(msg)

	sign_len := C.ulong(len(signature))
	sgn := C.CBytes(signature)
	defer C.free(sgn)

	pk := C.CBytes(publicKey.Pk)
	defer C.free(pk)

	res := C.Verify(s.sig, (*C.uchar)(msg), mes_len, (*C.uchar)(sgn), sign_len, (*C.uchar)(pk))
	if res != C.ERR_OK {
		return false, libError(res, "verification failed")
	}

	return true, nil
}


func (s *OQSSig) Close() error {
	if s.sig == nil {
		return errAlreadyClosed
	}

	res := C.FreeSig(s.ctx, s.sig)
	if res != C.ERR_OK {
		return libError(res, "failed to free signature")
	}

	s.sig = nil
	return nil
}


func libError(result C.libResult, msg string, a ...interface{}) error {

	if result == C.ERR_OPERATION_FAILED {
		return errors.Errorf(msg, a...)
	}

	str := C.GoString(C.errorString(result))
	return errors.Errorf("%s: %s", fmt.Sprintf(msg, a...), str)
}


type Sig interface {
	KeyPair() (publicKey PublicKey, secretKey SecretKey, err error)

	Sign(k SecretKey, message []byte) (signature []byte, err error)

	Verify(k PublicKey, signature []byte, publicKey []byte) (assert bool, err error)

	Close() error
}


type OQSLib struct {
	ctx *C.ctx
}


func (l *OQSLib) Close() error {
	res := C.Close(l.ctx)
	if res != C.ERR_OK {
		return libError(res, "failed to close library")
	}

	return nil
}

func LoadDefaultLib() (*OQSLib, error) {
	return LoadLib(defaultLibPath)
}

func LoadLib(path string) (*OQSLib, error) {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))

	var ctx *C.ctx
	res := C.New(p, &ctx)
	if res != C.ERR_OK {
		return nil, libError(res, "failed to load module at %q", path)
	}

	return &OQSLib{ctx: ctx}, nil
}


func (l *OQSLib) GetSign(SigType SigType) (*OQSSig, error) {
	cStr := C.CString(string(SigType))
	defer C.free(unsafe.Pointer(cStr))

	var sigPtr *C.OQS_SIG

	res := C.GetSign(l.ctx, cStr, &sigPtr)
	if res != C.ERR_OK {
		return nil, libError(res, "failed to get Signature")
	}

	sig := &OQSSig{
		sig: sigPtr,
		ctx: l.ctx,
	}
	if sig.sig == nil {
		return nil, errAlgDisabledOrUnknown
	}

	return sig, nil
}


func (l *OQSLib) SetRandomAlg(strAlg AlgType) (int, error) {
	cStr := C.CString(string(strAlg))
	defer C.free(unsafe.Pointer(cStr))

	res := C.SetRandomAlg(l.ctx, cStr)

	if res != C.ERR_OK {
		return -1, libError(res, "failed to get Alg")
	}

	return 1, nil
}


func (l *OQSLib) GetRandomBytes(nbytes int) (randombytes []byte, err error) {
	bytes := C.malloc(C.ulong(nbytes))
	defer C.free(unsafe.Pointer(bytes))

	res := C.GetRandomBytes((*C.uint8_t)(bytes), C.int(nbytes))

	if res != C.ERR_OK {
		return nil, libError(res, "failed to set bytes")
	}

	return C.GoBytes(bytes, C.int(nbytes)), nil
}

