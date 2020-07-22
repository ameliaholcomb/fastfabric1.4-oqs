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


type AlgType string

const (
	AlgNistKat AlgType = "NIST-KAT"
	defaultLibPath string = "liboqs.so"
	defaultSigType SigType = SigqTESLAI
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
	Sig OQSSigInfo
}

type OQSSig struct {
	sig *C.OQS_SIG
	ctx *C.ctx
}

type OQSLib struct {
	ctx *C.ctx
}

type OQSSigInfo struct {
	Algorithm SigType
}

var packageLib *OQSLib
var packageSig *OQSSig

func KeyPair() (publicKey PublicKey, secretKey SecretKey, err error) {
	if packageSig == nil {
		InitSig()
	}

	pubKeyLen := C.int(packageSig.sig.length_public_key)
	pk := C.malloc(C.ulong(pubKeyLen))
	defer C.free(unsafe.Pointer(pk))

	secKeyLen := C.int(packageSig.sig.length_secret_key)
	sk := C.malloc(C.ulong(secKeyLen))
	defer C.free(unsafe.Pointer(sk))

	res := C.KeyPair(packageSig.sig, (*C.uchar)(pk), (*C.uchar)(sk))
	if res != C.ERR_OK {
		return PublicKey{}, SecretKey{}, libError(res, "key pair generation failed")
	}

	s := OQSSigInfo{
		Algorithm: SigType(C.GoString(packageSig.sig.method_name)),
	}
	publicKey = PublicKey { Pk: C.GoBytes(pk, pubKeyLen), Sig: s}
	secretKey = SecretKey{
		C.GoBytes(sk, secKeyLen),
		publicKey,
	}
	return publicKey, secretKey, nil
}


func Sign(secretKey SecretKey, message []byte) (signature []byte, err error) {
	if packageSig == nil {
		InitSig()
	}
	var signatureLen C.ulong

	sig := C.malloc(C.ulong(packageSig.sig.length_signature))
	defer C.free(unsafe.Pointer(sig))

	mes_len := C.size_t(len(message))
	msg := C.CBytes(message)
	defer C.free(msg)

	sk := C.CBytes(secretKey.Sk)
	defer C.free(sk)

	res := C.Sign(packageSig.sig, (*C.uchar)(sig), &signatureLen, (*C.uchar)(msg), mes_len, (*C.uchar)(sk))
	if res != C.ERR_OK {
		return nil, libError(res, "signing failed")
	}

	return C.GoBytes(sig, C.int(signatureLen)), nil
}


func Verify(publicKey PublicKey, signature []byte, message []byte) (assert bool, err error) {
	if packageSig == nil {
		InitSig()
	}
	mes_len := C.ulong(len(message))
	msg := C.CBytes(message)
	defer C.free(msg)

	sign_len := C.ulong(len(signature))
	sgn := C.CBytes(signature)
	defer C.free(sgn)

	pk := C.CBytes(publicKey.Pk)
	defer C.free(pk)

	res := C.Verify(packageSig.sig, (*C.uchar)(msg), mes_len, (*C.uchar)(sgn), sign_len, (*C.uchar)(pk))
	if res != C.ERR_OK {
		return false, libError(res, "verification failed")
	}

	return true, nil
}

func libError(result C.libResult, msg string, a ...interface{}) error {

	if result == C.ERR_OPERATION_FAILED {
		return errors.Errorf(msg, a...)
	}

	str := C.GoString(C.errorString(result))
	return errors.Errorf("%s: %s", fmt.Sprintf(msg, a...), str)
}


// InitSig may optionally specify a SigType.
// If exactly one SigType is not supplied, Init will fall back to defaultSigType
func InitSig(sigT ...SigType) (err error) {
	if packageSig != nil {
		return nil
	}
	if packageLib == nil {
		err = InitLib()
		if err != nil {
			return err
		}
	}
	cryptoAlg := defaultSigType
	if len(sigT) == 1 {
		cryptoAlg = sigT[0]

	}
	sig, err := GetSign(packageLib, cryptoAlg)
	if err != nil {
		return errors.Wrapf(err, "Unable to load OQS crypto sig for %s", cryptoAlg)
	}
	packageSig = sig
	return nil
}

func InitLib() (err error) {
	if packageLib != nil {
		return nil
	}
	lib, err := LoadLib(defaultLibPath)
	if err != nil {
		return err
	}
	packageLib = lib
	return nil
}

func DestroySig() (err error) {
	if packageSig == nil {
		return nil
	}
	err = CloseSig(packageSig)
	if err == nil {
		packageSig = nil
	}
	return err
}


func DestroyLib() (err error) {
	if packageLib == nil {
		return nil
	}
	err = CloseLib(packageLib)
	if err == nil {
		packageLib = nil
	}
	return err
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

func CloseLib(lib *OQSLib) (error) {
	res := C.Close(lib.ctx)
	if res != C.ERR_OK {
		return libError(res, "failed to close library")
	}
	return nil
}


func GetSign(lib *OQSLib, alg SigType) (*OQSSig, error) {
	cStr := C.CString(string(alg))
	defer C.free(unsafe.Pointer(cStr))

	var sigPtr *C.OQS_SIG

	res := C.GetSign(lib.ctx, cStr, &sigPtr)
	if res != C.ERR_OK {
		return nil, libError(res, "failed to get Signature")
	}

	sig := &OQSSig{
		sig: sigPtr,
		ctx: lib.ctx,
	}
	if sig.sig == nil {
		return nil, errAlgDisabledOrUnknown
	}

	return sig, nil
}

func CloseSig(sig *OQSSig) (error) {
	if sig == nil {
		return errAlreadyClosed
	}
	res := C.FreeSig(sig.ctx, sig.sig)
	if res != C.ERR_OK {
		return libError(res, "failed to free signature")
	}

	sig.sig = nil
	return nil
}

func SetRandomAlg(lib *OQSLib, strAlg AlgType) (int, error) {
	cStr := C.CString(string(strAlg))
	defer C.free(unsafe.Pointer(cStr))

	res := C.SetRandomAlg(lib.ctx, cStr)

	if res != C.ERR_OK {
		return -1, libError(res, "failed to get Alg")
	}

	return 1, nil
}

func GetRandomBytes(nbytes int) (randombytes []byte, err error) {
	bytes := C.malloc(C.ulong(nbytes))
	defer C.free(unsafe.Pointer(bytes))

	res := C.GetRandomBytes((*C.uint8_t)(bytes), C.int(nbytes))

	if res != C.ERR_OK {
		return nil, libError(res, "failed to set bytes")
	}

	return C.GoBytes(bytes, C.int(nbytes)), nil
}

