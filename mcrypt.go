package nscatools

/*
#cgo LDFLAGS: -lmcrypt
#include <stdlib.h>
#include <string.h>
#include <mcrypt.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// MCrypt uses libmcrypt to decrypt/encrypt the data received from the send_nsca
// client. When I have some more time I'll dig to find out why I'm not able to
// decrypt directly using the NewCFBDecrypter
// To decrypt, set the decrypt parameter to true, else it will encrypt.
func MCrypt(algo string, blocks, key, iv []byte, decrypt bool) error {
	algorithm := C.CString(algo)
	defer C.free(unsafe.Pointer(algorithm))

	mode := C.CString("cfb")
	defer C.free(unsafe.Pointer(mode))

	td := C.mcrypt_module_open(algorithm, nil, mode, nil)
	defer C.mcrypt_module_close(td)

	if uintptr(unsafe.Pointer(td)) == C.MCRYPT_FAILED {
		return fmt.Errorf("mcrypt module open failed")
	}

	keySize := C.mcrypt_enc_get_key_size(td)
	ivSize := C.mcrypt_enc_get_iv_size(td)
	realKey := make([]byte, keySize)
	if len(key) > int(keySize) {
		copy(realKey, key[:keySize])
	} else {
		copy(realKey, key)
	}
	realIv := make([]byte, ivSize)
	if len(iv) > int(ivSize) {
		copy(realIv, iv[:ivSize])
	} else {
		copy(realIv, iv)
	}

	rv := C.mcrypt_generic_init(td, unsafe.Pointer(&realKey[0]), keySize, unsafe.Pointer(&realIv[0]))
	defer C.mcrypt_generic_deinit(td)

	if rv < 0 {
		return fmt.Errorf("mcrypt generic init failed")
	}

	bufferSize := len(blocks)
	if decrypt == true {
		for x := 0; x < bufferSize; x++ {
			C.mdecrypt_generic(td, unsafe.Pointer(&blocks[x]), C.int(1))
		}
	} else {
		for x := 0; x < bufferSize; x++ {
			C.mcrypt_generic(td, unsafe.Pointer(&blocks[x]), C.int(1))
		}
	}
	return nil
}
