package dkim

// #cgo pkg-config: opendkim
// #include <opendkim/dkim.h>
import "C"
import "fmt"
import "unsafe"

var lib *C.DKIM_LIB = nil

func VerifyMessage(msg []byte) (bool, error) {
	var err error

	if lib == nil {
		lib = C.dkim_init(nil, nil)
		if lib == nil {
			return false, fmt.Errorf("dkim_init() failed")
		}
	}

	var flags C.u_int = C.DKIM_LIBFLAGS_FIXCRLF
	C.dkim_options(lib, C.DKIM_OP_SETOPT, C.DKIM_OPTS_FLAGS, unsafe.Pointer(&flags), C.size_t(unsafe.Sizeof(flags)))

	var status C.DKIM_STAT

	dkim := C.dkim_verify(lib, (*C.uchar)(unsafe.Pointer(C.CString("go-dkim"))), nil, &status)
	if dkim == nil {
		err = fmt.Errorf("dkim_verify(): %s", C.GoString(C.dkim_getresultstr(status)))
		return false, err
	}

	status = C.dkim_chunk(dkim, (*C.u_char)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)))
	if status != C.DKIM_STAT_OK {
		err = fmt.Errorf("dkim_chunk(): %s", C.GoString(C.dkim_getresultstr(status)))
		goto fail
	}

	status = C.dkim_chunk(dkim, nil, 0)
	if status != C.DKIM_STAT_OK {
		err = fmt.Errorf("dkim_chunk(): %s", C.GoString(C.dkim_getresultstr(status)))
		goto fail
	}

	status = C.dkim_eom(dkim, nil) // TODO testkey
	if status != C.DKIM_STAT_OK {
		err = fmt.Errorf("dkim_eom(): %s", C.GoString(C.dkim_getresultstr(status)))
		goto fail
	}

	return true, nil

fail:
	C.dkim_free(dkim)
	return false, err
}
