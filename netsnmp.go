package asn1cmp

/*
#cgo LDFLAGS: -lnetsnmp
#include <stdint.h>
#include <stdlib.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/output_api.h>
#include <net-snmp/config_api.h>

u_char* getPktStart(u_char* pkt, ulong len, ulong off){
	return pkt+len-off;
}
*/
import "C"
import (
	"errors"
	"unsafe"
)

func NetSnmpAsn1Marshal(typ NetSnmpAsnType, data any) ([]byte, error) {
	switch typ {
	case ASN_GAUGE, ASN_COUNTER, ASN_TIMETICKS, ASN_UINTEGER:
		return NetSnmpAsn1Uint(typ, int(data.(uint32)))
	case ASN_OPAQUE_COUNTER64, ASN_OPAQUE_U64, ASN_COUNTER64:
		return NetSnmpAsn1Uint64(typ, data.(uint64))
	case ASN_OPAQUE_I64:
		return NetSnmpAsn1Int64(typ, data.(int64))
	case ASN_OPAQUE_FLOAT:
		return NetSnmpAsn1Float(typ, data.(float32))
	case ASN_OPAQUE_DOUBLE:
		return NetSnmpAsn1Double(typ, data.(float64))
	default:
		return nil, errors.New("unknown type")
	}

}

// NetSnmpAsn1Int uses `asn_build_unsigned_int` to build a uint type
func NetSnmpAsn1Uint(typ NetSnmpAsnType, data int) ([]byte, error) {
	in := C.ulong(data)
	sz := C.sizeof_long

	bufszorig := C.size_t(512)
	bufsz := bufszorig
	buf := (*C.uchar)(C.malloc(bufsz))
	defer C.free(unsafe.Pointer(buf))

	rc := C.asn_build_unsigned_int(buf, &bufsz, (C.uchar)(typ), &in, C.ulong(sz))

	if unsafe.Pointer(rc) == C.NULL {
		return nil, errors.New("error with 'asn_build_int'")
	}

	return C.GoBytes(unsafe.Pointer(buf), C.int(bufszorig-bufsz)), nil

}

// NetSnmpAsn1Uint64 uses `asn_build_unsigned_int64` to build a uint64 type
func NetSnmpAsn1Uint64(typ NetSnmpAsnType, data uint64) ([]byte, error) {
	high := data >> 32
	low := (data << 32) >> 32
	in := C.struct_counter64{
		high: C.ulong(high),
		low:  C.ulong(low),
	}
	sz := C.sizeof_struct_counter64

	bufszorig := C.size_t(512)
	bufsz := bufszorig
	buf := (*C.uchar)(C.malloc(bufsz))
	defer C.free(unsafe.Pointer(buf))

	rc := C.asn_build_unsigned_int64(buf, &bufsz, (C.uchar)(typ), &in, C.ulong(sz))

	if unsafe.Pointer(rc) == C.NULL {
		return nil, errors.New("error with 'asn_build_int'")
	}

	return C.GoBytes(unsafe.Pointer(buf), C.int(bufszorig-bufsz)), nil
}

// NetSnmpAsn1Int64 uses `asn_build_signed_int64` to build a int64 type
func NetSnmpAsn1Int64(typ NetSnmpAsnType, data int64) ([]byte, error) {
	high := data >> 32
	low := (data << 32) >> 32
	in := C.struct_counter64{
		high: C.ulong(high),
		low:  C.ulong(low),
	}
	sz := C.sizeof_struct_counter64

	bufszorig := C.size_t(512)
	bufsz := bufszorig
	buf := (*C.uchar)(C.malloc(bufsz))
	defer C.free(unsafe.Pointer(buf))

	rc := C.asn_build_signed_int64(buf, &bufsz, (C.uchar)(typ), &in, C.ulong(sz))

	if unsafe.Pointer(rc) == C.NULL {
		return nil, errors.New("error with 'asn_build_int'")
	}

	return C.GoBytes(unsafe.Pointer(buf), C.int(bufszorig-bufsz)), nil

}

// NetSnmpAsn1Float uses `asn_build_float` to build a float type
func NetSnmpAsn1Float(typ NetSnmpAsnType, data float32) ([]byte, error) {
	in := C.float(data)
	sz := C.sizeof_float

	bufszorig := C.size_t(512)
	bufsz := bufszorig
	buf := (*C.uchar)(C.malloc(bufsz))
	defer C.free(unsafe.Pointer(buf))

	rc := C.asn_build_float(buf, &bufsz, (C.uchar)(typ), &in, C.ulong(sz))

	if unsafe.Pointer(rc) == C.NULL {
		return nil, errors.New("error with 'asn_build_int'")
	}

	return C.GoBytes(unsafe.Pointer(buf), C.int(bufszorig-bufsz)), nil

}

// NetSnmpAsn1Double uses `asn_build_double` to build a double type
func NetSnmpAsn1Double(typ NetSnmpAsnType, data float64) ([]byte, error) {
	in := C.double(data)
	sz := C.sizeof_double

	bufszorig := C.size_t(512)
	bufsz := bufszorig
	buf := (*C.uchar)(C.malloc(bufsz))
	defer C.free(unsafe.Pointer(buf))

	rc := C.asn_build_double(buf, &bufsz, (C.uchar)(typ), &in, C.ulong(sz))

	if unsafe.Pointer(rc) == C.NULL {
		return nil, errors.New("error with 'asn_build_int'")
	}

	return C.GoBytes(unsafe.Pointer(buf), C.int(bufszorig-bufsz)), nil

}

func netSnmpEnableLogging() {
	C.snmp_enable_stderrlog()
	C.snmp_set_do_debugging(1)
	C.snmp_set_dump_packet(1)
	tmp := C.CString("")
	C.debug_register_tokens(tmp)
	C.free(unsafe.Pointer(tmp))
}
