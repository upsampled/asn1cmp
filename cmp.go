package asn1cmp

import (
	"encoding/asn1"
	"fmt"
)

//go:generate stringer -type=NetSnmpAsnType
type NetSnmpAsnType int

// from include/net-snmp/library/snmp_impl.h#L90
const (
	/*
	 * defined types (from the SMI, RFC 1157)
	 */
	ASN_APPLICATION NetSnmpAsnType = 0x40
	ASN_IPADDRESS                  = ASN_APPLICATION + 0
	ASN_COUNTER                    = ASN_APPLICATION + 1
	ASN_GAUGE                      = ASN_APPLICATION + 2
	ASN_UNSIGNED                   = ASN_APPLICATION + 2 /* RFC 1902 - same as GAUGE */
	ASN_TIMETICKS                  = ASN_APPLICATION + 3
	ASN_OPAQUE                     = ASN_APPLICATION + 4 /* changed so no conflict with other includes */

	/*
	 * defined types (from the SMI, RFC 1442)
	 */
	//ASN_NSAP      = ASN_APPLICATION + 5 /* historic - don't use */
	ASN_COUNTER64 = ASN_APPLICATION + 6
	ASN_UINTEGER  = ASN_APPLICATION + 7 /* historic - don't use */

	/*
	 * defined types from draft-perkins-opaque-01.txt
	 */
	ASN_FLOAT      = ASN_APPLICATION + 8
	ASN_DOUBLE     = ASN_APPLICATION + 9
	ASN_INTEGER64  = ASN_APPLICATION + 10
	ASN_UNSIGNED64 = ASN_APPLICATION + 11

	ASN_OPAQUE_TAG2      = 0x30
	ASN_OPAQUE_COUNTER64 = ASN_OPAQUE_TAG2 + ASN_FLOAT
	ASN_OPAQUE_FLOAT     = ASN_OPAQUE_TAG2 + ASN_COUNTER64
	ASN_OPAQUE_DOUBLE    = ASN_OPAQUE_TAG2 + ASN_DOUBLE
	ASN_OPAQUE_I64       = ASN_OPAQUE_TAG2 + ASN_INTEGER64
	ASN_OPAQUE_U64       = ASN_OPAQUE_TAG2 + ASN_UNSIGNED64
)

func (t NetSnmpAsnType) String() string {
	switch t {
	case ASN_COUNTER64:
		return "ASN_COUNTER64"
	case ASN_UINTEGER:
		return "ASN_UINTERGER"
	case ASN_FLOAT:
		return "ASN_FLOAT"
	case ASN_DOUBLE:
		return "ASN_DOUBLE"
	case ASN_INTEGER64:
		return "ASN_INTEGER64"
	case ASN_UNSIGNED64:
		return "ASN_UNSIGNED64"
	case ASN_OPAQUE_COUNTER64:
		return "ASN_OPAQUE_COUNTER64"
	case ASN_OPAQUE_FLOAT:
		return "ASN_OPAQUE_FLOAT"
	case ASN_OPAQUE_DOUBLE:
		return "ASN_OPAQUE_DOUBLE"
	case ASN_OPAQUE_I64:
		return "ASN_OPAQUE_I64"
	case ASN_OPAQUE_U64:
		return "ASN_OPAQUE_U64"
	}
	return "unknown"
}

func GoAsn1Marshal(typ NetSnmpAsnType, data any) ([]byte, error) {

	var in interface{}
	switch v := data.(type) {
	case uint32:
		in = int(v)
	default:
		in = data
	}

	tag := fmt.Sprintf("application,tag:%d", typ-ASN_APPLICATION)
	return asn1.MarshalWithParams(in, tag)

}
