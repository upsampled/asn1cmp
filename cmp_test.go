package asn1cmp

import (
	"fmt"
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type cmpTst struct {
	data any
	typ  NetSnmpAsnType
}

func testNetSnmpvGo(t *testing.T, tst cmpTst) {
	got, err := GoAsn1Marshal(tst.typ, tst.data)
	if err != nil {
		t.Fatal(err)
	}
	exp, err := NetSnmpAsn1Marshal(tst.typ, tst.data)
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(exp, got); diff != "" {
		t.Fatalf("exp: %x \n got:%x \n%s", exp, got, diff)
	}

}
func TestUint32(t *testing.T) {
	in := []cmpTst{
		{uint32(math.MaxUint32), ASN_GAUGE},
		{uint32(math.MaxUint32), ASN_COUNTER},
		{uint32(math.MaxUint32), ASN_TIMETICKS},
		{uint32(math.MaxUint32), ASN_UINTEGER},
		{uint32(0), ASN_GAUGE},
		{uint32(0), ASN_COUNTER},
		{uint32(0), ASN_TIMETICKS},
		{uint32(0), ASN_UINTEGER},
	}

	for i := range in {
		t.Run(fmt.Sprintf("%s_%d", in[i].typ.String(), in[i].data), func(t *testing.T) {
			testNetSnmpvGo(t, in[i])
		})
	}

}

func TestUint64(t *testing.T) {
	in := []cmpTst{
		{uint64(math.MaxUint64), ASN_OPAQUE_COUNTER64},
		{uint64(math.MaxUint64), ASN_OPAQUE_U64},
		{uint64(math.MaxUint64), ASN_COUNTER64},
		{uint64(0), ASN_OPAQUE_COUNTER64},
		{uint64(0), ASN_OPAQUE_U64},
		{uint64(0), ASN_COUNTER64},
	}

	for i := range in {
		t.Run(fmt.Sprintf("%s_%d", in[i].typ.String(), in[i].data), func(t *testing.T) {
			testNetSnmpvGo(t, in[i])
		})
	}
}

func TestInt64(t *testing.T) {
	in := []cmpTst{
		{int64(math.MaxInt64), ASN_OPAQUE_I64},
		{int64(0), ASN_OPAQUE_I64},
	}

	for i := range in {
		t.Run(fmt.Sprintf("%s_%d", in[i].typ.String(), in[i].data), func(t *testing.T) {
			testNetSnmpvGo(t, in[i])
		})
	}

}

func TestFloats(t *testing.T) {
	in := []cmpTst{
		{float32(math.MaxFloat32), ASN_OPAQUE_FLOAT},
		{float64(math.MaxFloat64), ASN_OPAQUE_DOUBLE},
		{float32(0), ASN_OPAQUE_FLOAT},
		{float64(0), ASN_OPAQUE_DOUBLE},
	}

	for i := range in {
		t.Run(fmt.Sprintf("%s_%v", in[i].typ.String(), in[i].data), func(t *testing.T) {
			testNetSnmpvGo(t, in[i])
		})
	}

}
