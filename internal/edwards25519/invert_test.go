// Copyright 2019 Spacemesh Authors
// edwards25519 invert mod l unit tests

package edwards25519

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// test vectors
const INV_2 = "3618502788666131106986593281521497120428558179689953803000975469142727125495"
const INV_17 = "851412420862619083996845478005058145983190159927047953647288345680641676587"

func BenchmarkInvertModL(b *testing.B) {
	var xInv Scalar
	xBytes := make([]byte, 32)
	xBytes[0] = byte(2)
	x, err := NewScalar().SetBytesWithClamping(xBytes)
	require.NoError(b, err, "failed to set bytes")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InvertModL(&xInv, x)
	}
}

func TestInvertModLOne(t *testing.T) {
	var xInv Scalar
	xBytes := make([]byte, 32)
	xBytes[0] = byte(1)
	x, err := NewScalar().SetCanonicalBytes(xBytes)
	require.NoError(t, err, "failed to set bytes")

	InvertModL(&xInv, x)
	require.Equal(t, big.NewInt(1), toInt(xInv.Bytes()))

	x.Multiply(x, &xInv)
	outVal := toInt(x.Bytes())
	require.Equal(t, big.NewInt(1), outVal, "expected 1 * 1 == 1")
}

func TestInvertModL2(t *testing.T) {
	var xInv Scalar
	xBytes := make([]byte, 32)
	xBytes[0] = byte(2)
	x, err := NewScalar().SetCanonicalBytes(xBytes)
	require.NoError(t, err, "failed to set bytes")

	InvertModL(&xInv, x)
	require.Equal(t, INV_2, toInt(xInv.Bytes()).String())

	x.Multiply(x, &xInv)
	require.Equal(t, big.NewInt(1), toInt(x.Bytes()), "expected x * xInv == 1")
}

func TestInvertModL17(t *testing.T) {
	var xInv Scalar
	xBytes := make([]byte, 32)
	xBytes[0] = byte(17)
	x, err := NewScalar().SetCanonicalBytes(xBytes)
	require.NoError(t, err, "failed to set bytes")

	InvertModL(&xInv, x)
	require.Equal(t, INV_17, toInt(xInv.Bytes()).String())

	x.Multiply(x, &xInv)
	outVal := toInt(x.Bytes()).String()
	require.Equal(t, "1", outVal, "expected x * xInv == 1")
}

func TestInvertModLRnd(testing *testing.T) {
	var tinv, out Scalar
	for i := 1; i < 100; i++ {
		t, err := NewScalar().SetUniformBytes(rnd64Bytes(testing))
		require.NoError(testing, err, "failed to set bytes")

		InvertModL(&tinv, t)
		out.Multiply(t, &tinv)
		require.Equal(testing, big.NewInt(1), toInt(out.Bytes()), "expected t * tinv to equal 1")
	}
}

// toInt returns a big int with the value of 256^0*b[0]+256^1*b[1]+...+256^31*b[len(b)-1]
// b must be a non-empty bytes slice. toInt is a test helper function.
func toInt(b []byte) *big.Int {
	res := big.NewInt(0)
	mul := big.NewInt(0)
	c := big.NewInt(256)
	t := big.NewInt(0)
	data := big.NewInt(0)
	l := len(b)

	for i := 0; i < l; i++ {

		// 256^i
		mul = mul.Exp(c, big.NewInt(int64(i)), nil)

		// res[i] = 256^i * b[i]
		data.SetUint64(uint64(b[i]))
		t = t.Mul(data, mul)
		res = res.Add(res, t)
	}
	return res
}

func rnd64Bytes(tb testing.TB) []byte {
	d := make([]byte, 64)
	n, err := rand.Read(d)
	require.NoError(tb, err, "no system entropy")
	require.Equal(tb, 64, n, "expected 32 bytes of entropy")
	return d
}
