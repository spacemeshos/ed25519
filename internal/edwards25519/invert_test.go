// Copyright 2019 Spacemesh Authors
// edwards25519 invert mod l unit tests

package edwards25519

import (
	"crypto/rand"
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

// test vectors
const INV_2 = "3618502788666131106986593281521497120428558179689953803000975469142727125495"
const INV_17 = "851412420862619083996845478005058145983190159927047953647288345680641676587"

func BenchmarkInvertModL(b *testing.B) {
	var x, xInv [32]byte
	x[0] = byte(2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InvertModL(&xInv, &x)
	}
}

func TestInvertModLOne(t *testing.T) {
	var x, xInv, z [32]byte
	x[0] = byte(1)
	InvertModL(&xInv, &x)
	assert.Equal(t, "1", ToInt(xInv[:]).String())
	ScMulAdd(&x, &x, &xInv, &z)
	outVal := ToInt(x[:])
	assert.Equal(t, "1", outVal.String(), "expected 0 * 0 == 0")
}

func TestInvertModL2(t *testing.T) {
	var x, xInv, z [32]byte
	x[0] = byte(2)
	InvertModL(&xInv, &x)
	xInvStr := ToInt(xInv[:]).String()
	// fmt.Printf("Hex string: 0x%s\n", hex.EncodeToString(xInv[:]))
	// fmt.Printf("Int value: %s\n", xInvStr)
	assert.Equal(t, INV_2, xInvStr)

	ScMulAdd(&x, &x, &xInv, &z)
	outVal := ToInt(x[:]).String()
	// fmt.Printf("Hex string: 0x%s\n", hex.EncodeToString(x[:]))
	// fmt.Printf("Int value: %s\n", outVal)
	assert.Equal(t, "1", outVal, "expected x * xInv == 1")
}

func TestInvertModL17(t *testing.T) {
	var x, xInv, z [32]byte
	x[0] = byte(17)
	InvertModL(&xInv, &x)
	xInvStr := ToInt(xInv[:]).String()
	assert.Equal(t, INV_17, xInvStr)
	ScMulAdd(&x, &x, &xInv, &z)
	outVal := ToInt(x[:]).String()
	assert.Equal(t, "1", outVal, "expected x * xInv == 1")
}

func TestInvertModLRnd(testing *testing.T) {
	var t, tinv, z, out [32]byte
	for i := 1; i < 10000; i++ {
		n, err := rand.Read(t[:])
		fmt.Printf("Rand value: 0x%x\n", t[:])
		// tStr := ToInt(t[:]).String()
		// fmt.Printf("Int value: %s\n", tStr)

		assert.NoError(testing, err, "no system entropy")
		assert.Equal(testing, 32, n, "expected 32 bytes of entropy")

		InvertModL(&tinv, &t)
		ScMulAdd(&out, &t, &tinv, &z)
		assert.Equal(testing, "1", ToInt(out[:]).String(), "expected t * tinv to equal 1")
	}
}

// ToInt returns a big int with the value of 256^0*b[0]+256^1*b[1]+...+256^31*b[len(b)-1]
// b must be a non-empty bytes slice. ToInt is a test helper function.
func ToInt(b []byte) *big.Int {
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
