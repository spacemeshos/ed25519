// Copyright 2019 Spacemesh Authors
// ed25519 extensions tests

package ed25519

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestInvertModL(t *testing.T) {
	var x, out [32]byte
	x[0] = byte(0x2)
	InvertModL(&out, &x)
	fmt.Printf("Hex string: 0x%s\n", hex.EncodeToString(out[:]))
	fmt.Printf("Int value: %s\n", ToInt(out[:]).String())
}

func Test2InvertModL(t *testing.T) {
	var x, tinv, out [32]byte
	x[0] = byte(0x2)	// I don't want this to be 2 anymore, but some 'random' 252-bit number.
				// I call this number t in the code below, so as if is the input to the function.
	InvertModL(&tinv, &x)	// (so this should be inverse of t, not x)
	// let's check that we actually get some number
	fmt.Printf("Hex string: 0x%s\n", hex.EncodeToString(tinv[:]))
	fmt.Printf("Int value: %s\n", ToInt(tinv[:]).String())
	edwards25519.ScMulAdd(&out, &t, &tinv, &zero)
	// checking that we actually got the inverse - result should be 1.
	fmt.Printf("Hex string: 0x%s\n", hex.EncodeToString(out[:]))
	fmt.Printf("Int value: %s\n", ToInt(out[:]).String())
}

// ToInt returns 256^0*b[0]+256^1*b[1]+...+256^31*b[len(b)-1]
func ToInt(b []byte) *big.Int {
	l := len(b)
	res := big.NewInt(0)
	mul := big.NewInt(0)
	c := big.NewInt(256)
	t := big.NewInt(0)

	for i := 0; i < l; i++ {

		// 256^i
		mul = mul.Exp(c, big.NewInt(int64(i)), nil)

		// res[i] = 256^i * bytes[i]
		data := big.NewInt(int64(b[i]))
		t = t.Mul(data, mul)
		res = res.Add(res, t)
	}
	return res
}

func TestPublicKeyExtraction(t *testing.T) {
	var zero zeroReader
	public, private, _ := GenerateKey(zero)
	message := []byte("test message")
	sig := SignExt(private, message)

	public1, err := ExtractPublicKey(message, sig)

	assert.NoError(t, err)
	assert.EqualValues(t, public, public1, "expected same public key")

	wrongMessage := []byte("wrong message")
	public2, err := ExtractPublicKey(wrongMessage, sig)

	assert.NoError(t, err)
	if bytes.Compare(public, public2) == 0 {
		t.Errorf("expected different public keys")
	}

}

func TestSignVerifyExt(t *testing.T) {
	var zero zeroReader
	public, private, _ := GenerateKey(zero)

	message := []byte("test message")
	sig := SignExt(private, message)
	if !Verify(public, message, sig) {
		t.Errorf("valid signature rejected")
	}

	wrongMessage := []byte("wrong message")
	if Verify(public, wrongMessage, sig) {
		t.Errorf("signature of different message accepted")
	}
}

func BenchmarkPublicKeyExtraction(b *testing.B) {
	var zero zeroReader
	_, priv, err := GenerateKey(zero)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	sig := SignExt(priv, message)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ExtractPublicKey(message, sig)
	}
}

func BenchmarkSigningExt(b *testing.B) {
	var zero zeroReader
	_, priv, err := GenerateKey(zero)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SignExt(priv, message)
	}
}

func BenchmarkVerificationExt(b *testing.B) {
	var zero zeroReader
	pub, priv, err := GenerateKey(zero)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	signature := SignExt(priv, message)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(pub, message, signature)
	}
}
