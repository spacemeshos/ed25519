// Copyright 2019 Spacemesh Authors
// ed25519 extensions tests

package ed25519

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func VerifyEx(publicKey PublicKey, message, sig []byte) bool {
	if l := len(publicKey); l != PublicKeySize {
		panic("ed25519: bad public key length: " + strconv.Itoa(l))
	}

	if len(sig) != SignatureSize || sig[63]&224 != 0 {
		return false
	}

	var A edwards25519.ExtendedGroupElement
	var publicKeyBytes [32]byte
	copy(publicKeyBytes[:], publicKey)
	if !A.FromBytes(&publicKeyBytes) {
		return false
	}
	edwards25519.FeNeg(&A.X, &A.X)
	edwards25519.FeNeg(&A.T, &A.T)

	h := sha512.New()
	h.Write(sig[:32])
	// we remove the public key from the hash
	// h.Write(publicKey[:])
	h.Write(message)
	var digest [64]byte
	h.Sum(digest[:0])

	var hReduced [32]byte
	edwards25519.ScReduce(&hReduced, &digest)

	var R edwards25519.ProjectiveGroupElement
	var s [32]byte
	copy(s[:], sig[32:])

	// https://tools.ietf.org/html/rfc8032#section-5.1.7 requires that s be in
	// the range [0, order) in order to prevent signature malleability.
	if !edwards25519.ScMinimal(&s) {
		return false
	}

	edwards25519.GeDoubleScalarMultVartime(&R, &hReduced, &A, &s)

	var checkR [32]byte
	R.ToBytes(&checkR)
	return bytes.Equal(sig[:32], checkR[:])
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
	if !VerifyEx(public, message, sig) {
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
