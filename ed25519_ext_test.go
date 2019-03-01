// Copyright 2019 Spacemesh Authors
// ed25519 extensions unit tests

package ed25519

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPublicKeyExtraction(t *testing.T) {
	var zero zeroReader
	public, private, _ := GenerateKey(zero)
	message := []byte("test message")

	// sign the message
	sig := SignExt(private, message)

	// extract public key from signature and the message
	public1, err := ExtractPublicKey(message, sig)

	// ensure extracted key is the same as public key created by GenerateKey()
	assert.NoError(t, err)
	assert.EqualValues(t, public, public1, "expected same public key")

	// attempt to extract the public key from the same sig but a wrong message
	wrongMessage := []byte("wrong message")
	public2, err := ExtractPublicKey(wrongMessage, sig)

	// we expect the extracted key to not be the same as the correct signer public key
	assert.NoError(t, err)
	if bytes.Compare(public, public2) == 0 {
		t.Errorf("expected different public keys")
	}
}

func TestSignVerifyExt(t *testing.T) {
	var zero zeroReader
	public, private, _ := GenerateKey(zero)

	message := []byte("test message")

	// sign and verify a message using the public key created by GenerateKey()
	sig := SignExt(private, message)
	if !VerifyExt(public, message, sig) {
		t.Errorf("valid signature rejected")
	}

	// Verification of the signature on a wrong message should fail
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
