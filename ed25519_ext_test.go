// Copyright 2019 Spacemesh Authors
// ed25519 extensions unit tests

package ed25519

import (
	"bytes"
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

// Test with a fixed message
func TestPublicKeyExtraction(t *testing.T) {
	var zero zeroReader
	public, private, _ := GenerateKey(zero)
	message := []byte("test message")

	// sign the message
	sig := Sign2(private, message)

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

// Test with a random message
func TestPublicKeyExtraction1(t *testing.T) {
	var zero zeroReader
	public, private, _ := GenerateKey(zero)

	message := rnd32Bytes(t)

	// sign the message
	sig := Sign2(private, message[:])

	// extract public key from signature and the message
	public1, err := ExtractPublicKey(message[:], sig)

	// ensure extracted key is the same as public key created by GenerateKey()
	assert.NoError(t, err)
	assert.EqualValues(t, public, public1, "expected same public key")

	// attempt to extract the public key from the same sig but a wrong message

	wrongMessage := rnd32Bytes(t)
	public2, err := ExtractPublicKey(wrongMessage[:], sig)

	// we expect the extracted key to not be the same as the correct signer public key
	assert.NoError(t, err)
	if bytes.Compare(public, public2) == 0 {
		t.Errorf("expected different public keys")
	}
}

// Test Verify2 with a fixed message
func TestSignVerify2(t *testing.T) {
	var zero zeroReader
	public, private, _ := GenerateKey(zero)

	message := []byte("test message")

	// sign and verify a message using the public key created by GenerateKey()
	sig := Sign2(private, message)
	if !Verify2(public, message, sig) {
		t.Errorf("valid signature rejected")
	}

	// Verification of the signature on a wrong message should fail
	wrongMessage := []byte("wrong message")
	if Verify2(public, wrongMessage, sig) {
		t.Errorf("signature of different message accepted")
	}
}

// Test Verify2 with a random message
func TestSignVerify3(t *testing.T) {
	var zero zeroReader
	public, private, _ := GenerateKey(zero)

	message := rnd32Bytes(t)

	// sign and verify a message using the public key created by GenerateKey()
	sig := Sign2(private, message[:])
	if !Verify2(public, message[:], sig) {
		t.Errorf("valid signature rejected")
	}

	// Verification of the signature on a wrong message should fail
	wrongMessage := rnd32Bytes(t)
	if Verify2(public, wrongMessage[:], sig) {
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
	sig := Sign2(priv, message)
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
		Sign2(priv, message)
	}
}

func BenchmarkVerificationExt(b *testing.B) {
	var zero zeroReader
	pub, priv, err := GenerateKey(zero)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	signature := Sign2(priv, message)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify2(pub, message, signature)
	}
}

func rnd32Bytes(t *testing.T) *[32]byte {
	var d [32]byte
	n, err := rand.Read(d[:])
	assert.NoError(t, err, "no system entropy")
	assert.Equal(t, 32, n, "expected 32 bytes of entropy")
	return &d
}

func rnd32BytesBench(b *testing.B) *[32]byte {
	var d [32]byte
	n, err := rand.Read(d[:])
	assert.NoError(b, err, "no system entropy")
	assert.Equal(b, 32, n, "expected 32 bytes of entropy")
	return &d
}

