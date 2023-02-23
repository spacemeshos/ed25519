// Copyright 2019 Spacemesh Authors
// ed25519 extensions unit tests

package ed25519

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test with a fixed message
func TestPublicKeyExtraction(t *testing.T) {
	public, private, err := GenerateKey(nil)
	require.NoError(t, err)

	// sign the message
	message := []byte("test message")
	sig := Sign2(private, message)

	// extract public key from signature and the message
	public1, err := ExtractPublicKey(message, sig)
	require.NoError(t, err)

	// ensure extracted key is the same as public key created by GenerateKey()
	require.EqualValues(t, public, public1, "expected same public key")

	// attempt to extract the public key from the same sig but a wrong message
	wrongMessage := []byte("wrong message")
	public2, err := ExtractPublicKey(wrongMessage, sig)
	require.NoError(t, err)

	// we expect the extracted key to not be the same as the correct signer public key
	require.NotEqual(t, public, public2, "expected different public keys")
}

// Test with a random message
func TestPublicKeyExtraction1(t *testing.T) {
	public, private, err := GenerateKey(nil)
	require.NoError(t, err)

	// sign the message
	message := rnd32Bytes(t)
	sig := Sign2(private, message)

	// extract public key from signature and the message
	public1, err := ExtractPublicKey(message, sig)
	require.NoError(t, err)

	// ensure extracted key is the same as public key created by GenerateKey()
	require.EqualValues(t, public, public1, "expected same public key")

	// attempt to extract the public key from the same sig but a wrong message
	wrongMessage := rnd32Bytes(t)
	public2, err := ExtractPublicKey(wrongMessage, sig)
	require.NoError(t, err)

	// we expect the extracted key to not be the same as the correct signer public key
	require.NotEqual(t, public, public2, "expected different public keys")
}

// Test Verify2 with a fixed message
func TestSignVerify2(t *testing.T) {
	public, private, err := GenerateKey(nil)
	require.NoError(t, err)

	// sign and verify a message using the public key created by GenerateKey()
	message := []byte("test message")
	sig := Sign2(private, message)
	require.True(t, Verify2(public, message, sig), "valid signature rejected")

	// Verification of the signature on a wrong message should fail
	wrongMessage := []byte("wrong message")
	require.False(t, Verify2(public, wrongMessage, sig), "signature of different message accepted")
}

// Test Verify2 with a random message
func TestSignVerify2Random(t *testing.T) {
	public, private, err := GenerateKey(nil)
	require.NoError(t, err)

	// sign and verify a message using the public key created by GenerateKey()
	message := rnd32Bytes(t)
	sig := Sign2(private, message)
	require.True(t, Verify2(public, message, sig), "valid signature rejected")

	// Verification of the signature on a wrong message should fail
	wrongMessage := rnd32Bytes(t)
	require.False(t, Verify2(public, wrongMessage, sig), "signature of different message accepted")
}

func BenchmarkPublicKeyExtraction(b *testing.B) {
	_, priv, err := GenerateKey(nil)
	require.NoError(b, err)

	message := []byte("Hello, world!")
	sig := Sign2(priv, message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractPublicKey(message, sig)
	}
}

func BenchmarkSigningExt(b *testing.B) {
	_, priv, err := GenerateKey(nil)
	require.NoError(b, err)

	message := []byte("Hello, world!")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sign2(priv, message)
	}
}

func BenchmarkVerificationExt(b *testing.B) {
	pub, priv, err := GenerateKey(nil)
	require.NoError(b, err)

	message := []byte("Hello, world!")
	signature := Sign2(priv, message)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify2(pub, message, signature)
	}
}

func rnd32Bytes(t *testing.T) []byte {
	d := make([]byte, 32)
	n, err := rand.Read(d)
	require.NoError(t, err, "no system entropy")
	require.Equal(t, 32, n, "expected 32 bytes of entropy")
	return d
}
