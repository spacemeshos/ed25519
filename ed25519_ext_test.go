// Copyright 2019 Spacemesh Authors
// ed25519 extensions unit tests

package ed25519

import (
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test with a fixed message
func TestPublicKeyExtraction(t *testing.T) {
	public, private, err := GenerateKey(zeroReader{})
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
	public, private, err := GenerateKey(zeroReader{})
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
	public, private, err := GenerateKey(zeroReader{})
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
	public, private, err := GenerateKey(zeroReader{})
	require.NoError(t, err)

	// sign and verify a message using the public key created by GenerateKey()
	message := rnd32Bytes(t)
	sig := Sign2(private, message)
	require.True(t, Verify2(public, message, sig), "valid signature rejected")

	// Verification of the signature on a wrong message should fail
	wrongMessage := rnd32Bytes(t)
	require.False(t, Verify2(public, wrongMessage, sig), "signature of different message accepted")
}

func TestDerive(t *testing.T) {
	seed := rnd32Bytes(t)
	var idx uint64 = 5
	salt := []byte("Spacemesh rocks")
	NewDerivedKeyFromSeed(seed[:], idx, salt)
}

func TestDerive1(t *testing.T) {
	const expectedEncodedKey = "b6e1caa7ed8fb8b517dbbd5a49f7c9e76f33f0dd74100396207b640479d6fade2b0f080a354fd3c981630efe75bcbc5f4134895b749364f25badeae5a687950c"
	const s = "8d03a58456bb1b45f696032444b09d476fa5406f998ed0a50e694ee8a40cfb09"
	seed, err := hex.DecodeString(s)
	require.NoError(t, err)

	privateKey1 := NewDerivedKeyFromSeed(seed[:], 5, []byte("Spacemesh rocks"))
	require.Equal(t, expectedEncodedKey, hex.EncodeToString(privateKey1), "Unexpected key")
}

func BenchmarkPublicKeyExtraction(b *testing.B) {
	_, priv, err := GenerateKey(zeroReader{})
	require.NoError(b, err)

	message := []byte("Hello, world!")
	sig := Sign2(priv, message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractPublicKey(message, sig)
	}
}

func Test_PythonReference(t *testing.T) {
	file, err := os.Open(filepath.Join("reference", "testdata.csv"))
	require.NoError(t, err)
	defer file.Close()

	// read csv line by line
	reader := csv.NewReader(file)
	reader.Read() // skip header

	for i := 0; ; i++ {
		line, err := reader.Read()
		if err != nil {
			require.Equal(t, io.EOF, err)
			require.Equal(t, 1000, i, "expected 1000 test vectors")
			break
		}

		// parse line
		pk, err := hex.DecodeString(line[0])
		require.NoError(t, err)
		seed, err := hex.DecodeString(line[1])
		require.NoError(t, err)
		msg, err := hex.DecodeString(line[2])
		require.NoError(t, err)
		sig, err := hex.DecodeString(line[3])
		require.NoError(t, err)

		// derive key from seed
		key := NewKeyFromSeed(seed)
		require.EqualValues(t, pk, key.Public(), "public key mismatch at record %d: %v", i, line)
		require.IsType(t, PublicKey{}, key.Public(), "key type mismatch at record %d: %v", i, line)

		// sign message
		signature := Sign2(key, msg)
		require.Equal(t, sig, signature, "signature mismatch at record %d: %v", i, line)

		// verify signature
		valid := Verify2(key.Public().(PublicKey), msg, signature)
		require.True(t, valid, "signature verification failed at record %d: %v", i, line)

		// extract public key from signature
		public, err := ExtractPublicKey(msg, signature)
		require.NoError(t, err)
		require.EqualValues(t, pk, public, "public key mismatch at record %d: %v", i, line)
	}
}

func Fuzz_ExtractPublicKey(f *testing.F) {
	f.Add([]byte("Hello, world!"), int64(0))
	f.Fuzz(func(t *testing.T, msg []byte, rndSeed int64) {
		src := rand.New(rand.NewSource(rndSeed))
		seed := make([]byte, 32)

		// generate random seed
		_, err := src.Read(seed)
		require.NoError(t, err, "failed to read random seed")

		// derive key from seed and sign
		key := NewKeyFromSeed(seed)
		sig, err := pySign(msg, key.Seed())
		require.NoError(t, err)

		// extract public key from signature
		pub, err := ExtractPublicKey(msg, sig)
		require.NoError(t, err)
		require.EqualValues(t, key.Public(), pub)
	})
}

func Fuzz_Sign2(f *testing.F) {
	f.Add([]byte("Hello, world!"), int64(0))
	f.Fuzz(func(t *testing.T, msg []byte, rndSeed int64) {
		src := rand.New(rand.NewSource(rndSeed))
		seed := make([]byte, 32)

		// generate random seed
		_, err := src.Read(seed)
		require.NoError(t, err, "failed to read random seed")

		// derive key from seed and sign
		key := NewKeyFromSeed(seed)
		sig := Sign2(key, msg)

		// extract public key from signature
		pub, err := pyExtract(msg, sig)
		require.NoError(t, err)
		require.EqualValues(t, key.Public(), pub)
	})
}

func BenchmarkSigningExt(b *testing.B) {
	_, priv, err := GenerateKey(zeroReader{})
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

func pySign(msg []byte, seed PrivateKey) ([]byte, error) {
	pwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	py := fmt.Sprintf("'import ed25519_ref; ed25519_ref.go_sign2(\"%s\", \"%s\")'", hex.EncodeToString(msg), hex.EncodeToString(seed))
	cmd := exec.Command("bash", "-c", "python3 -c "+py)
	cmd.Dir = filepath.Join(pwd, "reference")

	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("python command failed: %w", err)
	}

	return hex.DecodeString(strings.TrimSpace(string(out)))
}

func pyExtract(msg []byte, sig []byte) ([]byte, error) {
	pwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	py := fmt.Sprintf("'import ed25519_ref; ed25519_ref.go_extract_pk(\"%s\", \"%s\")'", hex.EncodeToString(sig), hex.EncodeToString(msg))
	cmd := exec.Command("bash", "-c", "python3 -c "+py)
	cmd.Dir = filepath.Join(pwd, "reference")

	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("python command failed: %w", err)
	}

	return hex.DecodeString(strings.TrimSpace(string(out)))
}
