// Copyright 2019 Spacemesh Authors
// ed25519 extensions

package ed25519

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"strconv"

	"github.com/spacemeshos/ed25519/internal/edwards25519"
)

// ExtractPublicKey extracts the signer's public key given a message and its signature.
// Note that signature must be created using Sign2() and NOT using Sign().
// It will panic if len(sig) is not SignatureSize.
func ExtractPublicKey(message, sig []byte) (PublicKey, error) {
	if l := len(sig); l != SignatureSize || sig[63]&224 != 0 {
		return nil, errors.New("ed25519: bad signature format")
	}

	h := sha512.New()
	h.Write(sig[:32])
	// we remove the public key from the hash
	//h.Write(privateKey[32:])
	h.Write(message)
	digest := make([]byte, 64)
	h.Sum(digest[:0])

	hReduced, err := new(edwards25519.Scalar).SetUniformBytes(digest)
	if err != nil {
		return nil, err
	}

	var hInv [32]byte
	edwards25519.InvertModL(&hInv, (*[32]byte)(hReduced.Bytes()))

	s, err := new(edwards25519.Scalar).SetCanonicalBytes(sig[32:])
	if err != nil {
		return nil, err
	}

	// var zero [32]byte
	oneBytes := make([]byte, 32)
	oneBytes[0] = 1
	one, err := new(edwards25519.Scalar).SetCanonicalBytes(oneBytes)
	if err != nil {
		return nil, err
	}

	// Extract R = sig[32:] as a point on the curve (and compute the inverse of R)
	R, err := new(edwards25519.Point).SetBytes(sig[:32])
	if err != nil {
		return nil, err
	}

	// The following lines make R -> -R
	R.Negate(R)

	A := new(edwards25519.Point)
	A.VarTimeDoubleScalarBaseMult(one, R, s)

	hInvScalar, err := new(edwards25519.Scalar).SetCanonicalBytes(hInv[:])
	if err != nil {
		return nil, err
	}

	EC_PK := new(edwards25519.Point).ScalarMult(hInvScalar, A)

	return EC_PK.Bytes(), nil
}

// NewDerivedKeyFromSeed calculates a private key from a 32 bytes random seed, an integer index and salt
func NewDerivedKeyFromSeed(seed []byte, index uint64, salt []byte) PrivateKey {
	if l := len(seed); l != SeedSize {
		panic("ed25519: bad seed length: " + strconv.Itoa(l))
	}

	digest := sha512.New()
	digest.Write(seed)
	digest.Write(salt)
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, index)
	digest.Write(buf)

	return NewKeyFromSeed(digest.Sum(nil)[:SeedSize])
}

// Sign2 signs the message with privateKey and returns a signature.
// The signature may be verified using Verify2(), if the signer's public key is known.
// The signature returned by this method can be used together with the message
// to extract the public key using ExtractPublicKey()
// It will panic if len(privateKey) is not PrivateKeySize.
func Sign2(privateKey PrivateKey, message []byte) []byte {

	// COMMENTS in the code refer to Algorithm 1 in https://eprint.iacr.org/2017/985.pdf

	if l := len(privateKey); l != PrivateKeySize {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}

	h := sha512.New()

	// privateKey follows from NewKeyFromSeed();
	// it seems that the first 32 bytes is 'a' as in line 2 in "Algorithm 1",
	// and the last 32 bytes is the (encoding) of the public key (elliptic curve point,
	// as in line 4 in "Algorithm 1").
	h.Write(privateKey[:32])
	digest1 := make([]byte, 64)
	expandedSecretKey := make([]byte, 32)
	h.Sum(digest1[:0])
	copy(expandedSecretKey, digest1)
	expandedSecretKey[0] &= 248
	expandedSecretKey[31] &= 63
	expandedSecretKey[31] |= 64 // this is the final value for 'a'

	h.Reset()
	// This seems to be 'b' as in line 3 in "Algorithm 1",
	// however it seems that it is obtained by hashing of (non-final 'a'),
	// rather by the way it is described in "Algorithm 1"
	h.Write(digest1[32:])
	h.Write(message)

	// line 5 in "Algorithm 1": creates r
	messageDigest := make([]byte, 64)
	h.Sum(messageDigest[:0])

	// looks like reduction mod l, this is the final r
	messageDigestReduced, err := new(edwards25519.Scalar).SetUniformBytes(messageDigest)
	if err != nil {
		panic(err)
	}

	// line 6 in "Algorithm 1": creates R
	R := new(edwards25519.Point).ScalarBaseMult(messageDigestReduced)

	encodedR := R.Bytes()

	h.Reset()
	h.Write(encodedR[:])
	// we remove the public key from the hash
	//h.Write(privateKey[32:])

	// line 7: creates h
	h.Write(message)
	hramDigest := make([]byte, 64)
	h.Sum(hramDigest[:0])

	// this is the final h
	hramDigestReduced, err := new(edwards25519.Scalar).SetUniformBytes(hramDigest)
	if err != nil {
		panic(err)
	}

	priv, err := new(edwards25519.Scalar).SetBytesWithClamping(expandedSecretKey)
	if err != nil {
		panic(err)
	}

	// line 8: s = h*a + r
	s := new(edwards25519.Scalar).MultiplyAdd(hramDigestReduced, priv, messageDigestReduced)

	signature := make([]byte, SignatureSize)
	copy(signature, encodedR)
	copy(signature[32:], s.Bytes())
	return signature
}

// Verify2 verifies a signature created with Sign2(),
// assuming the verifier possesses the public key.
func Verify2(publicKey PublicKey, message, sig []byte) bool {
	if l := len(publicKey); l != PublicKeySize {
		panic("ed25519: bad public key length: " + strconv.Itoa(l))
	}

	if len(sig) != SignatureSize || sig[63]&224 != 0 {
		return false
	}

	A, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		return false
	}
	A.Negate(A)

	h := sha512.New()
	h.Write(sig[:32])
	// we remove the public key from the hash
	// h.Write(publicKey[:])
	h.Write(message)
	digest := make([]byte, 64)
	h.Sum(digest[:0])

	hReduced, err := new(edwards25519.Scalar).SetUniformBytes(digest)
	if err != nil {
		return false
	}

	s := make([]byte, 32)
	copy(s, sig[32:])

	priv, err := new(edwards25519.Scalar).SetCanonicalBytes(s)
	if err != nil {
		panic(err)
	}

	R := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(hReduced, A, priv)
	return bytes.Equal(sig[:32], R.Bytes())
}
