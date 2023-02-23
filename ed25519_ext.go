// Copyright 2019 Spacemesh Authors
// ed25519 extensions

package ed25519

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"strconv"

	"github.com/spacemeshos/ed25519/internal/edwards25519"
)

// ExtractPublicKey extracts the signer's public key given a message and its signature.
// Note that signature must be created using Sign2() and NOT using Sign().
// It will panic if len(sig) is not SignatureSize.
func ExtractPublicKey(message, sig []byte) (PublicKey, error) {
	publicKey := make([]byte, PublicKeySize)
	err := extractPublicKey(publicKey, message, sig)
	return publicKey, err
}

func extractPublicKey(publicKey, message, sig []byte) error {
	if l := len(sig); l != SignatureSize || sig[63]&224 != 0 {
		return errors.New("ed25519: bad signature format")
	}

	kh := sha512.New()
	kh.Write(sig[:32])
	// we remove the public key from the hash
	// kh.Write(privateKey[32:])
	kh.Write(message)
	hramDigest := make([]byte, 0, sha512.Size)
	hramDigest = kh.Sum(hramDigest)
	k, err := edwards25519.NewScalar().SetUniformBytes(hramDigest)
	if err != nil {
		return err
	}

	S, err := edwards25519.NewScalar().SetCanonicalBytes(sig[32:])
	if err != nil {
		return err
	}

	// Extract R = sig[32:] as a point on the curve (and compute the inverse of R)
	R, err := (&edwards25519.Point{}).SetBytes(sig[:32])
	if err != nil {
		return err
	}

	// [S]B = R + [k]A --> A = (-R + [S]B)/[k]
	minusR := (&edwards25519.Point{}).Negate(R)
	AK := (&edwards25519.Point{}).Add(minusR, (&edwards25519.Point{}).ScalarBaseMult(S))

	// Compute the inverse of k
	kInv := edwards25519.NewScalar().InvertModL(k)

	A := (&edwards25519.Point{}).ScalarMult(kInv, AK)
	copy(publicKey, A.Bytes())
	return nil
}

// Sign2 signs the message with privateKey and returns a signature.
// The signature may be verified using Verify2(), if the signer's public key is known.
// The signature returned by this method can be used together with the message
// to extract the public key using ExtractPublicKey().
// It will panic if len(privateKey) is not PrivateKeySize.
func Sign2(privateKey PrivateKey, message []byte) []byte {
	// Outline the function body so that the returned signature can be
	// stack-allocated.
	signature := make([]byte, SignatureSize)
	sign(signature, privateKey, message)
	return signature
}

func sign(signature, privateKey, message []byte) {
	if l := len(privateKey); l != PrivateKeySize {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}
	seed := privateKey[:SeedSize]

	h := sha512.Sum512(seed)
	s, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}
	prefix := h[32:]

	mh := sha512.New()
	mh.Write(prefix)
	mh.Write(message)
	messageDigest := make([]byte, 0, sha512.Size)
	messageDigest = mh.Sum(messageDigest)
	r, err := edwards25519.NewScalar().SetUniformBytes(messageDigest)
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	R := (&edwards25519.Point{}).ScalarBaseMult(r)

	kh := sha512.New()
	kh.Write(R.Bytes())
	// we remove the public key from the hash
	// kh.Write(publicKey)
	kh.Write(message)
	hramDigest := make([]byte, 0, sha512.Size)
	hramDigest = kh.Sum(hramDigest)
	k, err := edwards25519.NewScalar().SetUniformBytes(hramDigest)
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	S := edwards25519.NewScalar().MultiplyAdd(k, s, r)

	copy(signature[:32], R.Bytes())
	copy(signature[32:], S.Bytes())
}

// Verify2 reports whether sig is a valid signature of message by publicKey
// created with Sign2(). It will panic if len(publicKey) is not PublicKeySize.
func Verify2(publicKey PublicKey, message, sig []byte) bool {
	if l := len(publicKey); l != PublicKeySize {
		panic("ed25519: bad public key length: " + strconv.Itoa(l))
	}

	if len(sig) != SignatureSize || sig[63]&224 != 0 {
		return false
	}

	A, err := (&edwards25519.Point{}).SetBytes(publicKey)
	if err != nil {
		return false
	}

	kh := sha512.New()
	kh.Write(sig[:32])
	// we remove the public key from the hash
	// kh.Write(publicKey)
	kh.Write(message)
	hramDigest := make([]byte, 0, sha512.Size)
	hramDigest = kh.Sum(hramDigest)
	k, err := edwards25519.NewScalar().SetUniformBytes(hramDigest)
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	S, err := edwards25519.NewScalar().SetCanonicalBytes(sig[32:])
	if err != nil {
		return false
	}

	// [S]B = R + [k]A --> [k](-A) + [S]B = R
	minusA := (&edwards25519.Point{}).Negate(A)
	R := (&edwards25519.Point{}).VarTimeDoubleScalarBaseMult(k, minusA, S)

	return bytes.Equal(sig[:32], R.Bytes())
}
