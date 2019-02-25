// Copyright 2019 Spacemesh Authors
// ed25519 extensions

package ed25519

import (
	"crypto/sha512"
	"github.com/spacemeshos/ed25519/internal/edwards25519"
	"strconv"
)

// ExtractPublicKey extracts the public key of the private key which signed the message.
// It will panic if len(sig) is not SignatureSize.
func ExtractPublicKey(message, sig []byte) PublicKey {

	if l := len(sig); l != SignatureSize {
		panic("ed25519: bad signature length: " + strconv.Itoa(l))
	}

	// todo: implement me

	pubKey := make([]byte, PublicKeySize)
	return pubKey
}

// SignExt signs the message with privateKey and returns a signature that should
// be verified using Verify().
// The signature returned by this method can be used together with the message
// to extract the public key using ExtractPublicKey()
// It will panic if len(privateKey) is not PrivateKeySize.
func SignExt(privateKey PrivateKey, message []byte) []byte {
	if l := len(privateKey); l != PrivateKeySize {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}

	// todo: modify me with the updated sign algo from research

	h := sha512.New()
	h.Write(privateKey[:32])

	var digest1, messageDigest, hramDigest [64]byte
	var expandedSecretKey [32]byte
	h.Sum(digest1[:0])
	copy(expandedSecretKey[:], digest1[:])
	expandedSecretKey[0] &= 248
	expandedSecretKey[31] &= 63
	expandedSecretKey[31] |= 64

	h.Reset()
	h.Write(digest1[32:])
	h.Write(message)
	h.Sum(messageDigest[:0])

	var messageDigestReduced [32]byte
	edwards25519.ScReduce(&messageDigestReduced, &messageDigest)
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &messageDigestReduced)

	var encodedR [32]byte
	R.ToBytes(&encodedR)

	h.Reset()
	h.Write(encodedR[:])
	h.Write(privateKey[32:])
	h.Write(message)
	h.Sum(hramDigest[:0])
	var hramDigestReduced [32]byte
	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)

	var s [32]byte
	edwards25519.ScMulAdd(&s, &hramDigestReduced, &expandedSecretKey, &messageDigestReduced)

	signature := make([]byte, SignatureSize)
	copy(signature[:], encodedR[:])
	copy(signature[32:], s[:])

	return signature
}
