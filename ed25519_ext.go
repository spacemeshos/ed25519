// Copyright 2019 Spacemesh Authors
// ed25519 extensions

package ed25519

import (
	"crypto/sha512"
	"github.com/spacemeshos/ed25519/internal/edwards25519"
	"strconv"
)

// ExtractPublicKey extracts the signer's public key given a message and its signature.
// It will panic if len(sig) is not SignatureSize.
func ExtractPublicKey(message, sig []byte) PublicKey {

	if l := len(sig); l != SignatureSize {
		panic("ed25519: bad signature length: " + strconv.Itoa(l))
	}

	pubKey := make([]byte, PublicKeySize)
	return pubKey
}

// SignExt signs the message with privateKey and returns a signature.
// The siganture may be verified using Verify(), if the signer's public key is known.
// The signature returned by this method can be used together with the message
// to extract the public key using ExtractPublicKey()
// It will panic if len(privateKey) is not PrivateKeySize.
// COMMENTS in the code refer to Algorithm 1 in https://eprint.iacr.org/2017/985.pdf
func SignExt(privateKey PrivateKey, message []byte) []byte {
	if l := len(privateKey); l != PrivateKeySize {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}

	h := sha512.New()
	h.Write(privateKey[:32])						// privateKey follows from NewKeyFromSeed(); it seems that the first 32 bytes is 'a' as in line 2 in "Algorithm 1", and the last 32 bytes is the (encoding) of the public key (elliptic curve point, as in line 4 in "Algorithm 1").

	var digest1, messageDigest, hramDigest [64]byte
	var expandedSecretKey [32]byte
	h.Sum(digest1[:0])
	copy(expandedSecretKey[:], digest1[:])
	expandedSecretKey[0] &= 248
	expandedSecretKey[31] &= 63
	expandedSecretKey[31] |= 64						// this is the final value for 'a'

	h.Reset()
	h.Write(digest1[32:])							// this seems to be 'b' as in line 3 in "Algorithm 1", however it seems that it is obtained by hashing of (non-final 'a'), rather by the way it is described in "Algorithm 1"
	h.Write(message)
	h.Sum(messageDigest[:0])						// line 5 in "Algorithm 1": creates r

	var messageDigestReduced [32]byte
	edwards25519.ScReduce(&messageDigestReduced, &messageDigest)		// looks like reduction mod l, this is the final r
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &messageDigestReduced)		// line 6 in "Algorithm 1": creates R

	var encodedR [32]byte
	R.ToBytes(&encodedR)

	h.Reset()
	h.Write(encodedR[:])
	//h.Write(privateKey[32:])						// we remove the public key from the hash
	h.Write(message)
	h.Sum(hramDigest[:0])							// line 7: creates h
	var hramDigestReduced [32]byte
	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)			// this is the final h

	var s [32]byte
	edwards25519.ScMulAdd(&s, &hramDigestReduced, &expandedSecretKey, &messageDigestReduced)	// line 8: s = h*a + r

	signature := make([]byte, SignatureSize)
	copy(signature[:], encodedR[:])
	copy(signature[32:], s[:])

	return signature
}
