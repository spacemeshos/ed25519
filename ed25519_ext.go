package ed25519

// Copyright 2019 Spacemesh Authors
// ed25519 extensions

import (
	"crypto/sha512"
	"errors"
	"github.com/spacemeshos/ed25519/internal/edwards25519"
	"strconv"
)

// ExtractPublicKey extracts the signer's public key given a message and its signature.
// It will panic if len(sig) is not SignatureSize.
// NOTE: the current code may try to "divide by 0", in case 123 is divisible by 8. Needs to be fixed.
func ExtractPublicKey(message, sig []byte) (PublicKey, error) {

	if l := len(sig); l != SignatureSize || sig[63]&224 != 0 {
		return nil, errors.New("ed25519: bad signature format")
	}

	h := sha512.New()
	h.Write(sig[:32])
	h.Write(message)
	var digest [64]byte
	h.Sum(digest[:0])

	var hReduced [32]byte
	edwards25519.ScReduce(&hReduced, &digest)

	var hInv [32]byte
	edwards25519.InvertModL(&hInv, &hReduced)

	// @barak - do we need this due to the ScReduce above?
	// var hInVReduced [32]byte
	// edwards25519.ScReduce(&hInVReduced, &hInv)

	var s [32]byte
	if l := copy(s[:], sig[32:]); l != PublicKeySize {
		return nil, errors.New("memory copy failed")
	}

	// https://tools.ietf.org/html/rfc8032#section-5.1.7 requires that s be in
	// the range [0, order) in order to prevent signature malleability.
	if !edwards25519.ScMinimal(&s) {
		return nil, errors.New("invalid signature")
	}

	var zero [32]byte
	var one [32]byte
	one[0] = byte(1)

	// Extract R = sig[32:] as a point on the curve (and compute the inverse of R)
	var R edwards25519.ExtendedGroupElement
	if ok := R.FromBytes(&s); !ok {
		return nil, errors.New("failed to create extended group element from s")
	}

	// First we try without negation of R
	var A edwards25519.ProjectiveGroupElement
	edwards25519.GeDoubleScalarMultVartime(&A, &one, &R, &s)

	// We need to convert A from projective to extended group element - I cannot find this function defined
	// ToBytes takes projective
	// FromBytes return extended
	// Let's try....  [in general there should be a smarter way of doing this, so remember to look into this]
	var buff [32]byte
	A.ToBytes(&buff)
	var A2 edwards25519.ExtendedGroupElement
	if ok := A2.FromBytes(&buff); !ok {
		return nil, errors.New("failed to create an extended group element A2 from A")
	}

	var EC_PK edwards25519.ProjectiveGroupElement
	edwards25519.GeDoubleScalarMultVartime(&EC_PK, &hInv, &A2, &zero)

	var pubKey [PublicKeySize]byte

	// EC_PK is supposed to be the public key as an elliptic curve point, we apply ToBytes
	EC_PK.ToBytes(&pubKey)
	return pubKey[:], nil
}

// SignExt signs the message with privateKey and returns a signature.
// The signature may be verified using Verify(), if the signer's public key is known.
// The signature returned by this method can be used together with the message
// to extract the public key using ExtractPublicKey()
// It will panic if len(privateKey) is not PrivateKeySize.
// COMMENTS in the code refer to Algorithm 1 in https://eprint.iacr.org/2017/985.pdf
func SignExt(privateKey PrivateKey, message []byte) []byte {

	if l := len(privateKey); l != PrivateKeySize {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}

	h := sha512.New()

	// privateKey follows from NewKeyFromSeed();
	// it seems that the first 32 bytes is 'a' as in line 2 in "Algorithm 1",
	// and the last 32 bytes is the (encoding) of the public key (elliptic curve point,
	// as in line 4 in "Algorithm 1").
	h.Write(privateKey[:32])

	var digest1, messageDigest, hramDigest [64]byte
	var expandedSecretKey [32]byte
	h.Sum(digest1[:0])
	copy(expandedSecretKey[:], digest1[:])
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
	h.Sum(messageDigest[:0])

	// @barak - do you mind if we'll always have the comments in a new line
	// above the code they refer to? It is hard to read them when they are in the same
	// line after the code like in the lines below...
	var messageDigestReduced [32]byte
	edwards25519.ScReduce(&messageDigestReduced, &messageDigest) // looks like reduction mod l, this is the final r

	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &messageDigestReduced) // line 6 in "Algorithm 1": creates R

	var encodedR [32]byte
	R.ToBytes(&encodedR)

	h.Reset()
	h.Write(encodedR[:])

	// we remove the public key from the hash
	//h.Write(privateKey[32:])

	// line 7: creates h
	h.Write(message)
	h.Sum(hramDigest[:0])

	var hramDigestReduced [32]byte

	// this is the final h
	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)

	// line 8: s = h*a + r
	var s [32]byte
	edwards25519.ScMulAdd(&s, &hramDigestReduced, &expandedSecretKey, &messageDigestReduced)

	signature := make([]byte, SignatureSize)
	copy(signature[:], encodedR[:])
	copy(signature[32:], s[:])

	return signature
}
