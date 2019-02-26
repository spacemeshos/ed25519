// Copyright 2019 Spacemesh Authors
// ed25519 extensions

package ed25519

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"github.com/spacemeshos/ed25519/internal/edwards25519"
	"golang.org/x/crypto/curve25519"
	"math"
	"strconv"
)

var L = uint64(math.Pow(2,252)) + 27742317777372353535851937790883648493


func invertModL(x *[32]byte, r *[32]byte) {
	v := binary.LittleEndian.Uint64(x[:])

}

// ExtractPublicKey extracts the signer's public key given a message and its signature.
// It will panic if len(sig) is not SignatureSize.
// NOTE: the current code may try to "divide by 0", in case 123 is divisible by 8. Needs to be fixed.
func ExtractPublicKey(message, sig []byte) (PublicKey, error) {

	if l := len(sig); l != SignatureSize || sig[63]&224 != 0 {
		return nil, errors.New("ed25519: bad signature format")
	}

	h := sha512.New()
	h.Write(sig[:32])
	//h.Write(publicKey[:])
	h.Write(message)
	var digest [64]byte
	h.Sum(digest[:0])

	var hReduced [32]byte
	edwards25519.ScReduce(&hReduced, &digest)

	var hInv [32]byte
	// todo: WE NEED INVERSION MOD L
	// where l = 2^252 + 27742317777372353535851937790883648493
	// invert(x) := x^(l-2) % l
	// edwards25519.InvertModL(&hInv, &hReduced)

	// var hInVReduced [32]byte
	// edwards25519.ScReduce(&hInVReduced, &hInv)
	var R edwards25519.ProjectiveGroupElement
	var s [32]byte
	copy(s[:], sig[32:])

	// https://tools.ietf.org/html/rfc8032#section-5.1.7 requires that s be in
	// the range [0, order) in order to prevent signature malleability.
	if !edwards25519.ScMinimal(&s) {
		return nil, errors.New("invalid signature")
	}

	var buff [32]byte
	buff[0] = byte(1)

	// NEXT: extract R as a point on the curve and compute the inverse of R, sig[32:] --- I'm stuck with that
	var SB edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&SB, &s)

	// First we try without negation ; 1 means the number one?
	edwards25519.GeDoubleScalarMultVartime(&R, &buff, &sig[:32], &s)
	var EC_PK [32]byte

	// Doc of curve25519 says point are given by x-coord.
	// https://github.com/golang/crypto/blob/master/curve25519/doc.go
	curve25519.ScalarMult(&EC_PK, &hInv, &R)

	pubKey := make([]byte, PublicKeySize)

	// todo: EC_PK is supposed to be the (x-coordinate of the) public key as an elliptic curve point
	// I think that we need to obtain the full point, so we can apply ToBytes below
	//EC_PK.ToBytes(&pubKey)
	return pubKey, nil
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


func InvertModL(out, z *FieldElement) {			// I am not sure  what type, if any, we should declare for the input z
	var t0, t1, t2, t3, t4, t5, tz FieldElement	// This function is not optimized
	var i int
	var zero [32]byte
	buff[0] = byte(0)
	
	copy(t1, z)					// 2^0  I'm actually not using it
	edwards25519.ScMulAdd(&t0, &z, &z, &zero)	// 2^1
	edwards25519.ScMulAdd(&t2, &t0, &z, &zero)	// 2^1 + 2^0
	for i = 1; i < 2; i++ { 			// 2^2
		edwards25519.ScMulAdd(&t0, &t0, &t0, &zero)
	}
	edwards25519.ScMulAdd(&t3, &t0, &t2, &zero)	// 2^2 + 2^1 + 2^0
	for i = 1; i < 2; i++ { 			// 2^3
		edwards25519.ScMulAdd(&t0, &t0, &t0, &zero)
	}
	edwards25519.ScMulAdd(&t4, &t0, &t3, &zero)	// 2^3 + 2^2 + 2^1 + 2^0
	for i = 1; i < 2; i++ { 			// 2^4
		edwards25519.ScMulAdd(&t0, &t0, &t0, &zero)
	}
	edwards25519.ScMulAdd(&t5, &t0, &t4, &zero)	// 2^4 + 2^3 + 2^2 + 2^1 + 2^0
	
	copy(tz, z)					// tz = 2^0
	copy(t0, z)
	for i = 1; i < 3; i++ { 			// 2^2
		edwards25519.ScMulAdd(&t0, &t0, &t0, &zero)
	}
	edwards25519.ScMulAdd(&tz, &t0, &tz, &zero)	// tz = 2^2 + 2^0
	for i = 1; i < 6; i++ { 			// 2^6 + 2^5
		edwards25519.ScMulAdd(&t0, &t2, &t2, &zero)
	}
	edwards25519.ScMulAdd(&tz, &t0, &tz, &zero)	// tz = 2^6 + 2^5 + 2^2 + 2^0
	for i = 1; i < 9; i++ { 			// 2^11 + 2^10 + 2^9 + 2^8
		edwards25519.ScMulAdd(&t0, &t4, &t4, &zero)
	}
	edwards25519.ScMulAdd(&tz, &t0, &tz, &zero)	// tz = 2^11 + 2^10 + 2^9 + 2^8 + 2^6 + 2^5 + 2^2 + 2^0
	
		// if you input z=2, we get 2^(2048 + 1024 + 512 + 256 + 64 + 32 + 4 + 1) = 2^3941 mod l
		//                         = 4390054613844824731020805728162554857567810442668694040812122513881566113753
	
	copy(out, tz)
	
	
	
	
	//for i = 1; i < 252; i++ { 			// 2^252
	//	edwards25519.ScMulAdd(&t0, &t0, &t0, &zero)
	//}
	
	
	
	
}
