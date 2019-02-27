// Copyright 2019 Spacemesh Authors
// ed25519 extensions

package ed25519

import (
	"crypto/sha512"
	"errors"
	"github.com/spacemeshos/ed25519/internal/edwards25519"
	"strconv"
)

// ExtractPublicKey extracts the signer's public key given a message and its signature.
// It will panic if len(sig) is not SignatureSize.
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
	InvertModL(&hInv, &hReduced)

	// var hInVReduced [32]byte
	// edwards25519.ScReduce(&hInVReduced, &hInv)
	// var R edwards25519.ProjectiveGroupElement
	var s [32]byte
	copy(s[:], sig[32:])

	// https://tools.ietf.org/html/rfc8032#section-5.1.7 requires that s be in
	// the range [0, order) in order to prevent signature malleability.
	if !edwards25519.ScMinimal(&s) {
		return nil, errors.New("invalid signature")
	}

	var one [32]byte
	one[0] = byte(1)

	// NEXT: extract R as a point on the curve and compute the inverse of R, sig[32:] --- I'm stuck with that
	//var SB edwards25519.ExtendedGroupElement
	//edwards25519.GeScalarMultBase(&SB, &s)    // probably not needed -- we do this operation below

	// First we try without negation
	// edwards25519.GeDoubleScalarMultVartime(&R, &one, &sig[:32], &s)
	// var EC_PK [32]byte
	// var zero [32]byte
	// edwards25519.GeDoubleScalarMultVartime(&EC_PK, &hInv, &R, &zero)

	pubKey := make([]byte, PublicKeySize)

	// EC_PK is supposed to be the public key as an elliptic curve point
	// THIS IS OLD COMMENT (unclear at the moment): I think that we need to obtain the full point, so we can apply ToBytes below
	// EC_PK.ToBytes(&pubKey)
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

func SquareModL(out, z *[32]byte) {
	var zero [32]byte
	edwards25519.ScMulAdd(out, z, z, &zero)
}

func MultModL(out, z *[32]byte, w *[32]byte) {
	var zero [32]byte
	edwards25519.ScMulAdd(out, z, w, &zero)
}

func InvertModL(out, z *[32]byte) {

	// This function is not optimized

	var t0, t1, t2, t3, t4, t5, tz, zero [32]byte

	copy(t1[:], z[:])        // 2^0
	SquareModL(&t0, z)       // 2^1
	MultModL(&t2, &t0, z)    // 2^1 + 2^0
	for i := 1; i < 2; i++ { // 2^2
		SquareModL(&t0, &t0)
	}
	MultModL(&t3, &t0, &t2)  // 2^2 + 2^1 + 2^0
	for i := 1; i < 2; i++ { // 2^3
		SquareModL(&t0, &t0)
	}
	MultModL(&t4, &t0, &t3)  // 2^3 + 2^2 + 2^1 + 2^0
	for i := 1; i < 2; i++ { // 2^4
		SquareModL(&t0, &t0)
	}
	MultModL(&t5, &t0, &t4) // 2^4 + 2^3 + 2^2 + 2^1 + 2^0

	copy(tz[:], z[:]) // tz = 2^0
	copy(t0[:], z[:])

	for i := 1; i < 3; i++ { // 2^2
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 2^2 + 2^0
	copy(t0[:], t2[:])
	for i := 1; i < 6; i++ { // 2^6 + 2^5
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 2^6 + 2^5 + 2^2 + 2^0
	copy(t0[:], t4[:])
	for i := 1; i < 9; i++ { // 2^11 + 2^10 + 2^9 + 2^8
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 2^11 + 2^10 + 2^9 + 2^8 + 2^6 + 2^5 + 2^2 + 2^0
	copy(t0[:], t5[:])
	for i := 1; i < 14; i++ { // 2^17 + 2^16 + 2^15 + 2^14 + 2^13
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 17..13, 11..8, 6,5,2,0
	copy(t0[:], t3[:])
	for i := 1; i < 21; i++ { // 2^22 + 2^21 + 2^20
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 22..20, 17..13, 11..8, 6,5,2,0
	copy(t0[:], t4[:])
	for i := 1; i < 25; i++ { // 2^27 + 2^26 + 2^25 + 2^24
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 27..24, 22..20, 17..13, 11..8, 6,5,2,0
	copy(t0[:], t1[:])
	for i := 1; i < 30; i++ { // 2^29
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 29,27..24, 22..20, 17..13, 11..8, 6,5,2,0
	copy(t0[:], t1[:])
	for i := 1; i < 32; i++ { // 2^31
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 31,29,27..24, 22..20, 17..13, 11..8, 6,5,2,0
	copy(t0[:], t1[:])
	for i := 1; i < 36; i++ { // 2^35
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 35,31,29,27..24, 22..20, 17..13, 11..8, 6,5,2,0
	copy(t0[:], t4[:])
	for i := 1; i < 38; i++ { // 2^40 + 2^39 + 2^38 + 2^37
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 40..37, 35,31,29,27..24, 22..20, 17..13, 11..8, 6,5,2,0
	copy(t0[:], t4[:])
	for i := 1; i < 43; i++ { // 2^45 + 2^44 + 2^43 + 2^42
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 45..42, 40..37, 35,31,29,27..24, 22..20, 17..13, 11..8, 6,5,2,0
	copy(t0[:], t4[:])
	for i := 1; i < 43; i++ { // 2^45 + 2^44 + 2^43 + 2^42
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 45..42, 40..37, 35,31,29,27..24, 22..20, 17..13, 11..8, 6,5,2,0
	copy(t0[:], t3[:])
	for i := 1; i < 49; i++ { // 2^50 + 2^49 + 2^48
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 50..48, 45..42, 40..37, 35,31,29,27..24, 22..20, 17..13, 11..8, 6,5,2,0
	copy(t0[:], t2[:])
	for i := 1; i < 54; i++ { // 2^54 + 2^53
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 54,53, **50.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 57; i++ { // 2^56
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 56,54,53, **50.....0**
	copy(t0[:], t2[:])
	for i := 1; i < 59; i++ { // 2^59 + 2^58
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 59,58,56,54,53, **50.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 63; i++ { // 2^62
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 62,59,58,56,54,53, **50.....0**
	copy(t0[:], t2[:])
	for i := 1; i < 65; i++ { // 2^65 + 2^64
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 65,64,62,59,58,56,54,53, **50.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 73; i++ { // 2^72
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 72,65,64,62,59,58,56,54,53, **50.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 76; i++ { // 2^75
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 75,72,65,64,62,59,58,56,54,53, **50.....0**
	copy(t0[:], t2[:])
	for i := 1; i < 79; i++ { // 2^79 + 2^78
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 79,78,75,72,65,64,62,59,58,56,54,53, **50.....0**
	copy(t0[:], t2[:])
	for i := 1; i < 84; i++ { // 2^84 + 2^83
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 84,83,79,78,75,72,65,64,62,59,58,56,54,53, **50.....0**
	copy(t0[:], t2[:])
	for i := 1; i < 89; i++ { // 2^89 + 2^88
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 89,88,84,83,79,78,75,72,65,64,62,59,58,56,54,53, **50.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 92; i++ { // 2^91
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 91,89,88,84,83,79,78,75,72,65,64,62,59,58,56,54,53, **50.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 95; i++ { // 2^94
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 94,91,89,88,84,83,79,78,75,72,65,64,62,59,58,56,54,53, **50.....0**
	copy(t0[:], t3[:])
	for i := 1; i < 97; i++ { // 2^98 + 2^97 + 2^96
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 98..96, 94,91,89,88,84,83,79,78,75,72,65,64,62,59,58,56,54,53, **50.....0**
	copy(t0[:], t4[:])
	for i := 1; i < 102; i++ { // 2^104 + 2^103 + 2^102 + 2^101
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 104..101, **98.....53**, **50.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 107; i++ { // 2^106
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 106,104..101, **98.....53**, **50.....0**
	copy(t0[:], t3[:])
	for i := 1; i < 109; i++ { // 2^110 + 2^109 + 2^108
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 110..108, 106,104..101, **98.....53**, **50.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 113; i++ { // 2^112
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 112,110..108, 106,104..101, **98.....53**, **50.....0**
	copy(t0[:], t5[:])
	for i := 1; i < 116; i++ { // 2^119 + 2^118 + 2^117 + 2^116 + 2^115
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 119..115, 112,110..108, 106,104..101, **98.....53**, **50.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 122; i++ { // 2^121
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 121, 119..115, 112,110..108, 106,104..101, **98.....53**, **50.....0**
	copy(t0[:], t2[:])
	for i := 1; i < 124; i++ { // 2^124 + 2^123
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 124,123, 121, 119..115, 112,110..108, 106,104..101, **98.....53**, **50.....0**

	copy(t0[:], z[:])
	for i := 1; i < 252; i++ { // 2^252
		edwards25519.ScMulAdd(&t0, &t0, &t0, &zero)
	}
	MultModL(&tz, &t0, &tz) // tz = 252, 124......
	copy(out[:], tz[:])

	// if you input z=2, we should get 2^(2048 + 1024 + 512 + 256 + 64 + 32 + 4 + 1) = 2^3941 mod l
	// = 4390054613844824731020805728162554857567810442668694040812122513881566113753

}