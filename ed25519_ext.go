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
	var R edwards25519.ProjectiveGroupElement
	var s [32]byte
	copy(s[:], sig[32:])

	// https://tools.ietf.org/html/rfc8032#section-5.1.7 requires that s be in
	// the range [0, order) in order to prevent signature malleability.
	if !edwards25519.ScMinimal(&s) {
		return nil, errors.New("invalid signature")
	}

	var zero [32]byte
	var one [32]byte
	one[0] = byte(1)

	// NEXT: extract R as a point on the curve and compute the inverse of R, sig[32:] --- I'm stuck with that
	//var SB edwards25519.ExtendedGroupElement
	//edwards25519.GeScalarMultBase(&SB, &s)    // probably not needed -- we do this operation below

	var ege edwards25519.ExtendedGroupElement
	if ok := ege.FromBytes(&s); !ok {
		return nil, errors.New("failed to create an extended group element from sig[32:]")
	}

	// First we try without negation
	edwards25519.GeDoubleScalarMultVartime(&R, &one, &ege, &s)

	var EC_PK edwards25519.ProjectiveGroupElement
	edwards25519.GeDoubleScalarMultVartime(&EC_PK, &hInv, &R, &zero)

	var pubKey [PublicKeySize]byte

	// EC_PK is supposed to be the public key as an elliptic curve point
	// THIS IS OLD COMMENT (unclear at the moment): I think that we need to obtain the full point, so we can apply ToBytes below
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

	copy(tz[:], t2[:]) // tz = 2^1 + 2^0

	copy(t0[:], t1[:])
	for i := 1; i < 4; i++ { // 2^3
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 2^3 + 2^1 + 2^0
	copy(t0[:], t5[:])
	for i := 1; i < 6; i++ { // 2^9 + 2^8 + 2^7 + 2^6 + 2^5
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 2^9 + 2^8 + 2^7 + 2^6 + 2^5 + 2^3 + 2^1 + 2^0
	copy(t0[:], t1[:])
	for i := 1; i < 13; i++ { // 2^12
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 2^12 + 2^9 + 2^8 + 2^7 + 2^6 + 2^5 + 2^3 + 2^1 + 2^0
	copy(t0[:], t3[:])
	for i := 1; i < 15; i++ { // 2^16 + 2^15 + 2^14
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 16..14, 12,9..5, 3,1,0
	copy(t0[:], t1[:])
	for i := 1; i < 19; i++ { // 2^18
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t4[:])
	for i := 1; i < 21; i++ { // 2^23 + 2^22 + 2^21 + 2^20
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t3[:])
	for i := 1; i < 27; i++ { // 2^28 + 2^27 + 2^26
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 28..26, 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t1[:])
	for i := 1; i < 31; i++ { // 2^30
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 30,28..26, 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t1[:])
	for i := 1; i < 34; i++ { // 2^33
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 33,30,28..26, 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t2[:])
	for i := 1; i < 36; i++ { // 2^36 + 2^35
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 36,35,33,30,28..26, 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t2[:])
	for i := 1; i < 41; i++ { // 2^41 + 2^40
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 41,40,36,35,33,30,28..26, 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t2[:])
	for i := 1; i < 46; i++ { // 2^46 + 2^45
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 46,45,41,40,36,35,33,30,28..26, 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t1[:])
	for i := 1; i < 50; i++ { // 2^49
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 49,46,45,41,40,36,35,33,30,28..26, 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t1[:])
	for i := 1; i < 53; i++ { // 2^52
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 52, **49.....0**
	copy(t0[:], t2[:])
	for i := 1; i < 60; i++ { // 2^60 + 2^59
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 60,59,52, **49.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 63; i++ { // 2^62
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 62,60,59,52, **49.....0**
	copy(t0[:], t2[:])
	for i := 1; i < 66; i++ { // 2^66 + 2^65
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 66,65,62,60,59,52, **49.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 69; i++ { // 2^68
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t2[:])
	for i := 1; i < 71; i++ { // 2^71 + 2^70
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t3[:])
	for i := 1; i < 75; i++ { // 2^76 + 2^75 + 2^74
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 75..74, 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t4[:])
	for i := 1; i < 80; i++ { // 2^82 + 2^81 + 2^80 + 2^79
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 82..79, 75..74, 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t4[:])
	for i := 1; i < 85; i++ { // 2^87 + 2^86 + 2^85 + 2^84
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 87..84, 82..79, 75..74, 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 90; i++ { // 2^89
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 89,87..84, 82..79, 75..74, 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 94; i++ { // 2^93
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 93,89,87..84, 82..79, 75..74, 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 96; i++ { // 2^95
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 95,93,89,87..84, 82..79, 75..74, 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t4[:])
	for i := 1; i < 98; i++ { // 2^100 + 2^99 + 2^98 + 2^97
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 100..97, 95,93,89,87..84, 82..79, 75..74, 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t3[:])
	for i := 1; i < 103; i++ { // 2^104 + 2^103 + 2^102
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 104..102, **100.....52**, **49.....0**
	copy(t0[:], t5[:])
	for i := 1; i < 108; i++ { // 2^111 + 2^110 + 2^109 + 2^108 + 2^107
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 111..107, 104..102, **100.....52**, **49.....0**
	copy(t0[:], t4[:])
	for i := 1; i < 114; i++ { // 2^116 + 2^115 + 2^114 + 2^113
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 116..113, 111..107, 104..102, **100.....52**, **49.....0**
	copy(t0[:], t2[:])
	for i := 1; i < 119; i++ { // 2^119 + 2^118
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 119,118,116..113, 111..107, 104..102, **100.....52**, **49.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 123; i++ { // 2^122
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 122,119,118,116..113, 111..107, 104..102, **100.....52**, **49.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 125; i++ { // 2^124
		SquareModL(&t0, &t0)
	}
	MultModL(&tz, &t0, &tz) // tz = 124,122,119,118,116..113, 111..107, 104..102, **100.....52**, **49.....0**
	copy(t0[:], z[:])
	for i := 1; i < 253; i++ { // 2^252
		edwards25519.ScMulAdd(&t0, &t0, &t0, &zero)
	}
	MultModL(&tz, &t0, &tz) // tz = 252, 124......

	copy(out[:], tz[:])

	// For z=2, we should get inv(2) mod l = 3618502788666131106986593281521497120428558179689953803000975469142727125495
	// For z=17, we should get inv(17) mod l = 851412420862619083996845478005058145983190159927047953647288345680641676587

	// COMMENT FOR BARAK w1 := 2^0 + ... + 2^49 = 671914833335275
	// 			w2 := w1 + 2^52 + ... + 2^100 = 2427280792339553645574181213163
	// 			w3 := w2 + ... + 2^1124 = 27742317777372353535851937790883648491

}
