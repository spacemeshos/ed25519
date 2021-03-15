package vrf

// Package ed25519 implements a verifiable random function using the Edwards form
// of Curve25519, SHA512 and the Elligator map.

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"github.com/spacemeshos/ed25519"
	"github.com/spacemeshos/ed25519/internal/edwards25519"
	"github.com/spacemeshos/ed25519/internal/extra25519"
	"io"
)

const (
	PublicKeySize    = ed25519.PublicKeySize
	PrivateKeySize   = ed25519.PrivateKeySize
	Size             = 32
	intermediateSize = ed25519.PublicKeySize
	ProofSize        = 32 + 32 + intermediateSize
)

var (
	ErrGetPubKey = errors.New("[vrf] Couldn't get corresponding public-key from private-key")
)

type PrivateKey []byte
type PublicKey []byte

// GenerateKey creates a public/private key pair using rnd for randomness.
// If rnd is nil, crypto/rand is used.
func GenerateKey(rnd io.Reader) (sk PrivateKey, err error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	_, skr, err := ed25519.GenerateKey(rnd)
	return PrivateKey(skr), err
}

// Public extracts the public VRF key from the underlying private-key
// and returns a boolean indicating if the operation was successful.
func (sk PrivateKey) Public() (PublicKey, bool) {
	pk, ok := ed25519.PrivateKey(sk).Public().(ed25519.PublicKey)
	return PublicKey(pk), ok
}

func (sk PrivateKey) expandSecret() (x, skhr *[32]byte) {
	x, skhr = new([32]byte), new([32]byte)
	skh := sha512.Sum512(sk[:32])
	copy(x[:], skh[:])
	copy(skhr[:], skh[32:])
	x[0] &= 248
	x[31] &= 127
	x[31] |= 64
	return
}

// Compute generates the vrf value for the byte slice m using the
// underlying private key sk.
func (sk PrivateKey) Compute(m []byte) []byte {
	x, _ := sk.expandSecret()
	var ii edwards25519.ExtendedGroupElement
	var iiB [32]byte
	edwards25519.GeScalarMult(&ii, x, hashToCurve(m))
	ii.ToBytes(&iiB)

	vrf := sha512.New()
	vrf.Write(iiB[:]) // const length: Size
	vrf.Write(m)
	return vrf.Sum(nil)[:32]
}

func hashToCurve(m []byte) *edwards25519.ExtendedGroupElement {
	// H(n) = (f(h(n))^8)
	hmbH := sha512.Sum512(m)
	var hmb [32]byte
	copy(hmb[:], hmbH[:])
	var hm edwards25519.ExtendedGroupElement
	extra25519.HashToEdwards(&hm, &hmb)
	edwards25519.GeDouble(&hm, &hm)
	edwards25519.GeDouble(&hm, &hm)
	edwards25519.GeDouble(&hm, &hm)
	return &hm
}

// Prove returns the vrf value and a proof such that
// Verify(m, vrf, proof) == true. The vrf value is the
// same as returned by Compute(m).
func (sk PrivateKey) Prove(m []byte) (proof []byte) {
	x, skhr := sk.expandSecret()
	var sH, rH [64]byte
	var r, s, minusS, t, gB, grB, hrB, hxB, hB [32]byte
	var ii, gr, hr edwards25519.ExtendedGroupElement

	h := hashToCurve(m)
	h.ToBytes(&hB)
	edwards25519.GeScalarMult(&ii, x, h)
	ii.ToBytes(&hxB)

	// use hash of private-, public-key and msg as randomness source:
	hash := sha512.New()
	hash.Write(skhr[:])
	hash.Write(sk[32:]) // public key, as in ed25519
	hash.Write(m)
	hash.Sum(rH[:0])

	edwards25519.ScReduce(&r, &rH)
	edwards25519.GeScalarMultBase(&gr, &r)
	edwards25519.GeScalarMult(&hr, &r, h)
	gr.ToBytes(&grB)
	hr.ToBytes(&hrB)
	gB = edwards25519.BaseBytes

	// H2(g, h, g^x, h^x, g^r, h^r, m)
	hash.Reset()
	hash.Write(gB[:])
	hash.Write(hB[:])
	hash.Write(sk[32:]) // ed25519 public-key
	hash.Write(hxB[:])
	hash.Write(grB[:])
	hash.Write(hrB[:])
	hash.Write(m)
	hash.Sum(sH[:0])
	hash.Reset()
	edwards25519.ScReduce(&s, &sH)
	edwards25519.ScNeg(&minusS, &s)
	edwards25519.ScMulAdd(&t, x, &minusS, &r)

	proof = make([]byte, ProofSize)
	copy(proof[:32], s[:])
	copy(proof[32:64], t[:])
	copy(proof[64:96], hxB[:])
	return
}

func Vrf(m, proof []byte) []byte{
	hash := sha512.New()
	hash.Write(proof[64:])
	hash.Write(m)
	return hash.Sum(nil)[:Size]
}

// Verify returns true iff vrf=Compute(m) for the sk that
// corresponds to pk.
func (pkBytes PublicKey) Verify(m, proof []byte) bool {
	if len(proof) != ProofSize || len(pkBytes) != PublicKeySize {
		return false
	}
	var pk, s, sRef, t, hxB, hB, gB, ABytes, BBytes [32]byte
	copy(pk[:], pkBytes[:])
	copy(s[:32], proof[:32])
	copy(t[:32], proof[32:64])
	copy(hxB[:], proof[64:96])

	var P, B, ii, iic edwards25519.ExtendedGroupElement
	var A, hmtP, iicP edwards25519.ProjectiveGroupElement
	if !P.FromBytesBaseGroup(&pk) {
		return false
	}
	if !ii.FromBytesBaseGroup(&hxB) {
		return false
	}
	edwards25519.GeDoubleScalarMultVartime(&A, &s, &P, &t)
	A.ToBytes(&ABytes)
	gB = edwards25519.BaseBytes

	h := hashToCurve(m) // h = H1(m)
	h.ToBytes(&hB)
	edwards25519.GeDoubleScalarMultVartime(&hmtP, &t, h, &[32]byte{})
	edwards25519.GeDoubleScalarMultVartime(&iicP, &s, &ii, &[32]byte{})
	iicP.ToExtended(&iic)
	hmtP.ToExtended(&B)
	edwards25519.GeAdd(&B, &B, &iic)
	B.ToBytes(&BBytes)

	var sH [64]byte
	// sRef = H2(g, h, g^x, v, g^t路G^s,H1(m)^t路v^s, m), with v=H1(m)^x=h^x
	hash := sha512.New()
	hash.Write(gB[:])
	hash.Write(hB[:])
	hash.Write(pkBytes)
	hash.Write(hxB[:])
	hash.Write(ABytes[:]) // const length (g^t*G^s)
	hash.Write(BBytes[:]) // const length (H1(m)^t*v^s)
	hash.Write(m)
	hash.Sum(sH[:0])

	edwards25519.ScReduce(&sRef, &sH)
	return sRef == s
}
