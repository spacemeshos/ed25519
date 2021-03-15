package vrf

import (
	"bytes"
	"fmt"
	"github.com/spacemeshos/ed25519"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestHonestComplete(t *testing.T) {
	sk, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := sk.Public()
	alice := []byte("alice")
	aliceProof := sk.Prove(alice)
	aliceVRF := Vrf(aliceProof)
	fmt.Printf("pk:           %X\n", pk)
	fmt.Printf("sk:           %X\n", sk)
	fmt.Printf("alice(bytes): %X\n", alice)
	fmt.Printf("aliceVRF:     %X\n", aliceVRF)
	fmt.Printf("aliceProof:   %X\n", aliceProof)

	if !pk.Verify(alice, aliceProof) {
		t.Error("Gen -> Compute -> Prove -> Verify -> FALSE")
	}
}

func TestConvertPrivateKeyToPublicKey(t *testing.T) {
	sk, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	pk, ok := sk.Public()
	if !ok {
		t.Fatal("Couldn't obtain public key.")
	}
	if !bytes.Equal(sk[32:], pk) {
		t.Fatal("Raw byte respresentation doesn't match public key.")
	}
}

func sampleVectorTest(pk PublicKey, aliceVRF, aliceProof []byte, t *testing.T) {
	alice := []byte{97, 108, 105, 99, 101}

	// Positive test case
	if !pk.Verify(alice, aliceProof) {
		t.Error("TestSampleVectors HonestVector Failed")
	}

	if !reflect.DeepEqual(Vrf(aliceProof),aliceVRF) {
		t.Error("TestSampleVectors Vrf Failed")
	}

	// Negative test cases - try increment the first byte of every vector
	pk[0]++
	if pk.Verify(alice, aliceProof) {
		t.Error("TestSampleVectors ForgedVector (pk modified) Passed")
	}
	pk[0]--

	alice[0]++
	if pk.Verify(alice, aliceProof) {
		t.Error("TestSampleVectors ForgedVector (alice modified) Passed")
	}
	alice[0]--

	aliceVRF[0]++
	if reflect.DeepEqual(Vrf(aliceProof),aliceVRF) {
		t.Error("TestSampleVectors Vrf Passed")
	}
	aliceVRF[0]--

	aliceProof[0]++
	if pk.Verify(alice, aliceProof) {
		t.Error("TestSampleVectors ForgedVector (aliceProof modified) Passed")
	}
	aliceProof[0]--
}

func _TestGenVectors(t *testing.T) {
	alice := []byte{97, 108, 105, 99, 101}
	strip := func(bs []byte) string{
		ss := make([]string,len(bs))
		for i,v :=range bs {
			ss[i] = strconv.Itoa(int(v))
		}
		return strings.Join(ss,", ")
	}
	gen := func(){
		pk, sk, _ := ed25519.GenerateKey(nil)
		aliceProof := PrivateKey(sk).Prove(alice)
		aliceVRF := Vrf(PrivateKey(aliceProof))
		fmt.Println("pk = []byte{",strip(pk),"}")
		fmt.Println("aliceVRF = []byte{",strip(aliceVRF),"}")
		fmt.Println("aliceProof = []byte{",strip(aliceProof),"}")
		fmt.Println("sampleVectorTest(pk, aliceVRF, aliceProof, t)")
		fmt.Println("")
	}
	gen()
	gen()
	gen()
}

func TestSampleVectorSets(t *testing.T) {
	//t.Skip("TODO: generate new test vectors or remove test")
	var aliceVRF, aliceProof []byte
	var pk []byte

	pk = []byte{ 140, 246, 215, 194, 177, 219, 204, 50, 222, 15, 239, 164, 40, 90, 194, 145, 182, 248, 250, 27, 138, 219, 124, 249, 190, 219, 234, 164, 101, 135, 57, 134 }
	aliceVRF = []byte{ 9, 156, 192, 253, 119, 101, 151, 186, 226, 63, 165, 171, 210, 97, 15, 9, 144, 101, 218, 155, 177, 13, 227, 80, 31, 17, 77, 35, 129, 74, 126, 86 }
	aliceProof = []byte{ 154, 60, 233, 213, 200, 109, 67, 148, 73, 36, 211, 61, 202, 145, 153, 109, 103, 38, 53, 220, 144, 173, 241, 114, 217, 166, 178, 83, 98, 96, 252, 15, 152, 245, 91, 214, 255, 154, 163, 70, 247, 184, 201, 123, 47, 128, 143, 181, 163, 24, 189, 141, 172, 95, 63, 96, 103, 111, 187, 88, 167, 56, 167, 7, 29, 66, 249, 0, 184, 149, 123, 255, 192, 94, 192, 245, 140, 8, 115, 137, 59, 11, 29, 139, 26, 94, 128, 160, 26, 208, 106, 152, 230, 224, 55, 191 }
	sampleVectorTest(pk, aliceVRF, aliceProof, t)

	pk = []byte{ 127, 160, 177, 129, 40, 135, 63, 174, 81, 57, 23, 118, 47, 6, 56, 46, 50, 109, 7, 108, 240, 165, 43, 34, 105, 96, 105, 176, 229, 1, 183, 160 }
	aliceVRF = []byte{ 112, 188, 154, 190, 211, 189, 5, 227, 98, 110, 87, 139, 62, 255, 74, 231, 121, 90, 31, 69, 155, 167, 197, 182, 96, 192, 175, 35, 208, 155, 226, 155 }
	aliceProof = []byte{ 90, 73, 80, 66, 211, 41, 213, 252, 208, 114, 94, 251, 75, 51, 67, 247, 82, 67, 205, 63, 98, 46, 248, 46, 174, 108, 146, 152, 147, 243, 210, 13, 86, 29, 10, 143, 16, 19, 94, 157, 207, 23, 41, 193, 122, 82, 38, 114, 85, 52, 240, 61, 35, 24, 113, 28, 74, 101, 16, 89, 79, 58, 6, 2, 45, 252, 137, 27, 204, 119, 126, 7, 82, 108, 185, 17, 155, 163, 225, 48, 154, 164, 133, 3, 114, 219, 75, 91, 247, 226, 129, 18, 65, 245, 242, 8 }
	sampleVectorTest(pk, aliceVRF, aliceProof, t)

	pk = []byte{ 41, 76, 212, 249, 206, 98, 110, 5, 53, 2, 57, 5, 229, 72, 191, 70, 175, 178, 31, 193, 191, 163, 49, 151, 52, 194, 165, 16, 132, 72, 133, 79 }
	aliceVRF = []byte{ 48, 251, 75, 116, 43, 126, 199, 181, 121, 54, 16, 236, 15, 16, 128, 80, 9, 52, 229, 234, 5, 105, 208, 158, 126, 196, 174, 125, 218, 126, 168, 66 }
	aliceProof = []byte{ 101, 182, 239, 70, 75, 18, 126, 200, 8, 126, 28, 201, 168, 217, 188, 145, 0, 207, 170, 198, 56, 47, 120, 251, 116, 45, 139, 235, 177, 166, 143, 6, 84, 108, 89, 180, 110, 169, 176, 173, 52, 4, 12, 245, 13, 129, 154, 234, 51, 36, 74, 125, 206, 77, 89, 71, 53, 52, 191, 130, 53, 148, 139, 10, 91, 7, 86, 94, 235, 167, 155, 178, 235, 48, 155, 124, 4, 131, 154, 144, 162, 70, 100, 70, 190, 108, 78, 38, 247, 40, 11, 9, 52, 62, 33, 76 }
	sampleVectorTest(pk, aliceVRF, aliceProof, t)

}

func BenchmarkHashToGE(b *testing.B) {
	alice := []byte("alice")
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		hashToCurve(alice)
	}
}

func BenchmarkProve(b *testing.B) {
	sk, err := GenerateKey(nil)
	if err != nil {
		b.Fatal(err)
	}
	alice := []byte("alice")
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		sk.Prove(alice)
	}
}

func BenchmarkVerify(b *testing.B) {
	sk, err := GenerateKey(nil)
	if err != nil {
		b.Fatal(err)
	}
	alice := []byte("alice")
	aliceProof := sk.Prove(alice)
	pk, _ := sk.Public()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		pk.Verify(alice, aliceProof)
	}
}

