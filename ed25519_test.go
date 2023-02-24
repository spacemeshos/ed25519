package ed25519

import (
	"crypto/ed25519"
	"testing"
)

type zeroReader struct{}

func (zeroReader) Read(buf []byte) (int, error) {
	for i := range buf {
		buf[i] = 0
	}
	return len(buf), nil
}

func BenchmarkSigning(b *testing.B) {
	_, priv, err := GenerateKey(zeroReader{})
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ed25519.Sign(priv, message)
	}
}

func BenchmarkVerification(b *testing.B) {
	pub, priv, err := GenerateKey(zeroReader{})
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	signature := ed25519.Sign(priv, message)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ed25519.Verify(pub, message, signature)
	}
}
