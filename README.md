# ed25519
A drop-in replacement for `golang/crypto/ed25519` ([godoc](https://godoc.org/golang.org/x/crypto/ed25519), 
[github](https://github.com/golang/crypto/tree/master/ed25519))
 with additional functionality. 

# Motivation
In order to verify the validity of a given signature, the validator should posses the public key of the signer. It can be sent along with the message and its signature, which means that the overall data being sent includes 256 bits of the public key. Our function allows to extract the public key from the signature (and the message), thus the public key may not be sent, resulting in a smaller trasfered data. Note: there's a computational cost for extracting the public key, so one should consider the trade-off between computations and data size.

# Usage

```go
import "github.com/spacemeshos/ed25519"
```
Import package `ed25519` from `github.com/spacemeshos/ed25519` instead of `golang.org/x/crypto/ed25519`.


## Sign2
Sign2 signs the message with privateKey and returns a signature.
The signature may be verified using Verify2(), if the signer's public key is known.
The signature returned by this method can be used together with the message
to extract the public key using ExtractPublicKey()
It will panic if len(privateKey) is not PrivateKeySize.

```
func Sign2(privateKey PrivateKey, message []byte) []byte
```

## ExtractPublicKey
ExtractPublicKey extracts the signer's public key given a message and its signature.
It will panic if len(sig) is not SignatureSize.

```
func ExtractPublicKey(message, sig []byte) PublicKey
```

## Verify2
Verify2 verifies a signature created with Sign2() using a public key
extracted from the signature using ExtractPublicKey().

```
func Verify2(publicKey PublicKey, message, sig []byte) bool
````

# Building
```
go build
```

# Testing
```
go test ./... -v
```

# Benchmarking
```
go test -bench= .
go test -bench . github.com/spacemeshos/ed25519/internal/edwards25519
```