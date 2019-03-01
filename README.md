# ed25519
A drop in replacement for golang/crypto/ed25519 with additional functionality

# Motivation
todo: explain why the extension are useful 

## Sign2
Sign2 signs the message with privateKey and returns a signature.
The signature may be verified using Verify2(), if the signer's public key is known.
The signature returned by this method can be used together with the message
to extract the public key using ExtractPublicKey()
It will panic if len(privateKey) is not PrivateKeySize.

COMMENTS in the code refer to Algorithm 1 in https://eprint.iacr.org/2017/985.pdf

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