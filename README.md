# ed25519
A drop in replacement for golang/crypto/ed25519 with additional functionality

# SignExt
SignExt signs the message with privateKey and returns a signature that can be verified using Verify(). The signature supports public key extraction using ExtractPublicKey()

```go
func SignExt(privateKey PrivateKey, message []byte) []byte
```

# ExtractPublicKey
ExtractPublicKey extracts the public key of the private key which signed the message. Sig MUST be a signature created with SignExt() and NOT Sign().

```go
func ExtractPublicKey(message, sig []byte) PublicKey
```
