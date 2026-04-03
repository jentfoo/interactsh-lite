package oobsrv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// ParsePublicKey decodes a base64-encoded PEM-wrapped PKIX RSA public key.
func ParsePublicKey(b64Key string) (*rsa.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}

	block, _ := pem.Decode(decoded)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaPubKey, nil
}

// GenerateAESKey returns 32 random bytes for AES-256.
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}
	return key, nil
}

// EncryptInteraction encrypts plaintext with AES-256-CTR and returns raw IV || ciphertext.
func EncryptInteraction(plaintext, aesKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	return EncryptInteractionBlock(plaintext, block)
}

// EncryptInteractionBlock encrypts using a pre-created cipher.Block, avoiding
// repeated key expansion. Returns raw IV || ciphertext bytes.
func EncryptInteractionBlock(plaintext []byte, block cipher.Block) ([]byte, error) {
	raw := make([]byte, aes.BlockSize+len(plaintext))
	if _, err := rand.Read(raw[:aes.BlockSize]); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}
	cipher.NewCTR(block, raw[:aes.BlockSize]).XORKeyStream(raw[aes.BlockSize:], plaintext)
	return raw, nil
}

// EncryptAESKey encrypts the AES key with RSA-OAEP SHA-256 and returns base64.
func EncryptAESKey(aesKey []byte, publicKey *rsa.PublicKey) (string, error) {
	if len(aesKey) == 0 {
		return "", nil
	}

	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, aesKey, nil)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt AES key: %w", err)
	}

	return base64.StdEncoding.EncodeToString(encrypted), nil
}
