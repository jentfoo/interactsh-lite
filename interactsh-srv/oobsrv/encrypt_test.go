package oobsrv

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/interactsh-lite/oobclient"
)

// encodeTestPublicKey encodes an RSA public key the same way the client does: PKIX DER -> PEM -> base64.
func encodeTestPublicKey(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
	return base64.StdEncoding.EncodeToString(pemBlock)
}

func TestParsePublicKey(t *testing.T) {
	t.Parallel()

	t.Run("valid_rsa_key", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		b64 := encodeTestPublicKey(t, &key.PublicKey)
		parsed, err := ParsePublicKey(b64)
		require.NoError(t, err)
		assert.Equal(t, key.N, parsed.N)
		assert.Equal(t, key.E, parsed.E)
	})

	t.Run("invalid_base64", func(t *testing.T) {
		_, err := ParsePublicKey("not-valid-base64!!!")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid base64")
	})

	t.Run("invalid_pem", func(t *testing.T) {
		b64 := base64.StdEncoding.EncodeToString([]byte("not a PEM block"))
		_, err := ParsePublicKey(b64)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode PEM block")
	})

	t.Run("non_rsa_key", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		der, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
		require.NoError(t, err)

		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: der,
		})
		b64 := base64.StdEncoding.EncodeToString(pemBlock)

		_, err = ParsePublicKey(b64)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not an RSA public key")
	})

	t.Run("empty_input", func(t *testing.T) {
		_, err := ParsePublicKey("")
		assert.Error(t, err)
	})

	t.Run("invalid_der_in_pem", func(t *testing.T) {
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: []byte("not valid DER content"),
		})
		b64 := base64.StdEncoding.EncodeToString(pemBlock)

		_, err := ParsePublicKey(b64)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse public key")
	})
}

func TestGenerateAESKey(t *testing.T) {
	t.Parallel()

	t.Run("correct_length", func(t *testing.T) {
		key, err := GenerateAESKey()
		require.NoError(t, err)
		assert.Len(t, key, 32)
	})

	t.Run("unique_values", func(t *testing.T) {
		key1, err := GenerateAESKey()
		require.NoError(t, err)
		key2, err := GenerateAESKey()
		require.NoError(t, err)
		assert.NotEqual(t, key1, key2)
	})
}

func TestEncryptInteraction(t *testing.T) {
	t.Parallel()

	aesKey, err := GenerateAESKey()
	require.NoError(t, err)

	t.Run("round_trip_raw_crypto", func(t *testing.T) {
		plaintext := []byte(`{"protocol":"http","unique-id":"test123"}`)

		encrypted, err := EncryptInteraction(plaintext, aesKey)
		require.NoError(t, err)

		decrypted := decryptTestInteraction(t, encrypted, aesKey)
		assert.Equal(t, string(plaintext), decrypted)
	})

	t.Run("decrypt_compatibility", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		interaction := oobclient.Interaction{
			Protocol:      "http",
			UniqueID:      "abcdefghijklmnopqrst",
			FullId:        "abcdefghijklmnopqrstnop",
			RawRequest:    "GET / HTTP/1.1\r\nHost: test.example.com\r\n",
			RawResponse:   "HTTP/1.1 200 OK\r\n",
			RemoteAddress: "192.168.1.1",
			Timestamp:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		}

		plaintext, err := json.Marshal(interaction)
		require.NoError(t, err)

		encData, err := EncryptInteraction(plaintext, aesKey)
		require.NoError(t, err)

		encAESKey, err := EncryptAESKey(aesKey, &rsaKey.PublicKey)
		require.NoError(t, err)

		// Decrypt AES key using RSA (same sequence as oobclient)
		encKeyBytes, err := base64.StdEncoding.DecodeString(encAESKey)
		require.NoError(t, err)

		recoveredAESKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, encKeyBytes, nil)
		require.NoError(t, err)

		// Decrypt interaction using recovered AES key
		decrypted := decryptTestInteraction(t, encData, recoveredAESKey)

		var recovered oobclient.Interaction
		require.NoError(t, json.Unmarshal([]byte(decrypted), &recovered))
		assert.Equal(t, interaction, recovered)
	})

	t.Run("unique_ivs_across_calls", func(t *testing.T) {
		plaintext := []byte("same plaintext for iv test")
		ivs := make(map[string]bool)

		for range 10 {
			enc, err := EncryptInteraction(plaintext, aesKey)
			require.NoError(t, err)

			ivs[string(enc[:aes.BlockSize])] = true
		}
		assert.Len(t, ivs, 10)
	})
}

func TestEncryptAESKey(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	t.Run("round_trip_with_private_key", func(t *testing.T) {
		aesKey, err := GenerateAESKey()
		require.NoError(t, err)

		encrypted, err := EncryptAESKey(aesKey, &key.PublicKey)
		require.NoError(t, err)
		assert.NotEmpty(t, encrypted)

		raw, err := base64.StdEncoding.DecodeString(encrypted)
		require.NoError(t, err)

		decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, raw, nil)
		require.NoError(t, err)
		assert.Equal(t, aesKey, decrypted)
	})

	t.Run("nil_key_returns_empty", func(t *testing.T) {
		result, err := EncryptAESKey(nil, &key.PublicKey)
		require.NoError(t, err)
		assert.Empty(t, result)
	})
}
