package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// Encrypt encrypts plain text using AES-GCM
func Encrypt(plaintext, key string) (string, error) {
	keyBytes := []byte(key)
	
	// Ensure key is 32 bytes for AES-256
	if len(keyBytes) != 32 {
		return "", fmt.Errorf("encryption key must be 32 bytes long")
	}
	
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}
	
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts cipher text using AES-GCM
func Decrypt(ciphertext, key string) (string, error) {
	keyBytes := []byte(key)
	
	// Ensure key is 32 bytes for AES-256
	if len(keyBytes) != 32 {
		return "", fmt.Errorf("decryption key must be 32 bytes long")
	}
	
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}
	
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}
	
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	
	nonce, encryptedData := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}
	
	return string(plaintext), nil
}

// GenerateKey generates a random 32-byte key for AES-256
func GenerateKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("failed to generate key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// PrepareKey takes a key string and ensures it's 32 bytes
func PrepareKey(key string) (string, error) {
	if len(key) == 32 {
		return key, nil
	}
	
	// If it's base64 encoded, decode it
	if decoded, err := base64.StdEncoding.DecodeString(key); err == nil {
		if len(decoded) == 32 {
			return string(decoded), nil
		}
	}
	
	// Pad or truncate to 32 bytes
	keyBytes := []byte(key)
	if len(keyBytes) > 32 {
		keyBytes = keyBytes[:32]
	} else if len(keyBytes) < 32 {
		padding := make([]byte, 32-len(keyBytes))
		keyBytes = append(keyBytes, padding...)
	}
	
	return string(keyBytes), nil
}
