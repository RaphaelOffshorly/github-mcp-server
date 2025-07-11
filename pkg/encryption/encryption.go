package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
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
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts cipher text using AES-GCM or OpenSSL format
func Decrypt(ciphertext, key string) (string, error) {
	keyBytes := []byte(key)
	
	// Ensure key is 32 bytes for AES-256
	if len(keyBytes) != 32 {
		return "", fmt.Errorf("decryption key must be 32 bytes long")
	}
	
	// URL decode first if needed
	if decoded, err := url.QueryUnescape(ciphertext); err == nil {
		ciphertext = decoded
	}
	
	// Try URL-safe base64 first, then standard base64
	data, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		// Try standard base64 as fallback
		data, err = base64.StdEncoding.DecodeString(ciphertext)
		if err != nil {
			return "", fmt.Errorf("failed to decode base64: %w", err)
		}
	}
	
	// Check if this is OpenSSL format (starts with "Salted__")
	if len(data) >= 16 && string(data[:8]) == "Salted__" {
		return decryptOpenSSL(data, keyBytes)
	}
	
	// Try AES-GCM format
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

// decryptOpenSSL decrypts OpenSSL-encrypted data
func decryptOpenSSL(data, key []byte) (string, error) {
	if len(data) < 16 {
		return "", fmt.Errorf("OpenSSL data too short")
	}
	
	// Extract salt (8 bytes after "Salted__")
	salt := data[8:16]
	encryptedData := data[16:]
	
	// Try both AES-128 and AES-256
	keySizes := []int{16, 32} // AES-128 and AES-256
	
	for _, keySize := range keySizes {
		result, err := tryDecryptWithKeySize(encryptedData, key, salt, keySize)
		if err == nil {
			return result, nil
		}
	}
	
	return "", fmt.Errorf("failed to decrypt with any supported key size")
}

// tryDecryptWithKeySize tries to decrypt with a specific key size
func tryDecryptWithKeySize(encryptedData, password, salt []byte, keySize int) (string, error) {
	// Derive key and IV using EVP_BytesToKey equivalent
	keyIV := make([]byte, keySize+16) // key + 16 bytes IV
	d := make([]byte, 0)
	
	for len(keyIV) > len(d) {
		h := md5.New()
		h.Write(d)
		h.Write(password)
		h.Write(salt)
		d = h.Sum(d)
	}
	
	derivedKey := keyIV[:keySize]
	iv := keyIV[keySize:keySize+16]
	
	// Decrypt using AES-CBC
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}
	
	if len(encryptedData)%aes.BlockSize != 0 {
		return "", fmt.Errorf("encrypted data is not a multiple of block size")
	}
	
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(encryptedData))
	mode.CryptBlocks(plaintext, encryptedData)
	
	// Remove PKCS7 padding
	if len(plaintext) == 0 {
		return "", fmt.Errorf("decrypted data is empty")
	}
	
	padding := int(plaintext[len(plaintext)-1])
	if padding < 1 || padding > aes.BlockSize || padding > len(plaintext) {
		return "", fmt.Errorf("invalid padding: %d", padding)
	}
	
	// Check padding validity
	for i := len(plaintext) - padding; i < len(plaintext); i++ {
		if plaintext[i] != byte(padding) {
			return "", fmt.Errorf("invalid padding bytes")
		}
	}
	
	return string(plaintext[:len(plaintext)-padding]), nil
}

// GenerateKey generates a random 32-byte key for AES-256
func GenerateKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("failed to generate key: %w", err)
	}
	return base64.URLEncoding.EncodeToString(key), nil
}

// PrepareKey takes a key string and ensures it's 32 bytes
func PrepareKey(key string) (string, error) {
	if len(key) == 32 {
		return key, nil
	}
	
	// If it's base64 encoded, decode it
	if decoded, err := base64.URLEncoding.DecodeString(key); err == nil {
		if len(decoded) == 32 {
			return string(decoded), nil
		}
	}
	// Try standard base64 as fallback
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
