package crypto

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "errors"
    "io"

    "golang.org/x/crypto/scrypt"
)

// deriveKey turns passphrase+salt into a 32-byte AES key
func deriveKey(passphrase string, salt []byte) ([]byte, error) {
    return scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32)
}

// Encrypt plaintext with AES-GCM; output = salt||nonce||ciphertext
func Encrypt(plaintext []byte, passphrase string) ([]byte, error) {
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return nil, err
    }
    key, err := deriveKey(passphrase, salt)
    if err != nil {
        return nil, err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }

    ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
    out := append(salt, nonce...)
    out = append(out, ciphertext...)
    return out, nil
}

// Decrypt reverses Encrypt; expects salt||nonce||ciphertext
func Decrypt(data []byte, passphrase string) ([]byte, error) {
    if len(data) < 16 {
        return nil, errors.New("ciphertext too short")
    }
    salt := data[:16]
    key, err := deriveKey(passphrase, salt)
    if err != nil {
        return nil, err
    }
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(data) < 16+nonceSize {
        return nil, errors.New("ciphertext too short for nonce")
    }
    nonce := data[16 : 16+nonceSize]
    ciphertext := data[16+nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}
