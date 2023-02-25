package main

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

func main() {
	text := []byte("dick")
	key := []byte("the-key-has-to-be-32-bytes-long!")

	ciphertext, _ := encrypt(text, key)
	fmt.Printf("%s => %x\n", text, ciphertext)
	plaintext, _ := decrypt(ciphertext, key)
	fmt.Printf("%x => %s\n", ciphertext, plaintext)
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
