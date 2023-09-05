/*
 * Project: Application Security Libraries
 * Filename: /aes.go
 * Created Date: Tuesday September 5th 2023 11:36:40 +0800
 * Author: Sallehuddin Abdul Latif (sallehuddin@berrypay.com)
 * Company: BerryPay (M) Sdn. Bhd.
 * --------------------------------------
 * Last Modified: Tuesday September 5th 2023 12:09:00 +0800
 * Modified By: Sallehuddin Abdul Latif (sallehuddin@berrypay.com)
 * --------------------------------------
 * Copyright (c) 2023 BerryPay (M) Sdn. Bhd.
 */

package appsec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

const INVALID_AES_KEY_LENGTH = "invalid AES key length. Expected 32 bytes, got %d bytes"

var AESSecretKey []byte

func InitAES(key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf(INVALID_AES_KEY_LENGTH, len(key))
	}
	AESSecretKey = key
	return nil
}

func EncryptAESGCM(secret []byte) ([]byte, error) {
	if len(AESSecretKey) != 32 {
		return nil, fmt.Errorf(INVALID_AES_KEY_LENGTH, len(AESSecretKey))
	}

	aes, err := aes.NewCipher([]byte(AESSecretKey))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}

	// We need a 12-byte nonce for GCM
	// A nonce should always be randomly generated for every encryption.
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	// cipherText here is actually nonce+cipherText
	// So that when we decrypt, just knowing the nonce size
	// is enough to separate it from the cipherText.
	cipherText := gcm.Seal(nonce, nonce, []byte(secret), nil)

	return cipherText, nil
}

func DecryptAESGCM(cipherText []byte) ([]byte, error) {
	if len(AESSecretKey) != 32 {
		return nil, fmt.Errorf(INVALID_AES_KEY_LENGTH, len(AESSecretKey))
	}

	aes, err := aes.NewCipher([]byte(AESSecretKey))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}

	// Since we know the cipherText is actually nonce+cipherText
	// And len(nonce) == NonceSize(). We can separate the two.
	nonceSize := gcm.NonceSize()
	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]

	secret, err := gcm.Open(nil, []byte(nonce), []byte(cipherText), nil)
	if err != nil {
		return nil, err
	}

	return secret, nil
}
