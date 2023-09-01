/*
 * Project: Application Security Libraries
 * Filename: /rsa.go
 * Created Date: Friday September 1st 2023 14:29:32 +0800
 * Author: Sallehuddin Abdul Latif (sallehuddin@berrypay.com)
 * Company: BerryPay (M) Sdn. Bhd.
 * --------------------------------------
 * Last Modified: Friday September 1st 2023 16:07:52 +0800
 * Modified By: Sallehuddin Abdul Latif (sallehuddin@berrypay.com)
 * --------------------------------------
 * Copyright (c) 2023 BerryPay (M) Sdn. Bhd.
 */

package appsec

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

var AppPublicKey *rsa.PublicKey
var AppPrivateKey *rsa.PrivateKey

// LoadPrivateKey loads the public key from the given PEM certificate file
//
// If the argument path is empty, the default app.key file on the same directory of executable is assumed to be used
func LoadPrivateKey(path string) error {
	// get base directory of the executable
	execBinFile, err := os.Executable()
	if err != nil {
		return err
	}
	binDir, err := filepath.Abs(filepath.Dir(execBinFile))
	if err != nil {
		return err
	}
	pemFilePath := filepath.Join(binDir, "app.key")

	if path != "" {
		pemFilePath = path
	}

	privateKeyFile, err := os.Open(pemFilePath)
	if err != nil {
		return err
	}

	pemFileInfo, _ := privateKeyFile.Stat()
	pemFileSize := pemFileInfo.Size()
	pemFileBytes := make([]byte, pemFileSize)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pemFileBytes)
	if err != nil {
		return err
	}

	pemBlock, _ := pem.Decode([]byte(pemFileBytes))
	privateKeyFile.Close()

	parsedKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return err
	}

	var parsingOk bool
	AppPrivateKey, parsingOk = parsedKey.(*rsa.PrivateKey)
	if !parsingOk {
		return fmt.Errorf("not a parsable RSA private key")
	}

	if err = AppPrivateKey.Validate(); err != nil {
		return err
	}

	AppPublicKey = &AppPrivateKey.PublicKey

	return nil
}

// LoadPublicKey loads the public key from the given PEM certificate file
//
// If the argument path is empty, the default app.crt file on the same directory of executable  is assumed to be used
func LoadPublicKey(path string) error {
	// get base directory of the executable
	execBinFile, err := os.Executable()
	if err != nil {
		return err
	}
	binDir, err := filepath.Abs(filepath.Dir(execBinFile))
	if err != nil {
		return err
	}
	pemFilePath := filepath.Join(binDir, "app.crt")

	if path != "" {
		pemFilePath = path
	}

	publicKeyFile, err := os.Open(pemFilePath)
	if err != nil {
		return err
	}

	pemFileInfo, _ := publicKeyFile.Stat()
	pemFileSize := pemFileInfo.Size()
	pemFileBytes := make([]byte, pemFileSize)
	buffer := bufio.NewReader(publicKeyFile)
	_, err = buffer.Read(pemFileBytes)
	if err != nil {
		return err
	}

	pemBlock, _ := pem.Decode([]byte(pemFileBytes))
	publicKeyFile.Close()

	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return err
	}

	AppPublicKey = cert.PublicKey.(*rsa.PublicKey)

	return nil
}

// Encrypt encrypts the given secret string with RSA-OAEP
// using the AppKey, SHA256 hash function and specified label
//
// Returns the base64 encoded cipher text
func EncryptOAEP(secret string, label string) (string, error) {
	rng := rand.Reader
	cipherText, err := rsa.EncryptOAEP(sha256.New(), rng, AppPublicKey, []byte(secret), []byte(label))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// Decrypt decrypts the given base64 encoded RSA-OAEP cipher text
// using the AppKey, SHA256 hash function
//
// # Returns the plain text string
//
// The label parameter must match the value given when encrypting
func DecryptOAEP(cipher string, label string) (string, error) {

	if AppPrivateKey == nil {
		return "", fmt.Errorf("AppPrivateKey is not loaded")
	}

	cipherText, err := base64.StdEncoding.DecodeString(cipher)
	if err != nil {
		return "", err
	}

	secret, err := rsa.DecryptOAEP(sha256.New(), nil, AppPrivateKey, []byte(cipherText), []byte(label))
	if err != nil {
		return "", err
	}

	return string(secret), nil
}
