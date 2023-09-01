/*
 * Project: Application Security Libraries
 * Filename: /hmac.go
 * Created Date: Friday September 1st 2023 14:29:32 +0800
 * Author: Sallehuddin Abdul Latif (sallehuddin@berrypay.com)
 * Company: BerryPay (M) Sdn. Bhd.
 * --------------------------------------
 * Last Modified: Friday September 1st 2023 14:38:06 +0800
 * Modified By: Sallehuddin Abdul Latif (sallehuddin@berrypay.com)
 * --------------------------------------
 * Copyright (c) 2023 BerryPay (M) Sdn. Bhd.
 */

package appsec

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
)

type MACAlgo string

const (
	HMAC_256 MACAlgo = "HMAC256"
	HMAC_512 MACAlgo = "HMAC512"
)

// ComputeHMAC256 computes HMAC256 signature of the message using the given secret
// parameters: message string, secret string
// return: base64 encoded HMAC256 signature
func ComputeHMAC256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// ComputeHMAC512 computes HMAC512 signature of the message using the given secret
// parameters: message string, secret string
// return: base64 encoded HMAC512 signature
func ComputeHMAC512(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha512.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// IsMatchedHMAC256 compares HMAC256 signature between the given signature to the computed signature based on given message and secret
// parameters: signature string, message string, secret string
// return: true if matched, false otherwise
func IsMatchedHMAC256(signature string, message string, secret string) bool {
	return ComputeHMAC256(message, secret) == signature
}

// IsMatchedHMAC512 compares HMAC512 signature between the given signature to the computed signature based on given message and secret
// parameters: signature string, message string, secret string
// return: true if matched, false otherwise
func IsMatchedHMAC512(signature string, message string, secret string) bool {
	return ComputeHMAC512(message, secret) == signature
}
