/*
 * Project: Application Security Libraries
 * Filename: /crc.go
 * Created Date: Tuesday September 5th 2023 07:04:56 +0800
 * Author: Sallehuddin Abdul Latif (sallehuddin@berrypay.com)
 * Company: BerryPay (M) Sdn. Bhd.
 * --------------------------------------
 * Last Modified: Tuesday September 5th 2023 07:29:16 +0800
 * Modified By: Sallehuddin Abdul Latif (sallehuddin@berrypay.com)
 * --------------------------------------
 * Copyright (c) 2023 BerryPay (M) Sdn. Bhd.
 */

package appsec

import (
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
)

func Crc32IEEE(b []byte) uint32 {
	return crc32.ChecksumIEEE(b)
}

func Crc32Castagnoli(b []byte) uint32 {
	return crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli))
}

func Crc32Koopman(b []byte) uint32 {
	return crc32.Checksum(b, crc32.MakeTable(crc32.Koopman))
}

func Adler32(b []byte) uint32 {
	return adler32.Checksum(b)
}

func Crc64ISO(b []byte) uint64 {
	return crc64.Checksum(b, crc64.MakeTable(crc64.ISO))
}

func Crc64ECMA(b []byte) uint64 {
	return crc64.Checksum(b, crc64.MakeTable(crc64.ECMA))
}
