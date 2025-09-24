// Copyright 2021 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package prf

import (
	"crypto/hmac"
	"crypto/sha1"
	"hash"

	"github.com/omec-project/n3iwf/ike/message"
)

const (
	PrfHmacSha1KeyLength    = 20 // SHA-1 output size in bytes
	PrfHmacSha1OutputLength = 20 // SHA-1 output size in bytes
)

var _ PRFType = &PrfHmacSha1{}

// PrfHmacSha1 implements PRFType for HMAC-SHA1
// keyLength and outputLength are fixed for SHA-1
type PrfHmacSha1 struct{}

// toString_PRF_HMAC_SHA1 returns the name of the PRF
func toString_PRF_HMAC_SHA1(_ uint16, _ uint16, _ []byte) string {
	return PRF_HMAC_SHA1
}

func (t *PrfHmacSha1) TransformID() uint16 {
	return message.PRF_HMAC_SHA1
}

// getAttribute returns default values for HMAC-SHA1 (no attributes)
func (t *PrfHmacSha1) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

// GetKeyLength returns the key length for HMAC-SHA1
func (t *PrfHmacSha1) GetKeyLength() int {
	return PrfHmacSha1KeyLength
}

// GetOutputLength returns the output length for HMAC-SHA1
func (t *PrfHmacSha1) GetOutputLength() int {
	return PrfHmacSha1OutputLength
}

// Init initializes a new HMAC-SHA1 hash with the given key
func (t *PrfHmacSha1) Init(key []byte) hash.Hash {
	return hmac.New(sha1.New, key)
}
