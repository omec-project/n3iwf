// Copyright 2021 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package prf

import (
	"crypto/hmac"
	"crypto/md5"
	"hash"

	"github.com/omec-project/n3iwf/ike/message"
)

const (
	PrfHmacMd5KeyLength    = 16 // MD5 key length in bytes
	PrfHmacMd5OutputLength = 16 // MD5 output length in bytes
)

var _ PRFType = &PrfHmacMd5{}

// PrfHmacMd5 implements HMAC-MD5 PRF
// Key and output lengths are fixed for MD5
type PrfHmacMd5 struct{}

func toString_PRF_HMAC_MD5(attrType, attrValue uint16, variableAttr []byte) string {
	return PRF_HMAC_MD5
}

func (t *PrfHmacMd5) TransformID() uint16 {
	return message.PRF_HMAC_MD5
}

// getAttribute returns no attributes for HMAC-MD5
func (t *PrfHmacMd5) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

// GetKeyLength returns the fixed key length for HMAC-MD5
func (t *PrfHmacMd5) GetKeyLength() int {
	return PrfHmacMd5KeyLength
}

// GetOutputLength returns the fixed output length for HMAC-MD5
func (t *PrfHmacMd5) GetOutputLength() int {
	return PrfHmacMd5OutputLength
}

// Init initializes a new HMAC-MD5 hash with the given key
func (t *PrfHmacMd5) Init(key []byte) hash.Hash {
	return hmac.New(md5.New, key)
}
