// Copyright 2021 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package prf

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"

	"github.com/omec-project/n3iwf/ike/message"
)

// PRF_HMAC_SHA2_256 implements the PRFType interface using HMAC-SHA2-256.
const (
	PrfHmacSha2_256KeyLength    = 32 // 256 bits
	PrfHmacSha2_256OutputLength = 32 // 256 bits
)

var _ PRFType = &PrfHmacSha2_256{}

// PrfHmacSha2_256 provides HMAC-SHA2-256 PRF functionality.
type PrfHmacSha2_256 struct{}

func toString_PRF_HMAC_SHA2_256(attrType, attrValue uint16, variableAttr []byte) string {
	return PRF_HMAC_SHA2_256
}

func (t *PrfHmacSha2_256) TransformID() uint16 {
	return message.PRF_HMAC_SHA2_256
}

func (t *PrfHmacSha2_256) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (t *PrfHmacSha2_256) GetKeyLength() int {
	return PrfHmacSha2_256KeyLength
}

func (t *PrfHmacSha2_256) GetOutputLength() int {
	return PrfHmacSha2_256OutputLength
}

func (t *PrfHmacSha2_256) Init(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}
