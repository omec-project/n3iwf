// Copyright 2021 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package integ

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"

	"github.com/omec-project/n3iwf/ike/message"
)

func toString_AUTH_HMAC_SHA2_256_128(attrType uint16, intValue uint16, bytesValue []byte) string {
	return AUTH_HMAC_SHA2_256_128
}

// AuthHmacSha2_256_128 implements HMAC-SHA2-256-128 integrity algorithm
type AuthHmacSha2_256_128 struct {
	KeyLen    int
	OutputLen int
}

func (a *AuthHmacSha2_256_128) TransformID() uint16 {
	return message.AUTH_HMAC_SHA2_256_128
}

func (a *AuthHmacSha2_256_128) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (a *AuthHmacSha2_256_128) GetKeyLength() int {
	return a.KeyLen
}

func (a *AuthHmacSha2_256_128) GetOutputLength() int {
	return a.OutputLen
}

func (a *AuthHmacSha2_256_128) Init(key []byte) hash.Hash {
	if len(key) == 32 {
		return hmac.New(sha256.New, key)
	}
	return nil
}

var (
	_ INTEGType  = &AuthHmacSha2_256_128{}
	_ INTEGKType = &AuthHmacSha2_256_128{}
)
