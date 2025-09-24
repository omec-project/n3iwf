// Copyright 2021 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package integ

import (
	"crypto/hmac"
	"crypto/sha1"
	"hash"

	"github.com/omec-project/n3iwf/ike/message"
)

func toString_AUTH_HMAC_SHA1_96(attrType uint16, intValue uint16, bytesValue []byte) string {
	return AUTH_HMAC_SHA1_96
}

// AuthHmacSha1_96 implements HMAC-SHA1-96 integrity algorithm
type AuthHmacSha1_96 struct {
	KeyLen    int
	OutputLen int
}

func (a *AuthHmacSha1_96) TransformID() uint16 {
	return message.AUTH_HMAC_SHA1_96
}

func (a *AuthHmacSha1_96) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (a *AuthHmacSha1_96) GetKeyLength() int {
	return a.KeyLen
}

func (a *AuthHmacSha1_96) GetOutputLength() int {
	return a.OutputLen
}

func (a *AuthHmacSha1_96) Init(key []byte) hash.Hash {
	if len(key) == 20 {
		return hmac.New(sha1.New, key)
	}
	return nil
}
