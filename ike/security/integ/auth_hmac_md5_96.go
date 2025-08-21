// Copyright 2021 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package integ

import (
	"crypto/hmac"
	"crypto/md5"
	"hash"

	"github.com/omec-project/n3iwf/ike/message"
)

func toString_AUTH_HMAC_MD5_96(attrType uint16, intValue uint16, bytesValue []byte) string {
	return AUTH_HMAC_MD5_96
}

var (
	_ INTEGType  = &AuthHmacMd5_96{}
	_ INTEGKType = &AuthHmacMd5_96{}
)

// AuthHmacMd5_96 implements HMAC-MD5-96 integrity algorithm
type AuthHmacMd5_96 struct {
	KeyLen    int
	OutputLen int
}

func (a *AuthHmacMd5_96) TransformID() uint16 {
	return message.AUTH_HMAC_MD5_96
}

func (a *AuthHmacMd5_96) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (a *AuthHmacMd5_96) GetKeyLength() int {
	return a.KeyLen
}

func (a *AuthHmacMd5_96) GetOutputLength() int {
	return a.OutputLen
}

func (a *AuthHmacMd5_96) Init(key []byte) hash.Hash {
	if len(key) == 16 {
		return hmac.New(md5.New, key)
	}
	return nil
}
