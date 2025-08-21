// Copyright 2021 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package prf

import (
	"hash"

	"github.com/omec-project/n3iwf/ike/message"
)

const (
	PRF_HMAC_MD5      string = "PRF_HMAC_MD5"
	PRF_HMAC_SHA1     string = "PRF_HMAC_SHA1"
	PRF_HMAC_SHA2_256 string = "PRF_HMAC_SHA2_256"
)

var (
	prfIDToStringFunc map[uint16]func(uint16, uint16, []byte) string
	prfNameToType     map[string]PRFType
)

func init() {
	prfIDToStringFunc = map[uint16]func(uint16, uint16, []byte) string{
		message.PRF_HMAC_MD5:      toString_PRF_HMAC_MD5,
		message.PRF_HMAC_SHA1:     toString_PRF_HMAC_SHA1,
		message.PRF_HMAC_SHA2_256: toString_PRF_HMAC_SHA2_256,
	}

	prfNameToType = map[string]PRFType{
		PRF_HMAC_MD5:      &PrfHmacMd5{},
		PRF_HMAC_SHA1:     &PrfHmacSha1{},
		PRF_HMAC_SHA2_256: &PrfHmacSha2_256{},
	}
}

// StrToType returns the PRFType for a given algorithm name.
func StrToType(algo string) PRFType {
	return prfNameToType[algo]
}

// DecodeTransform returns the PRFType for a given Transform message.
func DecodeTransform(transform *message.Transform) PRFType {
	if toStrFunc, ok := prfIDToStringFunc[transform.TransformID]; ok {
		prfName := toStrFunc(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		if prfName == "" {
			return nil
		}
		return prfNameToType[prfName]
	}
	return nil
}

// ToTransform creates a Transform message from a PRFType.
func ToTransform(prfType PRFType) *message.Transform {
	t := new(message.Transform)
	t.TransformType = message.TypePseudorandomFunction
	t.TransformID = prfType.TransformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = prfType.getAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = message.AttributeFormatUseTV
	}
	return t
}

// PRFType defines the interface for PRF implementations.
type PRFType interface {
	TransformID() uint16
	getAttribute() (bool, uint16, uint16, []byte)
	GetKeyLength() int
	GetOutputLength() int
	Init(key []byte) hash.Hash
}
