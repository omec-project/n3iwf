// Copyright 2021 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package integ

import (
	"hash"

	"github.com/omec-project/n3iwf/ike/message"
)

const (
	AUTH_HMAC_MD5_96       string = "AUTH_HMAC_MD5_96"
	AUTH_HMAC_SHA1_96      string = "AUTH_HMAC_SHA1_96"
	AUTH_HMAC_SHA2_256_128 string = "AUTH_HMAC_SHA2_256_128"
)

var integString map[uint16]func(uint16, uint16, []byte) string

var (
	integTypes  map[string]INTEGType
	integKTypes map[string]INTEGKType
)

// INTEGType is the interface for integrity algorithms
// INTEGKType is the interface for kernel integrity algorithms
func init() {
	// INTEG String
	integString = make(map[uint16]func(uint16, uint16, []byte) string)
	integString[message.AUTH_HMAC_MD5_96] = toString_AUTH_HMAC_MD5_96
	integString[message.AUTH_HMAC_SHA1_96] = toString_AUTH_HMAC_SHA1_96
	integString[message.AUTH_HMAC_SHA2_256_128] = toString_AUTH_HMAC_SHA2_256_128

	// INTEG Types
	integTypes = make(map[string]INTEGType)
	integTypes[AUTH_HMAC_MD5_96] = &AuthHmacMd5_96{
		KeyLen:    16,
		OutputLen: 12,
	}
	integTypes[AUTH_HMAC_SHA1_96] = &AuthHmacSha1_96{
		KeyLen:    20,
		OutputLen: 12,
	}
	integTypes[AUTH_HMAC_SHA2_256_128] = &AuthHmacSha2_256_128{
		KeyLen:    32,
		OutputLen: 16,
	}

	// INTEG Kernel Types
	integKTypes = make(map[string]INTEGKType)
	integKTypes[AUTH_HMAC_MD5_96] = &AuthHmacMd5_96{
		KeyLen:    16,
		OutputLen: 12,
	}
	integKTypes[AUTH_HMAC_SHA1_96] = &AuthHmacSha1_96{
		KeyLen:    20,
		OutputLen: 12,
	}
	integKTypes[AUTH_HMAC_SHA2_256_128] = &AuthHmacSha2_256_128{
		KeyLen:    32,
		OutputLen: 16,
	}
}

func StrToType(algo string) INTEGType {
	if t, ok := integTypes[algo]; ok {
		return t
	} else {
		return nil
	}
}

func StrToKType(algo string) INTEGKType {
	if t, ok := integKTypes[algo]; ok {
		return t
	} else {
		return nil
	}
}

func DecodeTransform(transform *message.Transform) INTEGType {
	if f, ok := integString[transform.TransformID]; ok {
		s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		if s != "" {
			if integType, ok2 := integTypes[s]; ok2 {
				return integType
			} else {
				return nil
			}
		} else {
			return nil
		}
	} else {
		return nil
	}
}

func ToTransform(integType INTEGType) *message.Transform {
	t := new(message.Transform)
	t.TransformType = message.TypeIntegrityAlgorithm
	t.TransformID = integType.TransformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = integType.getAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = 1 // TV
	}
	return t
}

func DecodeTransformChildSA(transform *message.Transform) INTEGKType {
	if f, ok := integString[transform.TransformID]; ok {
		s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		if s != "" {
			if integKType, ok2 := integKTypes[s]; ok2 {
				return integKType
			} else {
				return nil
			}
		} else {
			return nil
		}
	} else {
		return nil
	}
}

func ToTransformChildSA(integKType INTEGKType) *message.Transform {
	t := new(message.Transform)
	t.TransformType = message.TypeIntegrityAlgorithm
	t.TransformID = integKType.TransformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = integKType.getAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = message.AttributeFormatUseTV
	}
	return t
}

type INTEGType interface {
	TransformID() uint16
	getAttribute() (bool, uint16, uint16, []byte)
	GetKeyLength() int
	GetOutputLength() int
	Init(key []byte) hash.Hash
}

type INTEGKType interface {
	TransformID() uint16
	getAttribute() (bool, uint16, uint16, []byte)
	GetKeyLength() int
}
