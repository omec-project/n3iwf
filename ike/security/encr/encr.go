// Copyright 2021 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package encr

import (
	"fmt"

	"github.com/omec-project/n3iwf/ike/message"
	ikeCrypto "github.com/omec-project/n3iwf/ike/security/IKECrypto"
)

var encrString map[uint16]func(uint16, uint16, []byte) string

var encrTypes map[string]ENCRType

func init() {
	// ENCR String
	encrString = map[uint16]func(uint16, uint16, []byte) string{
		message.ENCR_AES_CBC: toString_ENCR_AES_CBC,
	}

	// ENCR Types
	encrTypes = map[string]ENCRType{
		ENCR_AES_CBC_128: &EncrAesCbc{keyLength: 16},
		ENCR_AES_CBC_192: &EncrAesCbc{keyLength: 24},
		ENCR_AES_CBC_256: &EncrAesCbc{keyLength: 32},
	}
}

func DecodeTransform(transform *message.Transform) ENCRType {
	if f, ok := encrString[transform.TransformID]; ok {
		s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		return encrTypes[s]
	}
	return nil
}

func ToTransform(encrType ENCRType) (*message.Transform, error) {
	t := &message.Transform{
		TransformType: message.TypeEncryptionAlgorithm,
		TransformID:   encrType.TransformID(),
	}
	var err error
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue, err = encrType.getAttribute()
	if err != nil {
		return nil, fmt.Errorf("ToTransform: %w", err)
	}
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = message.AttributeFormatUseTV
	}
	return t, nil
}

type ENCRType interface {
	TransformID() uint16
	getAttribute() (bool, uint16, uint16, []byte, error)
	GetKeyLength() int
	NewCrypto(key []byte) (ikeCrypto.IKECrypto, error)
}
