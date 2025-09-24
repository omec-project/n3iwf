// Copyright 2021 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package esn

import (
	"fmt"

	"github.com/omec-project/n3iwf/ike/message"
)

// ESN constants
const (
	ESNEnableString  = "ESN_ENABLE"
	ESNDisableString = "ESN_DISABLE"
)

// ESN struct definition
type ESN struct {
	needESN bool
}

// ESN string and type maps
var (
	esnStringMap map[uint16]func(uint16, uint16, []byte) string
	esnTypeMap   map[string]ESN
)

// ESN string conversion functions
func esnEnableToString(attrType, intValue uint16, bytesValue []byte) string {
	return ESNEnableString
}

func esnDisableToString(attrType, intValue uint16, bytesValue []byte) string {
	return ESNDisableString
}

// Initialize ESN maps
func init() {
	esnStringMap = map[uint16]func(uint16, uint16, []byte) string{
		message.ESN_ENABLE:  esnEnableToString,
		message.ESN_DISABLE: esnDisableToString,
	}

	esnTypeMap = map[string]ESN{
		ESNEnableString:  {needESN: true},
		ESNDisableString: {needESN: false},
	}
}

// GetNeedESN returns whether ESN is needed
func (e *ESN) GetNeedESN() bool {
	return e.needESN
}

// TransformID returns the corresponding transform ID
func (e *ESN) TransformID() uint16 {
	if e.needESN {
		return message.ESN_ENABLE
	}
	return message.ESN_DISABLE
}

// getAttribute returns ESN transform attributes
func (e *ESN) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

// StrToType converts string to ESN type
func StrToType(algo string) (ESN, error) {
	if t, ok := esnTypeMap[algo]; ok {
		return t, nil
	}
	return ESN{}, fmt.Errorf("unsupported ESN string: %s", algo)
}

// DecodeTransform decodes a message.Transform to ESN
func DecodeTransform(transform *message.Transform) (ESN, error) {
	f, ok := esnStringMap[transform.TransformID]
	if !ok {
		return ESN{}, fmt.Errorf("unsupported ESN transform ID: %d", transform.TransformID)
	}
	s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
	if s == "" {
		return ESN{}, fmt.Errorf("unsupported ESN string for transform")
	}
	esn, err := StrToType(s)
	if err != nil {
		return ESN{}, fmt.Errorf("DecodeTransform: %v", err)
	}
	return esn, nil
}

// ToTransform converts ESN type to message.Transform
func ToTransform(esnType ESN) *message.Transform {
	t := new(message.Transform)
	t.TransformType = message.TypeExtendedSequenceNumbers
	t.TransformID = esnType.TransformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = esnType.getAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = message.AttributeFormatUseTV
	}
	return t
}
