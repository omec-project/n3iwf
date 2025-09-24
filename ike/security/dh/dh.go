// Copyright 2021 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package dh

import (
	"math/big"

	"github.com/omec-project/n3iwf/ike/message"
	"github.com/omec-project/n3iwf/logger"
)

const (
	DH_1024_BIT_MODP string = "DH_1024_BIT_MODP"
	DH_2048_BIT_MODP string = "DH_2048_BIT_MODP"
)

var (
	dhString map[uint16]func(uint16, uint16, []byte) string
	dhTypes  map[string]DHType
)

func init() {
	// Initialize DH String map
	dhString = map[uint16]func(uint16, uint16, []byte) string{
		message.DH_1024_BIT_MODP: toString_DH_1024_BIT_MODP,
		message.DH_2048_BIT_MODP: toString_DH_2048_BIT_MODP,
	}

	// Initialize DH Types map
	dhTypes = make(map[string]DHType)

	// Group 2: Dh1024BitModp
	prime1024, ok := new(big.Int).SetString(Group2PrimeString, 16)
	if !ok {
		logger.IKELog.Errorln("IKE Diffie Hellman Group 2 failed to init")
		return
	}
	dhTypes[DH_1024_BIT_MODP] = &Dh1024BitModp{
		prime:            prime1024,
		generator:        new(big.Int).SetUint64(Group2Generator),
		primeBytesLength: len(prime1024.Bytes()),
	}

	// Group 14: DH2048BitModp
	prime2048, ok := new(big.Int).SetString(Group14PrimeString, 16)
	if !ok {
		logger.IKELog.Errorln("IKE Diffie Hellman Group 14 failed to init")
		return
	}
	dhTypes[DH_2048_BIT_MODP] = &DH2048BitModp{
		prime:            prime2048,
		generator:        new(big.Int).SetUint64(Group14Generator),
		primeBytesLength: len(prime2048.Bytes()),
	}
}

// StrToType returns the DHType for a given algorithm string
func StrToType(algo string) DHType {
	return dhTypes[algo]
}

// DecodeTransform decodes a message.Transform to a DHType
func DecodeTransform(transform *message.Transform) DHType {
	f, ok := dhString[transform.TransformID]
	if !ok {
		return nil
	}
	s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
	if s == "" {
		return nil
	}
	return dhTypes[s]
}

// ToTransform converts a DHType to a message.Transform
func ToTransform(dhType DHType) *message.Transform {
	t := &message.Transform{
		TransformType: message.TypeDiffieHellmanGroup,
		TransformID:   dhType.TransformID(),
	}
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = dhType.getAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = message.AttributeFormatUseTV
	}
	return t
}

// DHType interface for Diffie-Hellman groups
type DHType interface {
	TransformID() uint16
	getAttribute() (bool, uint16, uint16, []byte)
	GetSharedKey(secret, peerPublicValue *big.Int) []byte
	GetPublicValue(secret *big.Int) []byte
}
