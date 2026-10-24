// Copyright 2021 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package dh

import (
	"errors"
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
	// ValidatePeerPublicValue checks the peer's public value as received on the wire
	ValidatePeerPublicValue(peerPublicValue []byte) error
}

// validatePublicValue checks that the value is exactly as long as the prime (RFC 7296
// section 3.4) and lies in the range 1 < y < p-1 (RFC 6989 section 2.1); 0, 1 and p-1 would
// yield a predictable shared secret.
func validatePublicValue(raw []byte, prime *big.Int, primeBytesLength int) error {
	if len(raw) != primeBytesLength {
		return errors.New("DH public value length does not match the group")
	}
	y := new(big.Int).SetBytes(raw)
	pMinusOne := new(big.Int).Sub(prime, big.NewInt(1))
	if y.Cmp(big.NewInt(1)) <= 0 || y.Cmp(pMinusOne) >= 0 {
		return errors.New("DH public value out of range")
	}
	return nil
}
