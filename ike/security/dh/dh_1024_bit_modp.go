// Copyright 2021 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package dh

import (
	"math/big"

	"github.com/omec-project/n3iwf/ike/message"
)

// Group2PrimeString is the 1024-bit MODP prime for DH Group 2
const (
	Group2PrimeString string = "FFFFFFFFFFFFFFFFC90FDAA22168C234" +
		"C4C6628B80DC1CD129024E088A67CC74" +
		"020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F1437" +
		"4FE1356D6D51C245E485B576625E7EC6" +
		"F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE6" +
		"49286651ECE65381FFFFFFFFFFFFFFFF"
	Group2Generator = 2
)

// toString_DH_1024_BIT_MODP returns the string identifier for DH Group 2
func toString_DH_1024_BIT_MODP(attrType uint16, intValue uint16, bytesValue []byte) string {
	return DH_1024_BIT_MODP
}

var _ DHType = &Dh1024BitModp{}

// Dh1024BitModp implements DH Group 2 (1024-bit MODP)
type Dh1024BitModp struct {
	prime            *big.Int // The prime modulus
	generator        *big.Int // The generator
	primeBytesLength int      // Length of prime in bytes
}

// TransformID returns the transform ID for DH Group 2
func (d *Dh1024BitModp) TransformID() uint16 {
	return message.DH_1024_BIT_MODP
}

// getAttribute returns DH attributes (none for Group 2)
func (d *Dh1024BitModp) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

// GetSharedKey computes the shared secret given the peer's public value and local secret
func (d *Dh1024BitModp) GetSharedKey(secret, peerPublicValue *big.Int) []byte {
	sharedKey := new(big.Int).Exp(peerPublicValue, secret, d.prime).Bytes()
	// Prepend zeros to match the prime length
	prependZero := make([]byte, d.primeBytesLength-len(sharedKey))
	sharedKey = append(prependZero, sharedKey...)
	return sharedKey
}

// GetPublicValue computes the public value to send to the peer
func (d *Dh1024BitModp) GetPublicValue(secret *big.Int) []byte {
	publicValue := new(big.Int).Exp(d.generator, secret, d.prime).Bytes()
	// Prepend zeros to match the prime length
	prependZero := make([]byte, d.primeBytesLength-len(publicValue))
	publicValue = append(prependZero, publicValue...)
	return publicValue
}
