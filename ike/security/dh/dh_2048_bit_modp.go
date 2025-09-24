// Copyright 2021 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package dh

import (
	"math/big"

	"github.com/omec-project/n3iwf/ike/message"
)

const (
	// Parameters
	Group14PrimeString string = "FFFFFFFFFFFFFFFFC90FDAA22168C234" +
		"C4C6628B80DC1CD129024E088A67CC74" +
		"020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F1437" +
		"4FE1356D6D51C245E485B576625E7EC6" +
		"F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE6" +
		"49286651ECE45B3DC2007CB8A163BF05" +
		"98DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB" +
		"9ED529077096966D670C354E4ABC9804" +
		"F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28F" +
		"B5C55DF06F4C52C9DE2BCBF695581718" +
		"3995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"
	Group14Generator = 2
)

func toString_DH_2048_BIT_MODP(attrType uint16, intValue uint16, bytesValue []byte) string {
	return DH_2048_BIT_MODP
}

var _ DHType = &DH2048BitModp{}

type DH2048BitModp struct {
	prime            *big.Int
	generator        *big.Int
	primeBytesLength int
}

func (t *DH2048BitModp) TransformID() uint16 {
	return message.DH_2048_BIT_MODP
}

func (d *DH2048BitModp) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

// GetSharedKey computes the shared secret given peer's public value and our secret
func (d *DH2048BitModp) GetSharedKey(secret, peerPublicValue *big.Int) []byte {
	shared := new(big.Int).Exp(peerPublicValue, secret, d.prime).Bytes()
	if len(shared) < d.primeBytesLength {
		pad := make([]byte, d.primeBytesLength-len(shared))
		shared = append(pad, shared...)
	}
	return shared
}

// GetPublicValue computes our public value given our secret
func (d *DH2048BitModp) GetPublicValue(secret *big.Int) []byte {
	pub := new(big.Int).Exp(d.generator, secret, d.prime).Bytes()
	if len(pub) < d.primeBytesLength {
		pad := make([]byte, d.primeBytesLength-len(pub))
		pub = append(pad, pub...)
	}
	return pub
}
