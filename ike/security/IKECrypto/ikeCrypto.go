// Copyright 2021 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

// Package crypto provides interfaces for IKE cryptographic operations.

package crypto

// IKECrypto defines methods for encryption and decryption used in IKE.
type IKECrypto interface {
	// Encrypt encrypts the given plainText and returns the cipherText or an error.
	Encrypt(plainText []byte) ([]byte, error)
	// Decrypt decrypts the given cipherText and returns the plainText or an error.
	Decrypt(cipherText []byte) ([]byte, error)
}
