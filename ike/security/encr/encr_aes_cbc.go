// Copyright 2021 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package encr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"math"

	"github.com/omec-project/n3iwf/ike/message"
	ikeCrypto "github.com/omec-project/n3iwf/ike/security/IKECrypto"
)

const (
	ENCR_AES_CBC_128 string = "ENCR_AES_CBC_128"
	ENCR_AES_CBC_192 string = "ENCR_AES_CBC_192"
	ENCR_AES_CBC_256 string = "ENCR_AES_CBC_256"
)

func toString_ENCR_AES_CBC(attrType uint16, intValue uint16, bytesValue []byte) string {
	if attrType != message.AttributeTypeKeyLength {
		return ""
	}
	switch intValue {
	case 128:
		return ENCR_AES_CBC_128
	case 192:
		return ENCR_AES_CBC_192
	case 256:
		return ENCR_AES_CBC_256
	default:
		return ""
	}
}

var _ ENCRType = &EncrAesCbc{}

type EncrAesCbc struct {
	keyLength int
}

func (t *EncrAesCbc) TransformID() uint16 {
	return message.ENCR_AES_CBC
}

func (t *EncrAesCbc) getAttribute() (bool, uint16, uint16, []byte, error) {
	keyLengthBits := t.keyLength * 8
	if keyLengthBits <= 0 || keyLengthBits > math.MaxUint16 {
		return false, 0, 0, nil, fmt.Errorf("key length exceeds uint16 maximum value: %v", keyLengthBits)
	}
	return true, message.AttributeTypeKeyLength, uint16(keyLengthBits), nil, nil
}

func (t *EncrAesCbc) GetKeyLength() int {
	return t.keyLength
}

func (t *EncrAesCbc) NewCrypto(key []byte) (ikeCrypto.IKECrypto, error) {
	if len(key) != t.keyLength {
		return nil, fmt.Errorf("EncrAesCbc init error: unexpected key length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("EncrAesCbc init: failed to create cipher: %v", err)
	}
	return &EncrAesCbcCrypto{Block: block}, nil
}

var _ ikeCrypto.IKECrypto = &EncrAesCbcCrypto{}

type EncrAesCbcCrypto struct {
	Block   cipher.Block
	Iv      []byte // initialization vector
	Padding []byte
}

func (encr *EncrAesCbcCrypto) Encrypt(plainText []byte) ([]byte, error) {
	// Apply PKCS7 padding if not set
	if encr.Padding == nil {
		var err error
		plainText, err = pkcs7Pad(plainText, aes.BlockSize)
		if err != nil {
			return nil, fmt.Errorf("Encrypt: %v", err)
		}
	} else {
		plainText = append(plainText, encr.Padding...)
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if encr.Iv == nil {
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, fmt.Errorf("Encrypt: failed to read IV: %v", err)
		}
	} else {
		copy(iv, encr.Iv)
	}

	cbc := cipher.NewCBCEncrypter(encr.Block, iv)
	cbc.CryptBlocks(cipherText[aes.BlockSize:], plainText)
	return cipherText, nil
}

func pkcs7Pad(data []byte, blockSize int) ([]byte, error) {
	padLen := blockSize - (len(data) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}
	padding := make([]byte, padLen)
	if _, err := rand.Read(padding); err != nil {
		return nil, fmt.Errorf("pkcs7Pad: %v", err)
	}
	for i := 0; i < padLen-1; i++ {
		padding[i] = byte(int(padding[i]) % (math.MaxUint8 + 1))
	}
	padding[padLen-1] = byte(padLen - 1)
	return append(data, padding...), nil
}

func (encr *EncrAesCbcCrypto) Decrypt(cipherText []byte) ([]byte, error) {
	if len(cipherText) < aes.BlockSize {
		return nil, fmt.Errorf("Decrypt: cipher text too short")
	}
	iv := cipherText[:aes.BlockSize]
	if encr.Iv != nil {
		iv = encr.Iv
	}
	encMsg := cipherText[aes.BlockSize:]
	if len(encMsg)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("Decrypt: cipher text not multiple of block size")
	}
	plainText := make([]byte, len(encMsg))
	cbc := cipher.NewCBCDecrypter(encr.Block, iv)
	cbc.CryptBlocks(plainText, encMsg)
	if len(plainText) == 0 {
		return nil, fmt.Errorf("Decrypt: plain text empty after decryption")
	}
	padLen := int(plainText[len(plainText)-1]) + 1
	if padLen > len(plainText) {
		return nil, fmt.Errorf("Decrypt: invalid padding")
	}
	return plainText[:len(plainText)-padLen], nil
}
