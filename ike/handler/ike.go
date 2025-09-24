// SPDX-FileCopyrightText: 2025 Intel Corporation
// Copyright 2021 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"hash"

	"github.com/omec-project/n3iwf/ike/message"
	"github.com/omec-project/n3iwf/ike/security"
)

func EncodeEncrypt(ikeMsg *message.IKEMessage, ikesaKey *security.IKESAKey, role message.Role) ([]byte, error) {
	if ikesaKey != nil {
		if err := encryptMsg(ikeMsg, ikesaKey, role); err != nil {
			return nil, fmt.Errorf("IKE encode encrypt: %w", err)
		}
	}
	msg, err := ikeMsg.Encode()
	if err != nil {
		return nil, fmt.Errorf("IKE encode: %w", err)
	}
	return msg, nil
}

// Decode and decrypt IKE message
func DecodeDecrypt(msg []byte, ikeHeader *message.IKEHeader, ikesaKey *security.IKESAKey, role message.Role) (*message.IKEMessage, error) {
	ikeMsg := new(message.IKEMessage)
	var err error

	if ikeHeader == nil {
		err = ikeMsg.Decode(msg)
	} else {
		ikeMsg.IKEHeader = ikeHeader
		err = ikeMsg.DecodePayload(msg[message.IKE_HEADER_LEN:])
	}
	if err != nil {
		return nil, fmt.Errorf("DecodeDecrypt(): %w", err)
	}

	if len(ikeMsg.Payloads) > 0 && ikeMsg.Payloads[0].Type() == message.TypeSK {
		if ikesaKey == nil {
			return nil, errors.New("IKE decode decrypt: need ikesaKey to decrypt")
		}
		ikeMsg, err = decryptMsg(msg, ikeMsg, ikesaKey, role)
		if err != nil {
			return nil, fmt.Errorf("IKE decode decrypt: %w", err)
		}
	}
	return ikeMsg, nil
}

func verifyIntegrity(originData, checksum []byte, ikesaKey *security.IKESAKey, role message.Role) error {
	expectChecksum, err := calculateIntegrity(ikesaKey, role, originData)
	if err != nil {
		return fmt.Errorf("verifyIntegrity[%d]: %w", ikesaKey.IntegInfo.TransformID(), err)
	}
	if !hmac.Equal(checksum, expectChecksum) {
		return errors.New("invalid checksum")
	}
	return nil
}

func calculateIntegrity(ikesaKey *security.IKESAKey, role message.Role, originData []byte) ([]byte, error) {
	outputLen := ikesaKey.IntegInfo.GetOutputLength()
	var mac hash.Hash
	if role == message.Role_Initiator {
		mac = ikesaKey.Integ_i
	} else {
		mac = ikesaKey.Integ_r
	}
	if mac == nil {
		return nil, errors.New("CalcIKEChecksum(): integrity key is nil")
	}
	mac.Reset()
	if _, err := mac.Write(originData); err != nil {
		return nil, fmt.Errorf("CalcIKEChecksum(): %w", err)
	}
	return mac.Sum(nil)[:outputLen], nil
}

func encryptPayload(plainText []byte, ikesaKey *security.IKESAKey, role message.Role) ([]byte, error) {
	if role == message.Role_Initiator {
		return ikesaKey.Encr_i.Encrypt(plainText)
	}
	return ikesaKey.Encr_r.Encrypt(plainText)
}

func decryptPayload(cipherText []byte, ikesaKey *security.IKESAKey, role message.Role) ([]byte, error) {
	if role == message.Role_Initiator {
		return ikesaKey.Encr_r.Decrypt(cipherText)
	}
	return ikesaKey.Encr_i.Decrypt(cipherText)
}

func decryptMsg(msg []byte, ikeMsg *message.IKEMessage, ikesaKey *security.IKESAKey, role message.Role) (*message.IKEMessage, error) {
	// Parameter checks
	if ikesaKey == nil || msg == nil || ikeMsg == nil || ikesaKey.IntegInfo == nil || ikesaKey.EncrInfo == nil || ikesaKey.Integ_i == nil || ikesaKey.Encr_i == nil {
		return nil, errors.New("decryptMsg(): missing required context or keys")
	}

	var encryptedPayload *message.Encrypted
	for _, ikePayload := range ikeMsg.Payloads {
		if ikePayload.Type() == message.TypeSK {
			encryptedPayload = ikePayload.(*message.Encrypted)
			break
		}
	}
	if encryptedPayload == nil {
		return nil, errors.New("decryptMsg(): SK payload not found")
	}

	checksumLength := ikesaKey.IntegInfo.GetOutputLength()
	dataLen := len(encryptedPayload.EncryptedData)
	if dataLen < checksumLength {
		return nil, errors.New("decryptMsg(): encrypted data too short for checksum")
	}
	checksum := encryptedPayload.EncryptedData[dataLen-checksumLength:]
	if err := verifyIntegrity(msg[:len(msg)-checksumLength], checksum, ikesaKey, !role); err != nil {
		return nil, fmt.Errorf("decryptMsg(): verify integrity: %w", err)
	}

	plainText, err := decryptPayload(encryptedPayload.EncryptedData[:dataLen-checksumLength], ikesaKey, role)
	if err != nil {
		return nil, fmt.Errorf("decryptMsg(): Error decrypting message: %w", err)
	}

	var decryptedPayloads message.IKEPayloadContainer
	if err := decryptedPayloads.Decode(encryptedPayload.NextPayload, plainText); err != nil {
		return nil, fmt.Errorf("decryptMsg(): Decoding decrypted payload failed: %w", err)
	}
	ikeMsg.Payloads.Reset()
	ikeMsg.Payloads = append(ikeMsg.Payloads, decryptedPayloads...)
	return ikeMsg, nil
}

func encryptMsg(ikeMsg *message.IKEMessage, ikesaKey *security.IKESAKey, role message.Role) error {
	if ikeMsg == nil || ikesaKey == nil || ikesaKey.IntegInfo == nil || ikesaKey.EncrInfo == nil || ikesaKey.Integ_r == nil || ikesaKey.Encr_r == nil {
		return errors.New("encryptMsg(): missing required context or keys")
	}
	ikePayloads := ikeMsg.Payloads
	checksumLength := ikesaKey.IntegInfo.GetOutputLength()

	plainTextPayload, err := ikePayloads.Encode()
	if err != nil {
		return fmt.Errorf("encryptMsg(): Encoding IKE payload failed: %w", err)
	}
	encryptedData, err := encryptPayload(plainTextPayload, ikesaKey, role)
	if err != nil {
		return fmt.Errorf("encryptMsg(): Error encrypting message: %w", err)
	}
	encryptedData = append(encryptedData, make([]byte, checksumLength)...) // reserve space for checksum
	ikeMsg.Payloads.Reset()

	var encrNextPayloadType message.IKEPayloadType
	if len(ikePayloads) == 0 {
		encrNextPayloadType = message.NoNext
	} else {
		encrNextPayloadType = ikePayloads[0].Type()
	}
	sk := ikeMsg.Payloads.BuildEncrypted(encrNextPayloadType, encryptedData)

	ikeMsgData, err := ikeMsg.Encode()
	if err != nil {
		return fmt.Errorf("encryptMsg(): Encoding IKE message error: %w", err)
	}
	checksumOfMessage, err := calculateIntegrity(ikesaKey, role, ikeMsgData[:len(ikeMsgData)-checksumLength])
	if err != nil {
		return fmt.Errorf("encryptMsg(): Error calculating checksum: %w", err)
	}
	copy(sk.EncryptedData[len(sk.EncryptedData)-checksumLength:], checksumOfMessage)
	return nil
}
