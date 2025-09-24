// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/omec-project/n3iwf/logger"
)

type IKEMessage struct {
	*IKEHeader
	Payloads IKEPayloadContainer
}

func NewMessage(
	iSPI, rSPI uint64, exchgType uint8,
	response, initiator bool, mId uint32,
	payloads IKEPayloadContainer,
) *IKEMessage {
	ikeMessage := &IKEMessage{
		IKEHeader: NewHeader(iSPI, rSPI, exchgType,
			response, initiator, mId, NoNext, nil),
		Payloads: payloads,
	}
	return ikeMessage
}

func (ikeMessage *IKEMessage) Encode() ([]byte, error) {
	logger.IKELog.Debugln("encoding IKE message")
	if len(ikeMessage.Payloads) > 0 {
		ikeMessage.IKEHeader.NextPayload = ikeMessage.Payloads[0].Type()
	} else {
		ikeMessage.IKEHeader.NextPayload = NoNext
	}

	var err error
	ikeMessage.IKEHeader.PayloadBytes, err = ikeMessage.Payloads.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode payload failed: %w", err)
	}
	return ikeMessage.IKEHeader.Marshal()
}

func (ikeMessage *IKEMessage) Decode(rawData []byte) error {
	// IKE message packet format this implementation referenced is
	// defined in RFC 7296, Section 3.1
	logger.IKELog.Debugln("decoding IKE message")
	var err error
	ikeMessage.IKEHeader, err = ParseHeader(rawData)
	if err != nil {
		return fmt.Errorf("Decode(): %w", err)
	}

	err = ikeMessage.DecodePayload(ikeMessage.PayloadBytes)
	if err != nil {
		return fmt.Errorf("decode payload failed: %v", err)
	}

	return nil
}

func (ikeMessage *IKEMessage) DecodePayload(rawData []byte) error {
	err := ikeMessage.Payloads.Decode(ikeMessage.NextPayload, rawData)
	if err != nil {
		return fmt.Errorf("decode payload failed: %+v", err)
	}

	return nil
}

type IKEPayloadContainer []IKEPayload

// Helper function for bounds checking
func checkLen(data []byte, minLen int, errMsg string) error {
	if len(data) < minLen {
		return errors.New(errMsg)
	}
	return nil
}

// Helper function for appending bytes efficiently
func appendBytes(dst *[]byte, src []byte) {
	*dst = append(*dst, src...)
}

func (container *IKEPayloadContainer) Encode() ([]byte, error) {
	logger.IKELog.Debugln("encoding IKE payloads")

	ikeMessagePayloadData := make([]byte, 0)

	for index, payload := range *container {
		payloadData := make([]byte, 4)     // IKE payload general header
		if (index + 1) < len(*container) { // if it has next payload
			payloadData[0] = uint8((*container)[index+1].Type())
		} else {
			if payload.Type() == TypeSK {
				payloadData[0] = byte(payload.(*Encrypted).NextPayload)
			} else {
				payloadData[0] = byte(NoNext)
			}
		}

		data, err := payload.marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal payload: %+v", err)
		}

		payloadData = append(payloadData, data...)
		payloadDataLen := len(payloadData)
		if payloadDataLen > math.MaxUint16 {
			return nil, fmt.Errorf("payloadData length exceeds uint16 limit: %d", payloadDataLen)
		}
		binary.BigEndian.PutUint16(payloadData[2:4], uint16(payloadDataLen))

		appendBytes(&ikeMessagePayloadData, payloadData)
	}

	return ikeMessagePayloadData, nil
}

func (container *IKEPayloadContainer) Decode(nextPayload IKEPayloadType, rawData []byte) error {
	logger.IKELog.Debugln("decoding IKE payloads")

	for len(rawData) > 0 {
		// bounds checking
		logger.IKELog.Debugln("decode 1 payload")
		if err := checkLen(rawData, 4, "no sufficient bytes to decode next payload"); err != nil {
			return err
		}
		payloadLength := binary.BigEndian.Uint16(rawData[2:4])
		if payloadLength < 4 {
			return fmt.Errorf("illegal payload length %d < header length 4", payloadLength)
		}
		if err := checkLen(rawData, int(payloadLength), "the length of received message not match the length specified in header"); err != nil {
			return err
		}

		criticalBit := (rawData[1] & 0x80) >> 7

		var payload IKEPayload

		switch nextPayload {
		case TypeSA:
			payload = new(SecurityAssociation)
		case TypeKE:
			payload = new(KeyExchange)
		case TypeIDi:
			payload = new(IdentificationInitiator)
		case TypeIDr:
			payload = new(IdentificationResponder)
		case TypeCERT:
			payload = new(Certificate)
		case TypeCERTreq:
			payload = new(CertificateRequest)
		case TypeAUTH:
			payload = new(Authentication)
		case TypeNiNr:
			payload = new(Nonce)
		case TypeN:
			payload = new(Notification)
		case TypeD:
			payload = new(Delete)
		case TypeV:
			payload = new(VendorID)
		case TypeTSi:
			payload = new(TrafficSelectorInitiator)
		case TypeTSr:
			payload = new(TrafficSelectorResponder)
		case TypeSK:
			encryptedPayload := new(Encrypted)
			encryptedPayload.NextPayload = IKEPayloadType(rawData[0])
			payload = encryptedPayload
		case TypeCP:
			payload = new(Configuration)
		case TypeEAP:
			payload = new(EAP)
		default:
			if criticalBit != 0 {
				// TODO: Reject this IKE message
				return fmt.Errorf("unknown payload type: %d", nextPayload)
			}
			// Skip this payload
			nextPayload = IKEPayloadType(rawData[0])
			rawData = rawData[payloadLength:]
			continue
		}

		if err := payload.unmarshal(rawData[4:payloadLength]); err != nil {
			return fmt.Errorf("unmarshal payload failed: %+v", err)
		}

		*container = append(*container, payload)

		nextPayload = IKEPayloadType(rawData[0])
		rawData = rawData[payloadLength:]
	}

	return nil
}

type IKEPayload interface {
	// Type specifies the IKE payload types
	Type() IKEPayloadType

	// Called by Encode() or Decode()
	marshal() ([]byte, error)
	unmarshal(rawData []byte) error
}

// Definition of Security Association
var _ IKEPayload = &SecurityAssociation{}

type SecurityAssociation struct {
	Proposals ProposalContainer
}

type ProposalContainer []*Proposal

type Proposal struct {
	ProposalNumber          uint8
	ProtocolID              uint8
	SPI                     []byte
	EncryptionAlgorithm     TransformContainer
	PseudorandomFunction    TransformContainer
	IntegrityAlgorithm      TransformContainer
	DiffieHellmanGroup      TransformContainer
	ExtendedSequenceNumbers TransformContainer
}

type TransformContainer []*Transform

type Transform struct {
	TransformType                uint8
	TransformID                  uint16
	AttributePresent             bool
	AttributeFormat              uint8
	AttributeType                uint16
	AttributeValue               uint16
	VariableLengthAttributeValue []byte
}

func (securityAssociation *SecurityAssociation) Type() IKEPayloadType { return TypeSA }

func (securityAssociation *SecurityAssociation) marshal() ([]byte, error) {
	logger.IKELog.Debugln("start marshalling")

	securityAssociationData := make([]byte, 0)

	for proposalIndex, proposal := range securityAssociation.Proposals {
		proposalData := make([]byte, 8)

		if (proposalIndex + 1) < len(securityAssociation.Proposals) {
			proposalData[0] = 2
		} else {
			proposalData[0] = 0
		}

		proposalData[4] = proposal.ProposalNumber
		proposalData[5] = proposal.ProtocolID

		numberofSPI := len(proposal.SPI)
		if numberofSPI > math.MaxUint8 {
			return nil, fmt.Errorf("proposal: Too many SPI: %d", numberofSPI)
		}
		proposalData[6] = uint8(numberofSPI)
		if len(proposal.SPI) > 0 {
			proposalData = append(proposalData, proposal.SPI...)
		}

		// combine all transforms
		var transformList []*Transform
		transformList = append(transformList, proposal.EncryptionAlgorithm...)
		transformList = append(transformList, proposal.PseudorandomFunction...)
		transformList = append(transformList, proposal.IntegrityAlgorithm...)
		transformList = append(transformList, proposal.DiffieHellmanGroup...)
		transformList = append(transformList, proposal.ExtendedSequenceNumbers...)

		if len(transformList) == 0 {
			return nil, errors.New("one proposal has no any transform")
		}

		transformListCount := len(transformList)
		if transformListCount > math.MaxUint8 {
			return nil, fmt.Errorf("transform: Too many transform: %d", transformListCount)
		}
		proposalData[7] = uint8(transformListCount)

		proposalTransformData := make([]byte, 0)

		for transformIndex, transform := range transformList {
			transformData := make([]byte, 8)

			if (transformIndex + 1) < len(transformList) {
				transformData[0] = 3
			} else {
				transformData[0] = 0
			}

			transformData[4] = transform.TransformType
			binary.BigEndian.PutUint16(transformData[6:8], transform.TransformID)

			if transform.AttributePresent {
				attributeData := make([]byte, 4)

				if transform.AttributeFormat == 0 {
					// TLV
					if len(transform.VariableLengthAttributeValue) == 0 {
						return nil, errors.New("attribute of one transform not specified")
					}
					attributeFormatAndType := ((uint16(transform.AttributeFormat) & 0x1) << 15) | transform.AttributeType
					binary.BigEndian.PutUint16(attributeData[0:2], attributeFormatAndType)
					variableLen := len(transform.VariableLengthAttributeValue)
					if variableLen > math.MaxUint16 {
						return nil, fmt.Errorf("variableLengthAttributeValue length exceeds uint16 limit: %d", variableLen)
					}
					binary.BigEndian.PutUint16(attributeData[2:4], uint16(variableLen))
					attributeData = append(attributeData, transform.VariableLengthAttributeValue...)
				} else {
					// TV
					attributeFormatAndType := ((uint16(transform.AttributeFormat) & 0x1) << 15) | transform.AttributeType
					binary.BigEndian.PutUint16(attributeData[0:2], attributeFormatAndType)
					binary.BigEndian.PutUint16(attributeData[2:4], transform.AttributeValue)
				}

				transformData = append(transformData, attributeData...)
			}
			transformDataLen := len(transformData)
			if transformDataLen > math.MaxUint16 {
				return nil, fmt.Errorf("transform data length exceeds uint16 limit: %d", transformDataLen)
			}
			binary.BigEndian.PutUint16(transformData[2:4], uint16(transformDataLen))

			proposalTransformData = append(proposalTransformData, transformData...)
		}

		proposalData = append(proposalData, proposalTransformData...)
		proposalDataLen := len(proposalData)
		if proposalDataLen > math.MaxUint16 {
			return nil, fmt.Errorf("proposal data length exceeds uint16 limit: %d", proposalDataLen)
		}
		binary.BigEndian.PutUint16(proposalData[2:4], uint16(proposalDataLen))

		securityAssociationData = append(securityAssociationData, proposalData...)
	}

	return securityAssociationData, nil
}

func (securityAssociation *SecurityAssociation) unmarshal(rawData []byte) error {
	logger.IKELog.Debugln("start unmarshalling received bytes")
	logger.IKELog.Debugf("payload length %d bytes", len(rawData))

	for len(rawData) > 0 {
		logger.IKELog.Debugln("unmarshal 1 proposal")
		// bounds checking
		if err := checkLen(rawData, 8, "no sufficient bytes to decode next proposal"); err != nil {
			return err
		}
		proposalLength := binary.BigEndian.Uint16(rawData[2:4])
		if proposalLength < 8 {
			return fmt.Errorf("illegal payload length %d < header length 8", proposalLength)
		}
		if err := checkLen(rawData, int(proposalLength), "length of received message not match the length specified in header"); err != nil {
			return err
		}

		// Log whether this proposal is the last
		if rawData[0] == 0 {
			logger.IKELog.Debugln("this proposal is the last")
		}
		// Log the number of transform in the proposal
		logger.IKELog.Debugf("this proposal contained %d transform", rawData[7])

		proposal := new(Proposal)
		var transformData []byte

		proposal.ProposalNumber = rawData[4]
		proposal.ProtocolID = rawData[5]

		spiSize := rawData[6]
		if spiSize > 0 {
			// bounds checking
			if err := checkLen(rawData, int(8+spiSize), "no sufficient bytes for unmarshalling SPI of proposal"); err != nil {
				return err
			}
			proposal.SPI = append(proposal.SPI, rawData[8:8+spiSize]...)
		}

		transformData = rawData[8+spiSize : proposalLength]

		for len(transformData) > 0 {
			// bounds checking
			logger.IKELog.Debugln("unmarshal 1 transform")
			if err := checkLen(transformData, 8, "no sufficient bytes to decode next transform"); err != nil {
				return err
			}
			transformLength := binary.BigEndian.Uint16(transformData[2:4])
			if transformLength < 8 {
				return fmt.Errorf("illegal payload length %d < header length 8", transformLength)
			}
			if err := checkLen(transformData, int(transformLength), "length of received message not match the length specified in header"); err != nil {
				return err
			}

			// Log whether this transform is the last
			if transformData[0] == 0 {
				logger.IKELog.Debugln("this transform is the last")
			}

			transform := new(Transform)

			transform.TransformType = transformData[4]
			transform.TransformID = binary.BigEndian.Uint16(transformData[6:8])
			if transformLength > 8 {
				transform.AttributePresent = true
				transform.AttributeFormat = ((transformData[8] & 0x80) >> 7)
				transform.AttributeType = binary.BigEndian.Uint16(transformData[8:10]) & 0x7f

				if transform.AttributeFormat == 0 {
					attributeLength := binary.BigEndian.Uint16(transformData[10:12])
					// bounds checking
					if (12 + attributeLength) != transformLength {
						return fmt.Errorf("illegal attribute length %d not satisfies the transform length %d",
							attributeLength, transformLength)
					}
					transform.VariableLengthAttributeValue = append(transform.VariableLengthAttributeValue, transformData[12:12+attributeLength]...)
				} else {
					transform.AttributeValue = binary.BigEndian.Uint16(transformData[10:12])
				}
			}

			switch transform.TransformType {
			case TypeEncryptionAlgorithm:
				proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, transform)
			case TypePseudorandomFunction:
				proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, transform)
			case TypeIntegrityAlgorithm:
				proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, transform)
			case TypeDiffieHellmanGroup:
				proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, transform)
			case TypeExtendedSequenceNumbers:
				proposal.ExtendedSequenceNumbers = append(proposal.ExtendedSequenceNumbers, transform)
			}

			transformData = transformData[transformLength:]
		}

		securityAssociation.Proposals = append(securityAssociation.Proposals, proposal)

		rawData = rawData[proposalLength:]
	}

	return nil
}

// Definition of Key Exchange
var _ IKEPayload = &KeyExchange{}

type KeyExchange struct {
	DiffieHellmanGroup uint16
	KeyExchangeData    []byte
}

func (keyExchange *KeyExchange) Type() IKEPayloadType { return TypeKE }

func (keyExchange *KeyExchange) marshal() ([]byte, error) {
	logger.IKELog.Debugln("start marshalling")

	keyExchangeData := make([]byte, 4)

	binary.BigEndian.PutUint16(keyExchangeData[0:2], keyExchange.DiffieHellmanGroup)
	keyExchangeData = append(keyExchangeData, keyExchange.KeyExchangeData...)

	return keyExchangeData, nil
}

func (keyExchange *KeyExchange) unmarshal(rawData []byte) error {
	logger.IKELog.Debugln("start unmarshalling received bytes")
	logger.IKELog.Debugf("payload length %d bytes", len(rawData))

	if len(rawData) > 0 {
		logger.IKELog.Debugln("unmarshal 1 key exchange data")
		// bounds checking
		if len(rawData) <= 4 {
			return errors.New("no sufficient bytes to decode next key exchange data")
		}

		keyExchange.DiffieHellmanGroup = binary.BigEndian.Uint16(rawData[0:2])
		keyExchange.KeyExchangeData = append(keyExchange.KeyExchangeData, rawData[4:]...)
	}

	return nil
}

// Definition of Identification - Initiator
var _ IKEPayload = &IdentificationInitiator{}

type IdentificationInitiator struct {
	IDType uint8
	IDData []byte
}

func (identification *IdentificationInitiator) Type() IKEPayloadType { return TypeIDi }

func (identification *IdentificationInitiator) marshal() ([]byte, error) {
	logger.IKELog.Debugln("start marshalling")

	identificationData := make([]byte, 4)

	identificationData[0] = identification.IDType
	identificationData = append(identificationData, identification.IDData...)

	return identificationData, nil
}

func (identification *IdentificationInitiator) unmarshal(rawData []byte) error {
	logger.IKELog.Debugln("start unmarshalling received bytes")
	logger.IKELog.Debugf("payload length %d bytes", len(rawData))

	if len(rawData) > 0 {
		logger.IKELog.Debugln("unmarshal 1 identification")
		// bounds checking
		if len(rawData) <= 4 {
			return errors.New("no sufficient bytes to decode next identification")
		}

		identification.IDType = rawData[0]
		identification.IDData = append(identification.IDData, rawData[4:]...)
	}

	return nil
}

// Definition of Identification - Responder
var _ IKEPayload = &IdentificationResponder{}

type IdentificationResponder struct {
	IDType uint8
	IDData []byte
}

func (identification *IdentificationResponder) Type() IKEPayloadType { return TypeIDr }

func (identification *IdentificationResponder) marshal() ([]byte, error) {
	logger.IKELog.Debugln("start marshalling")

	identificationData := make([]byte, 4)

	identificationData[0] = identification.IDType
	identificationData = append(identificationData, identification.IDData...)

	return identificationData, nil
}

func (identification *IdentificationResponder) unmarshal(rawData []byte) error {
	logger.IKELog.Debugln("start unmarshalling received bytes")
	logger.IKELog.Debugf("payload length %d bytes", len(rawData))

	if len(rawData) > 0 {
		logger.IKELog.Debugln("unmarshal 1 identification")
		// bounds checking
		if len(rawData) <= 4 {
			return errors.New("no sufficient bytes to decode next identification")
		}

		identification.IDType = rawData[0]
		identification.IDData = append(identification.IDData, rawData[4:]...)
	}

	return nil
}

// Definition of Certificate
var _ IKEPayload = &Certificate{}

type Certificate struct {
	CertificateEncoding uint8
	CertificateData     []byte
}

func (certificate *Certificate) Type() IKEPayloadType { return TypeCERT }

func (certificate *Certificate) marshal() ([]byte, error) {
	logger.IKELog.Debugln("start marshalling")

	certificateData := make([]byte, 1)

	certificateData[0] = certificate.CertificateEncoding
	certificateData = append(certificateData, certificate.CertificateData...)

	return certificateData, nil
}

func (certificate *Certificate) unmarshal(rawData []byte) error {
	logger.IKELog.Debugln("start unmarshalling received bytes")
	logger.IKELog.Debugf("payload length %d bytes", len(rawData))

	if len(rawData) > 0 {
		logger.IKELog.Debugln("unmarshal 1 certificate")
		// bounds checking
		if len(rawData) <= 1 {
			return errors.New("no sufficient bytes to decode next certificate")
		}

		certificate.CertificateEncoding = rawData[0]
		certificate.CertificateData = append(certificate.CertificateData, rawData[1:]...)
	}

	return nil
}

// Definition of Certificate Request
var _ IKEPayload = &CertificateRequest{}

type CertificateRequest struct {
	CertificateEncoding    uint8
	CertificationAuthority []byte
}

func (certificateRequest *CertificateRequest) Type() IKEPayloadType { return TypeCERTreq }

func (certificateRequest *CertificateRequest) marshal() ([]byte, error) {
	logger.IKELog.Debugln("start marshalling")

	certificateRequestData := make([]byte, 1)

	certificateRequestData[0] = certificateRequest.CertificateEncoding
	certificateRequestData = append(certificateRequestData, certificateRequest.CertificationAuthority...)

	return certificateRequestData, nil
}

func (certificateRequest *CertificateRequest) unmarshal(rawData []byte) error {
	logger.IKELog.Debugln("start unmarshalling received bytes")
	logger.IKELog.Debugf("payload length %d bytes", len(rawData))

	if len(rawData) > 0 {
		logger.IKELog.Debugln("unmarshal 1 certificate request")
		// bounds checking
		if len(rawData) <= 1 {
			return errors.New("no sufficient bytes to decode next certificate request")
		}

		certificateRequest.CertificateEncoding = rawData[0]
		certificateRequest.CertificationAuthority = append(certificateRequest.CertificationAuthority, rawData[1:]...)
	}

	return nil
}

// Definition of Authentication
var _ IKEPayload = &Authentication{}

type Authentication struct {
	AuthenticationMethod uint8
	AuthenticationData   []byte
}

func (authentication *Authentication) Type() IKEPayloadType { return TypeAUTH }

func (authentication *Authentication) marshal() ([]byte, error) {
	logger.IKELog.Debugln("start marshalling")

	authenticationData := make([]byte, 4)

	authenticationData[0] = authentication.AuthenticationMethod
	authenticationData = append(authenticationData, authentication.AuthenticationData...)

	return authenticationData, nil
}

func (authentication *Authentication) unmarshal(rawData []byte) error {
	logger.IKELog.Debugln("start unmarshalling received bytes")
	logger.IKELog.Debugf("payload length %d bytes", len(rawData))

	if len(rawData) > 0 {
		logger.IKELog.Debugln("unmarshal 1 authentication")
		// bounds checking
		if len(rawData) <= 4 {
			return errors.New("no sufficient bytes to decode next authentication")
		}

		authentication.AuthenticationMethod = rawData[0]
		authentication.AuthenticationData = append(authentication.AuthenticationData, rawData[4:]...)
	}

	return nil
}

// Definition of Nonce
var _ IKEPayload = &Nonce{}

type Nonce struct {
	NonceData []byte
}

func (nonce *Nonce) Type() IKEPayloadType { return TypeNiNr }

func (nonce *Nonce) marshal() ([]byte, error) {
	logger.IKELog.Debugln("start marshalling")

	nonceData := make([]byte, 0)
	nonceData = append(nonceData, nonce.NonceData...)

	return nonceData, nil
}

func (nonce *Nonce) unmarshal(rawData []byte) error {
	logger.IKELog.Debugln("start unmarshalling received bytes")
	logger.IKELog.Debugf("payload length %d bytes", len(rawData))

	if len(rawData) > 0 {
		logger.IKELog.Debugln("unmarshal 1 nonce")
		nonce.NonceData = append(nonce.NonceData, rawData...)
	}

	return nil
}

// Definition of Notification
var _ IKEPayload = &Notification{}

type Notification struct {
	ProtocolID        uint8
	NotifyMessageType uint16
	SPI               []byte
	NotificationData  []byte
}

func (notification *Notification) Type() IKEPayloadType { return TypeN }

func (notification *Notification) marshal() ([]byte, error) {
	logger.IKELog.Debugln("start marshalling")

	notificationData := make([]byte, 4)

	notificationData[0] = notification.ProtocolID
	numberofSPI := len(notification.SPI)
	if numberofSPI > math.MaxUint8 {
		return nil, fmt.Errorf("number of SPI exceeds uint8 limit: %d", numberofSPI)
	}
	notificationData[1] = uint8(numberofSPI)
	binary.BigEndian.PutUint16(notificationData[2:4], notification.NotifyMessageType)

	notificationData = append(notificationData, notification.SPI...)
	notificationData = append(notificationData, notification.NotificationData...)

	return notificationData, nil
}

func (notification *Notification) unmarshal(rawData []byte) error {
	logger.IKELog.Debugln("start unmarshalling received bytes")
	logger.IKELog.Debugf("payload length %d bytes", len(rawData))

	if len(rawData) > 0 {
		logger.IKELog.Debugln("unmarshal 1 notification")
		// bounds checking
		if len(rawData) < 4 {
			return errors.New("no sufficient bytes to decode next notification")
		}
		spiSize := rawData[1]
		if len(rawData) < int(4+spiSize) {
			return errors.New("no sufficient bytes to get SPI according to the length specified in header")
		}

		notification.ProtocolID = rawData[0]
		notification.NotifyMessageType = binary.BigEndian.Uint16(rawData[2:4])

		notification.SPI = append(notification.SPI, rawData[4:4+spiSize]...)
		notification.NotificationData = append(notification.NotificationData, rawData[4+spiSize:]...)
	}

	return nil
}

// Definition of Delete
var _ IKEPayload = &Delete{}

type Delete struct {
	ProtocolID  uint8
	SPISize     uint8
	NumberOfSPI uint16
	SPIs        []uint32
}

func (del *Delete) Type() IKEPayloadType { return TypeD }

func (del *Delete) marshal() ([]byte, error) {
	logger.IKELog.Debugln("start marshalling")

	if len(del.SPIs) != int(del.NumberOfSPI) {
		return nil, errors.New("number of SPI not correct")
	}

	deleteData := make([]byte, 4)

	deleteData[0] = del.ProtocolID
	deleteData[1] = del.SPISize
	binary.BigEndian.PutUint16(deleteData[2:4], del.NumberOfSPI)

	if int(del.NumberOfSPI) > 0 {
		byteSlice := make([]byte, del.SPISize)
		for _, v := range del.SPIs {
			binary.BigEndian.PutUint32(byteSlice, v)
			deleteData = append(deleteData, byteSlice...)
		}
	}

	return deleteData, nil
}

func (del *Delete) unmarshal(rawData []byte) error {
	logger.IKELog.Debugln("start unmarshalling received bytes")
	logger.IKELog.Debugf("payload length %d bytes", len(rawData))

	if len(rawData) > 0 {
		logger.IKELog.Debugln("unmarshal 1 delete")
		// bounds checking
		if len(rawData) <= 3 {
			return errors.New("no sufficient bytes to decode next delete")
		}
		spiSize := rawData[1]
		numberOfSPI := binary.BigEndian.Uint16(rawData[2:4])
		if len(rawData) < (4 + (int(spiSize) * int(numberOfSPI))) {
			return errors.New("no Sufficient bytes to get SPIs according to the length specified in header")
		}

		del.ProtocolID = rawData[0]
		del.SPISize = spiSize
		del.NumberOfSPI = numberOfSPI

		rawData = rawData[4:]
		var spi uint32
		for i := 0; i < len(rawData); i += 4 {
			spi = binary.BigEndian.Uint32(rawData[i : i+4])
			del.SPIs = append(del.SPIs, spi)
		}
	}

	return nil
}

// Definition of Vendor ID
var _ IKEPayload = &VendorID{}

type VendorID struct {
	VendorIDData []byte
}

func (vendorID *VendorID) Type() IKEPayloadType { return TypeV }

func (vendorID *VendorID) marshal() ([]byte, error) {
	logger.IKELog.Debugln("start marshalling")
	return vendorID.VendorIDData, nil
}

func (vendorID *VendorID) unmarshal(rawData []byte) error {
	logger.IKELog.Debugln("start unmarshalling received bytes")
	logger.IKELog.Debugf("payload length %d bytes", len(rawData))

	if len(rawData) > 0 {
		logger.IKELog.Debugln("unmarshal 1 vendor ID")
		vendorID.VendorIDData = append(vendorID.VendorIDData, rawData...)
	}

	return nil
}

// Definition of Traffic Selector - Initiator
var _ IKEPayload = &TrafficSelectorInitiator{}

type TrafficSelectorInitiator struct {
	TrafficSelectors IndividualTrafficSelectorContainer
}

type IndividualTrafficSelectorContainer []*IndividualTrafficSelector

type IndividualTrafficSelector struct {
	TSType       uint8
	IPProtocolID uint8
	StartPort    uint16
	EndPort      uint16
	StartAddress []byte
	EndAddress   []byte
}

func (trafficSelector *TrafficSelectorInitiator) Type() IKEPayloadType { return TypeTSi }

func (trafficSelector *TrafficSelectorInitiator) marshal() ([]byte, error) {
	logger.IKELog.Debugln("start marshalling")

	if len(trafficSelector.TrafficSelectors) == 0 {
		return nil, errors.New("contains no traffic selector for marshalling message")
	}

	trafficSelectorData := make([]byte, 4)
	selectorCount := len(trafficSelector.TrafficSelectors)

	if selectorCount > math.MaxUint8 {
		return nil, fmt.Errorf("too many traffic selectors: %d", selectorCount)
	}

	trafficSelectorData[0] = uint8(selectorCount)

	for _, individualTrafficSelector := range trafficSelector.TrafficSelectors {
		switch individualTrafficSelector.TSType {
		case TS_IPV4_ADDR_RANGE:
			// Address length checking
			logger.IKELog.Debugf("address length %d", len(individualTrafficSelector.StartAddress))
			if len(individualTrafficSelector.StartAddress) != 4 {
				return nil, errors.New("start IPv4 address length is not correct")
			}
			if len(individualTrafficSelector.EndAddress) != 4 {
				return nil, errors.New("end IPv4 address length is not correct")
			}

			individualTrafficSelectorData := make([]byte, 8)

			individualTrafficSelectorData[0] = individualTrafficSelector.TSType
			individualTrafficSelectorData[1] = individualTrafficSelector.IPProtocolID
			binary.BigEndian.PutUint16(individualTrafficSelectorData[4:6], individualTrafficSelector.StartPort)
			binary.BigEndian.PutUint16(individualTrafficSelectorData[6:8], individualTrafficSelector.EndPort)

			individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.StartAddress...)
			individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.EndAddress...)

			dataLen := len(individualTrafficSelectorData)
			if dataLen > math.MaxUint16 {
				return nil, fmt.Errorf("individualTrafficSelectorData length exceeds uint16 maximum value: %v", dataLen)
			}
			binary.BigEndian.PutUint16(individualTrafficSelectorData[2:4], uint16(dataLen))

			trafficSelectorData = append(trafficSelectorData, individualTrafficSelectorData...)
		case TS_IPV6_ADDR_RANGE:
			// Address length checking
			logger.IKELog.Debugf("address length %d", len(individualTrafficSelector.StartAddress))
			if len(individualTrafficSelector.StartAddress) != 16 {
				return nil, errors.New("start IPv6 address length is not correct")
			}
			if len(individualTrafficSelector.EndAddress) != 16 {
				return nil, errors.New("end IPv6 address length is not correct")
			}

			individualTrafficSelectorData := make([]byte, 8)

			individualTrafficSelectorData[0] = individualTrafficSelector.TSType
			individualTrafficSelectorData[1] = individualTrafficSelector.IPProtocolID
			binary.BigEndian.PutUint16(individualTrafficSelectorData[4:6], individualTrafficSelector.StartPort)
			binary.BigEndian.PutUint16(individualTrafficSelectorData[6:8], individualTrafficSelector.EndPort)

			individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.StartAddress...)
			individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.EndAddress...)

			dataLen := len(individualTrafficSelectorData)
			if dataLen > math.MaxUint16 {
				return nil, fmt.Errorf("individualTrafficSelectorData length exceeds uint16 maximum value: %v", dataLen)
			}
			binary.BigEndian.PutUint16(individualTrafficSelectorData[2:4], uint16(dataLen))

			trafficSelectorData = append(trafficSelectorData, individualTrafficSelectorData...)
		default:
			logger.IKELog.Errorf("unsupported traffic selector type %d", individualTrafficSelector.TSType)
			return nil, errors.New("unsupported traffic selector type")
		}
	}

	return trafficSelectorData, nil
}

func (trafficSelector *TrafficSelectorInitiator) unmarshal(rawData []byte) error {
	logger.IKELog.Debugln("start unmarshalling received bytes")
	logger.IKELog.Debugf("payload length %d bytes", len(rawData))

	if len(rawData) == 0 {
		return nil
	}

	logger.IKELog.Debugln("unmarshal 1 traffic selector")
	// bounds checking
	if len(rawData) < 4 {
		return errors.New("no sufficient bytes to get number of traffic selector in header")
	}

	numberOfSPI := rawData[0]

	rawData = rawData[4:]

	for ; numberOfSPI > 0; numberOfSPI-- {
		// bounds checking
		if len(rawData) < 4 {
			return errors.New("no sufficient bytes to decode next individual traffic selector length in header")
		}
		trafficSelectorType := rawData[0]
		switch trafficSelectorType {
		case TS_IPV4_ADDR_RANGE:
			selectorLength := binary.BigEndian.Uint16(rawData[2:4])
			if selectorLength != 16 {
				return errors.New("a TS_IPV4_ADDR_RANGE type traffic selector should has length 16 bytes")
			}
			if len(rawData) < int(selectorLength) {
				return errors.New("no sufficient bytes to decode next individual traffic selector")
			}

			individualTrafficSelector := &IndividualTrafficSelector{}

			individualTrafficSelector.TSType = rawData[0]
			individualTrafficSelector.IPProtocolID = rawData[1]
			individualTrafficSelector.StartPort = binary.BigEndian.Uint16(rawData[4:6])
			individualTrafficSelector.EndPort = binary.BigEndian.Uint16(rawData[6:8])

			individualTrafficSelector.StartAddress = append(individualTrafficSelector.StartAddress, rawData[8:12]...)
			individualTrafficSelector.EndAddress = append(individualTrafficSelector.EndAddress, rawData[12:16]...)

			trafficSelector.TrafficSelectors = append(trafficSelector.TrafficSelectors, individualTrafficSelector)

			rawData = rawData[16:]
		case TS_IPV6_ADDR_RANGE:
			selectorLength := binary.BigEndian.Uint16(rawData[2:4])
			if selectorLength != 40 {
				return errors.New("a TS_IPV6_ADDR_RANGE type traffic selector should has length 40 bytes")
			}
			if len(rawData) < int(selectorLength) {
				return errors.New("no sufficient bytes to decode next individual traffic selector")
			}

			individualTrafficSelector := &IndividualTrafficSelector{}

			individualTrafficSelector.TSType = rawData[0]
			individualTrafficSelector.IPProtocolID = rawData[1]
			individualTrafficSelector.StartPort = binary.BigEndian.Uint16(rawData[4:6])
			individualTrafficSelector.EndPort = binary.BigEndian.Uint16(rawData[6:8])

			individualTrafficSelector.StartAddress = append(individualTrafficSelector.StartAddress, rawData[8:24]...)
			individualTrafficSelector.EndAddress = append(individualTrafficSelector.EndAddress, rawData[24:40]...)

			trafficSelector.TrafficSelectors = append(trafficSelector.TrafficSelectors, individualTrafficSelector)

			rawData = rawData[40:]
		default:
			return errors.New("unsupported traffic selector type")
		}
	}
	return nil
}

// Definition of Traffic Selector - Responder
var _ IKEPayload = &TrafficSelectorResponder{}

type TrafficSelectorResponder struct {
	TrafficSelectors IndividualTrafficSelectorContainer
}

func (trafficSelector *TrafficSelectorResponder) Type() IKEPayloadType { return TypeTSr }

func (trafficSelector *TrafficSelectorResponder) marshal() ([]byte, error) {
	logger.IKELog.Debugln("start marshalling")

	if len(trafficSelector.TrafficSelectors) == 0 {
		return nil, errors.New("contains no traffic selector for marshalling message")
	}
	trafficSelectorData := make([]byte, 4)
	selectorCount := len(trafficSelector.TrafficSelectors)

	if selectorCount > math.MaxUint8 {
		return nil, fmt.Errorf("too many traffic selectors: %d", selectorCount)
	}

	trafficSelectorData[0] = uint8(selectorCount)

	for _, individualTrafficSelector := range trafficSelector.TrafficSelectors {
		switch individualTrafficSelector.TSType {
		case TS_IPV4_ADDR_RANGE:
			// Address length checking
			if len(individualTrafficSelector.StartAddress) != 4 {
				return nil, errors.New("start IPv4 address length is not correct")
			}
			if len(individualTrafficSelector.EndAddress) != 4 {
				return nil, errors.New("end IPv4 address length is not correct")
			}

			individualTrafficSelectorData := make([]byte, 8)

			individualTrafficSelectorData[0] = individualTrafficSelector.TSType
			individualTrafficSelectorData[1] = individualTrafficSelector.IPProtocolID
			binary.BigEndian.PutUint16(individualTrafficSelectorData[4:6], individualTrafficSelector.StartPort)
			binary.BigEndian.PutUint16(individualTrafficSelectorData[6:8], individualTrafficSelector.EndPort)

			individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.StartAddress...)
			individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.EndAddress...)

			dataLen := len(individualTrafficSelectorData)
			if dataLen > math.MaxUint16 {
				return nil, fmt.Errorf("individualTrafficSelectorData length exceeds uint16 maximum value: %v", dataLen)
			}
			binary.BigEndian.PutUint16(individualTrafficSelectorData[2:4], uint16(dataLen))

			trafficSelectorData = append(trafficSelectorData, individualTrafficSelectorData...)
		case TS_IPV6_ADDR_RANGE:
			// Address length checking
			if len(individualTrafficSelector.StartAddress) != 16 {
				return nil, errors.New("start IPv6 address length is not correct")
			}
			if len(individualTrafficSelector.EndAddress) != 16 {
				return nil, errors.New("end IPv6 address length is not correct")
			}

			individualTrafficSelectorData := make([]byte, 8)

			individualTrafficSelectorData[0] = individualTrafficSelector.TSType
			individualTrafficSelectorData[1] = individualTrafficSelector.IPProtocolID
			binary.BigEndian.PutUint16(individualTrafficSelectorData[4:6], individualTrafficSelector.StartPort)
			binary.BigEndian.PutUint16(individualTrafficSelectorData[6:8], individualTrafficSelector.EndPort)

			individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.StartAddress...)
			individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.EndAddress...)

			dataLen := len(individualTrafficSelectorData)
			if dataLen > math.MaxUint16 {
				return nil, fmt.Errorf("individualTrafficSelectorData length exceeds uint16 maximum value: %v", dataLen)
			}
			binary.BigEndian.PutUint16(individualTrafficSelectorData[2:4], uint16(dataLen))

			trafficSelectorData = append(trafficSelectorData, individualTrafficSelectorData...)
		default:
			return nil, errors.New("unsupported traffic selector type")
		}
	}

	return trafficSelectorData, nil
}

func (trafficSelector *TrafficSelectorResponder) unmarshal(rawData []byte) error {
	logger.IKELog.Debugln("start unmarshalling received bytes")
	logger.IKELog.Debugf("payload length %d bytes", len(rawData))

	if len(rawData) == 0 {
		return nil
	}

	logger.IKELog.Debugln("unmarshal 1 traffic selector")
	// bounds checking
	if len(rawData) < 4 {
		return errors.New("no sufficient bytes to get number of traffic selector in header")
	}

	numberOfSPI := rawData[0]

	rawData = rawData[4:]

	for ; numberOfSPI > 0; numberOfSPI-- {
		// bounds checking
		if len(rawData) < 4 {
			return errors.New("no sufficient bytes to decode next individual traffic selector length in header")
		}
		trafficSelectorType := rawData[0]
		switch trafficSelectorType {
		case TS_IPV4_ADDR_RANGE:
			selectorLength := binary.BigEndian.Uint16(rawData[2:4])
			if selectorLength != 16 {
				return errors.New("a TS_IPV4_ADDR_RANGE type traffic selector should has length 16 bytes")
			}
			if len(rawData) < int(selectorLength) {
				return errors.New("no sufficient bytes to decode next individual traffic selector")
			}

			individualTrafficSelector := &IndividualTrafficSelector{}

			individualTrafficSelector.TSType = rawData[0]
			individualTrafficSelector.IPProtocolID = rawData[1]
			individualTrafficSelector.StartPort = binary.BigEndian.Uint16(rawData[4:6])
			individualTrafficSelector.EndPort = binary.BigEndian.Uint16(rawData[6:8])

			individualTrafficSelector.StartAddress = append(individualTrafficSelector.StartAddress, rawData[8:12]...)
			individualTrafficSelector.EndAddress = append(individualTrafficSelector.EndAddress, rawData[12:16]...)

			trafficSelector.TrafficSelectors = append(trafficSelector.TrafficSelectors, individualTrafficSelector)

			rawData = rawData[16:]
		case TS_IPV6_ADDR_RANGE:
			selectorLength := binary.BigEndian.Uint16(rawData[2:4])
			if selectorLength != 40 {
				return errors.New("a TS_IPV6_ADDR_RANGE type traffic selector should has length 40 bytes")
			}
			if len(rawData) < int(selectorLength) {
				return errors.New("no sufficient bytes to decode next individual traffic selector")
			}

			individualTrafficSelector := &IndividualTrafficSelector{}

			individualTrafficSelector.TSType = rawData[0]
			individualTrafficSelector.IPProtocolID = rawData[1]
			individualTrafficSelector.StartPort = binary.BigEndian.Uint16(rawData[4:6])
			individualTrafficSelector.EndPort = binary.BigEndian.Uint16(rawData[6:8])

			individualTrafficSelector.StartAddress = append(individualTrafficSelector.StartAddress, rawData[8:24]...)
			individualTrafficSelector.EndAddress = append(individualTrafficSelector.EndAddress, rawData[24:40]...)

			trafficSelector.TrafficSelectors = append(trafficSelector.TrafficSelectors, individualTrafficSelector)

			rawData = rawData[40:]
		default:
			return errors.New("unsupported traffic selector type")
		}
	}
	return nil
}

// Definition of Encrypted Payload
var _ IKEPayload = &Encrypted{}

type Encrypted struct {
	NextPayload   IKEPayloadType
	EncryptedData []byte
}

func (encrypted *Encrypted) Type() IKEPayloadType { return TypeSK }

func (encrypted *Encrypted) marshal() ([]byte, error) {
	logger.IKELog.Debugln("start marshalling")

	if len(encrypted.EncryptedData) == 0 {
		logger.IKELog.Errorln("encrypted data is empty")
		return nil, fmt.Errorf("encrypted data is empty")
	}

	return encrypted.EncryptedData, nil
}

func (encrypted *Encrypted) unmarshal(rawData []byte) error {
	logger.IKELog.Debugln("start unmarshalling received bytes")
	logger.IKELog.Debugf("payload length %d bytes", len(rawData))
	encrypted.EncryptedData = append(encrypted.EncryptedData, rawData...)
	return nil
}

// Definition of Configuration
var _ IKEPayload = &Configuration{}

type Configuration struct {
	ConfigurationType      uint8
	ConfigurationAttribute ConfigurationAttributeContainer
}

type ConfigurationAttributeContainer []*IndividualConfigurationAttribute

type IndividualConfigurationAttribute struct {
	Type  uint16
	Value []byte
}

func (configuration *Configuration) Type() IKEPayloadType { return TypeCP }

func (configuration *Configuration) marshal() ([]byte, error) {
	logger.IKELog.Debugln("start marshalling")

	configurationData := make([]byte, 4)

	configurationData[0] = configuration.ConfigurationType

	for _, attribute := range configuration.ConfigurationAttribute {
		individualConfigurationAttributeData := make([]byte, 4)

		binary.BigEndian.PutUint16(individualConfigurationAttributeData[0:2], (attribute.Type & 0x7fff))
		attributeLen := len(attribute.Value)
		if attributeLen > math.MaxUint16 {
			return nil, fmt.Errorf("attribute value length exceeds uint16 limit: %d", attributeLen)
		}
		binary.BigEndian.PutUint16(individualConfigurationAttributeData[2:4], uint16(attributeLen))
		individualConfigurationAttributeData = append(individualConfigurationAttributeData, attribute.Value...)

		configurationData = append(configurationData, individualConfigurationAttributeData...)
	}

	return configurationData, nil
}

func (configuration *Configuration) unmarshal(rawData []byte) error {
	logger.IKELog.Debugln("start unmarshalling received bytes")
	logger.IKELog.Debugf("payload length %d bytes", len(rawData))

	if len(rawData) > 0 {
		logger.IKELog.Debugln("unmarshal 1 configuration")
		// bounds checking
		if len(rawData) <= 4 {
			return errors.New("no sufficient bytes to decode next configuration")
		}
		configuration.ConfigurationType = rawData[0]

		configurationAttributeData := rawData[4:]

		for len(configurationAttributeData) > 0 {
			logger.IKELog.Debugln("unmarshal 1 configuration attribute")
			// bounds checking
			if len(configurationAttributeData) < 4 {
				return errors.New("no sufficient bytes to decode next configuration attribute")
			}
			length := binary.BigEndian.Uint16(configurationAttributeData[2:4])
			if len(configurationAttributeData) < int(4+length) {
				return errors.New("TLV attribute length error")
			}

			individualConfigurationAttribute := new(IndividualConfigurationAttribute)

			individualConfigurationAttribute.Type = binary.BigEndian.Uint16(configurationAttributeData[0:2])
			configurationAttributeData = configurationAttributeData[4:]
			individualConfigurationAttribute.Value = append(individualConfigurationAttribute.Value, configurationAttributeData[:length]...)
			configurationAttributeData = configurationAttributeData[length:]

			configuration.ConfigurationAttribute = append(configuration.ConfigurationAttribute, individualConfigurationAttribute)
		}
	}

	return nil
}

// Definition of IKE EAP
var _ IKEPayload = &EAP{}

type EAP struct {
	Code        uint8
	Identifier  uint8
	EAPTypeData EAPTypeDataContainer
}

func (eap *EAP) Type() IKEPayloadType { return TypeEAP }

func (eap *EAP) marshal() ([]byte, error) {
	logger.IKELog.Debugln("start marshalling")

	eapData := make([]byte, 4)

	eapData[0] = eap.Code
	eapData[1] = eap.Identifier

	if len(eap.EAPTypeData) > 0 {
		eapTypeData, err := eap.EAPTypeData[0].marshal()
		if err != nil {
			return nil, fmt.Errorf("EAP type data marshal failed: %+v", err)
		}

		eapData = append(eapData, eapTypeData...)
	}

	eapDataLen := len(eapData)
	if eapDataLen > math.MaxUint16 {
		return nil, fmt.Errorf("eap data length exceeds uint16 limit: %d", eapDataLen)
	}
	binary.BigEndian.PutUint16(eapData[2:4], uint16(eapDataLen))
	return eapData, nil
}

func (eap *EAP) unmarshal(rawData []byte) error {
	logger.IKELog.Debugln("start unmarshalling received bytes")
	logger.IKELog.Debugf("payload length %d bytes", len(rawData))

	if len(rawData) > 0 {
		logger.IKELog.Debugln("unmarshal 1 EAP")
		// bounds checking
		if len(rawData) < 4 {
			return errors.New("no sufficient bytes to decode next EAP payload")
		}
		eapPayloadLength := binary.BigEndian.Uint16(rawData[2:4])
		if eapPayloadLength < 4 {
			return errors.New("payload length specified in the header is too small for EAP")
		}
		if len(rawData) != int(eapPayloadLength) {
			return errors.New("received payload length not matches the length specified in header")
		}

		eap.Code = rawData[0]
		eap.Identifier = rawData[1]

		// EAP Success or Failed
		if eapPayloadLength == 4 {
			return nil
		}

		eapType := EAPType(rawData[4])
		var eapTypeData EAPTypeFormat

		switch eapType {
		case EAPTypeIdentity:
			eapTypeData = new(EAPIdentity)
		case EAPTypeNotification:
			eapTypeData = new(EAPNotification)
		case EAPTypeNak:
			eapTypeData = new(EAPNak)
		case EAPTypeExpanded:
			eapTypeData = new(EAPExpanded)
		default:
			// TODO: Create unsupprted type to handle it
			return errors.New("not supported EAP type")
		}

		if err := eapTypeData.unmarshal(rawData[4:]); err != nil {
			return fmt.Errorf("unamrshal EAP type data failed: %+v", err)
		}

		eap.EAPTypeData = append(eap.EAPTypeData, eapTypeData)
	}

	return nil
}

type EAPTypeDataContainer []EAPTypeFormat

type EAPTypeFormat interface {
	// Type specifies EAP types
	Type() EAPType

	// Called by EAP.marshal() or EAP.unmarshal()
	marshal() ([]byte, error)
	unmarshal(rawData []byte) error
}

// Definition of EAP Identity
var _ EAPTypeFormat = &EAPIdentity{}

type EAPIdentity struct {
	IdentityData []byte
}

func (eapIdentity *EAPIdentity) Type() EAPType { return EAPTypeIdentity }

func (eapIdentity *EAPIdentity) marshal() ([]byte, error) {
	logger.IKELog.Debugln("start marshalling")

	if len(eapIdentity.IdentityData) == 0 {
		return nil, errors.New("EAP identity is empty")
	}

	eapIdentityData := []byte{byte(EAPTypeIdentity)}
	eapIdentityData = append(eapIdentityData, eapIdentity.IdentityData...)

	return eapIdentityData, nil
}

func (eapIdentity *EAPIdentity) unmarshal(rawData []byte) error {
	logger.IKELog.Debugln("start unmarshalling received bytes")
	logger.IKELog.Debugf("payload length %d bytes", len(rawData))

	if len(rawData) > 1 {
		eapIdentity.IdentityData = append(eapIdentity.IdentityData, rawData[1:]...)
	}

	return nil
}

// Definition of EAP Notification
var _ EAPTypeFormat = &EAPNotification{}

type EAPNotification struct {
	NotificationData []byte
}

func (eapNotification *EAPNotification) Type() EAPType { return EAPTypeNotification }

func (eapNotification *EAPNotification) marshal() ([]byte, error) {
	logger.IKELog.Debugln("start marshalling")

	if len(eapNotification.NotificationData) == 0 {
		return nil, errors.New("EAP notification is empty")
	}

	eapNotificationData := []byte{byte(EAPTypeNotification)}
	eapNotificationData = append(eapNotificationData, eapNotification.NotificationData...)

	return eapNotificationData, nil
}

func (eapNotification *EAPNotification) unmarshal(rawData []byte) error {
	logger.IKELog.Debugln("start unmarshalling received bytes")
	logger.IKELog.Debugf("payload length %d bytes", len(rawData))

	if len(rawData) > 1 {
		eapNotification.NotificationData = append(eapNotification.NotificationData, rawData[1:]...)
	}

	return nil
}

// Definition of EAP Nak
var _ EAPTypeFormat = &EAPNak{}

type EAPNak struct {
	NakData []byte
}

func (eapNak *EAPNak) Type() EAPType { return EAPTypeNak }

func (eapNak *EAPNak) marshal() ([]byte, error) {
	logger.IKELog.Debugln("start marshalling")

	if len(eapNak.NakData) == 0 {
		return nil, errors.New("EAP nak is empty")
	}

	eapNakData := []byte{byte(EAPTypeNak)}
	eapNakData = append(eapNakData, eapNak.NakData...)

	return eapNakData, nil
}

func (eapNak *EAPNak) unmarshal(rawData []byte) error {
	logger.IKELog.Debugln("start unmarshalling received bytes")
	logger.IKELog.Debugf("payload length %d bytes", len(rawData))

	if len(rawData) > 1 {
		eapNak.NakData = append(eapNak.NakData, rawData[1:]...)
	}

	return nil
}

// Definition of EAP expanded
var _ EAPTypeFormat = &EAPExpanded{}

type EAPExpanded struct {
	VendorID   uint32
	VendorType uint32
	VendorData []byte
}

func (eapExpanded *EAPExpanded) Type() EAPType { return EAPTypeExpanded }

func (eapExpanded *EAPExpanded) marshal() ([]byte, error) {
	logger.IKELog.Debugln("start marshalling")

	eapExpandedData := make([]byte, 8)

	vendorID := eapExpanded.VendorID & 0x00ffffff
	typeAndVendorID := (uint32(EAPTypeExpanded)<<24 | vendorID)

	binary.BigEndian.PutUint32(eapExpandedData[0:4], typeAndVendorID)
	binary.BigEndian.PutUint32(eapExpandedData[4:8], eapExpanded.VendorType)

	if len(eapExpanded.VendorData) == 0 {
		logger.IKELog.Warnln("EAP vendor data field is empty")
		return eapExpandedData, nil
	}

	eapExpandedData = append(eapExpandedData, eapExpanded.VendorData...)

	return eapExpandedData, nil
}

func (eapExpanded *EAPExpanded) unmarshal(rawData []byte) error {
	logger.IKELog.Debugln("start unmarshalling received bytes")
	logger.IKELog.Debugf("payload length %d bytes", len(rawData))

	if len(rawData) == 0 {
		return nil
	}
	if len(rawData) < 8 {
		return errors.New("no sufficient bytes to decode the EAP expanded type")
	}

	typeAndVendorID := binary.BigEndian.Uint32(rawData[0:4])
	eapExpanded.VendorID = typeAndVendorID & 0x00ffffff

	eapExpanded.VendorType = binary.BigEndian.Uint32(rawData[4:8])

	if len(rawData) > 8 {
		eapExpanded.VendorData = append(eapExpanded.VendorData, rawData[8:]...)
	}

	return nil
}
