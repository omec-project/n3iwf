// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"

	"github.com/omec-project/n3iwf/context"
	ike_message "github.com/omec-project/n3iwf/ike/message"
	"github.com/omec-project/n3iwf/logger"
	ngap_message "github.com/omec-project/n3iwf/ngap/message"
	"github.com/omec-project/ngap/ngapType"
	"golang.org/x/sys/unix"
)

func HandleIKESAINIT(udpConn *net.UDPConn, n3iwfAddr, ueAddr *net.UDPAddr, message *ike_message.IKEMessage) {
	logger.IKELog.Infoln("handle IKE_SA_INIT")

	// Used to receive value from peer
	var securityAssociation *ike_message.SecurityAssociation
	var keyExcahge *ike_message.KeyExchange
	var nonce *ike_message.Nonce
	var notifications []*ike_message.Notification

	n3iwfSelf := context.N3IWFSelf()

	// For response or needed data
	responseIKEMessage := new(ike_message.IKEMessage)
	var sharedKeyData, localNonce, concatenatedNonce []byte
	// Chosen transform from peer's proposal
	var encryptionAlgorithmTransform, pseudorandomFunctionTransform *ike_message.Transform
	var integrityAlgorithmTransform, diffieHellmanGroupTransform *ike_message.Transform
	// For NAT-T
	var ueIsBehindNAT, n3iwfIsBehindNAT bool

	if message == nil {
		logger.IKELog.Errorln("IKE Message is nil")
		return
	}

	// parse IKE header and setup IKE context
	// check major version
	majorVersion := ((message.Version & 0xf0) >> 4)
	if majorVersion > 2 {
		logger.IKELog.Warnln("received an IKE message with higher major version")
		// send INFORMATIONAL type message with INVALID_MAJOR_VERSION Notify payload
		responseIKEMessage.BuildIKEHeader(message.InitiatorSPI, message.ResponderSPI,
			ike_message.INFORMATIONAL, ike_message.ResponseBitCheck, message.MessageID)
		responseIKEMessage.Payloads.Reset()
		responseIKEMessage.Payloads.BuildNotification(ike_message.TypeNone,
			ike_message.INVALID_MAJOR_VERSION, nil, nil)

		SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage)

		return
	}

	for _, ikePayload := range message.Payloads {
		switch ikePayload.Type() {
		case ike_message.TypeSA:
			securityAssociation = ikePayload.(*ike_message.SecurityAssociation)
		case ike_message.TypeKE:
			keyExcahge = ikePayload.(*ike_message.KeyExchange)
		case ike_message.TypeNiNr:
			nonce = ikePayload.(*ike_message.Nonce)
		case ike_message.TypeN:
			notifications = append(notifications, ikePayload.(*ike_message.Notification))
		default:
			logger.IKELog.Warnf(
				"get IKE payload (type %d) in IKE_SA_INIT message, this payload will not be handled by IKE handler",
				ikePayload.Type())
		}
	}

	if securityAssociation != nil {
		responseSecurityAssociation := responseIKEMessage.Payloads.BuildSecurityAssociation()

		for _, proposal := range securityAssociation.Proposals {
			// We need ENCR, PRF, INTEG, DH, but not ESN
			encryptionAlgorithmTransform = nil
			pseudorandomFunctionTransform = nil
			integrityAlgorithmTransform = nil
			diffieHellmanGroupTransform = nil

			if len(proposal.EncryptionAlgorithm) > 0 {
				for _, transform := range proposal.EncryptionAlgorithm {
					if is_supported(ike_message.TypeEncryptionAlgorithm, transform.TransformID,
						transform.AttributePresent, transform.AttributeValue) {
						encryptionAlgorithmTransform = transform
						break
					}
				}
				if encryptionAlgorithmTransform == nil {
					continue
				}
			} else {
				continue // mandatory
			}
			if len(proposal.PseudorandomFunction) > 0 {
				for _, transform := range proposal.PseudorandomFunction {
					if is_supported(ike_message.TypePseudorandomFunction, transform.TransformID,
						transform.AttributePresent, transform.AttributeValue) {
						pseudorandomFunctionTransform = transform
						break
					}
				}
				if pseudorandomFunctionTransform == nil {
					continue
				}
			} else {
				continue // mandatory
			}
			if len(proposal.IntegrityAlgorithm) > 0 {
				for _, transform := range proposal.IntegrityAlgorithm {
					if is_supported(ike_message.TypeIntegrityAlgorithm, transform.TransformID,
						transform.AttributePresent, transform.AttributeValue) {
						integrityAlgorithmTransform = transform
						break
					}
				}
				if integrityAlgorithmTransform == nil {
					continue
				}
			} else {
				continue // mandatory
			}
			if len(proposal.DiffieHellmanGroup) > 0 {
				for _, transform := range proposal.DiffieHellmanGroup {
					if is_supported(ike_message.TypeDiffieHellmanGroup, transform.TransformID,
						transform.AttributePresent, transform.AttributeValue) {
						diffieHellmanGroupTransform = transform
						break
					}
				}
				if diffieHellmanGroupTransform == nil {
					continue
				}
			} else {
				continue // mandatory
			}
			if len(proposal.ExtendedSequenceNumbers) > 0 {
				continue // No ESN
			}

			// Construct chosen proposal, with ENCR, PRF, INTEG, DH, and each
			// contains one transform expectively
			chosenProposal := responseSecurityAssociation.Proposals.BuildProposal(
				proposal.ProposalNumber, proposal.ProtocolID, nil)
			chosenProposal.EncryptionAlgorithm = append(chosenProposal.EncryptionAlgorithm, encryptionAlgorithmTransform)
			chosenProposal.PseudorandomFunction = append(chosenProposal.PseudorandomFunction, pseudorandomFunctionTransform)
			chosenProposal.IntegrityAlgorithm = append(chosenProposal.IntegrityAlgorithm, integrityAlgorithmTransform)
			chosenProposal.DiffieHellmanGroup = append(chosenProposal.DiffieHellmanGroup, diffieHellmanGroupTransform)

			break
		}

		if len(responseSecurityAssociation.Proposals) == 0 {
			logger.IKELog.Warnln("no proposal chosen")
			// Respond NO_PROPOSAL_CHOSEN to UE
			responseIKEMessage.BuildIKEHeader(message.InitiatorSPI, message.ResponderSPI,
				ike_message.IKE_SA_INIT, ike_message.ResponseBitCheck, message.MessageID)
			responseIKEMessage.Payloads.Reset()
			responseIKEMessage.Payloads.BuildNotification(ike_message.TypeNone, ike_message.NO_PROPOSAL_CHOSEN, nil, nil)

			SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage)

			return
		}
	} else {
		logger.IKELog.Errorln("the security association field is nil")
		// TODO: send error message to UE
		return
	}

	if keyExcahge != nil {
		chosenDiffieHellmanGroup := diffieHellmanGroupTransform.TransformID
		if chosenDiffieHellmanGroup != keyExcahge.DiffieHellmanGroup {
			logger.IKELog.Warnln("the Diffie-Hellman group defined in key exchange payload not matches the one in chosen proposal")
			// send INVALID_KE_PAYLOAD to UE
			responseIKEMessage.BuildIKEHeader(message.InitiatorSPI, message.ResponderSPI,
				ike_message.IKE_SA_INIT, ike_message.ResponseBitCheck, message.MessageID)
			responseIKEMessage.Payloads.Reset()

			notificationData := make([]byte, 2)
			binary.BigEndian.PutUint16(notificationData, chosenDiffieHellmanGroup)
			responseIKEMessage.Payloads.BuildNotification(
				ike_message.TypeNone, ike_message.INVALID_KE_PAYLOAD, nil, notificationData)

			SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage)

			return
		}

		var localPublicValue []byte

		localPublicValue, sharedKeyData = CalculateDiffieHellmanMaterials(GenerateRandomNumber(),
			keyExcahge.KeyExchangeData, chosenDiffieHellmanGroup)
		responseIKEMessage.Payloads.BuildKeyExchange(chosenDiffieHellmanGroup, localPublicValue)
	} else {
		logger.IKELog.Errorln("the key exchange field is nil")
		// TODO: send error message to UE
		return
	}

	if nonce != nil {
		localNonce = GenerateRandomNumber().Bytes()
		concatenatedNonce = append(nonce.NonceData, localNonce...)

		responseIKEMessage.Payloads.BuildNonce(localNonce)
	} else {
		logger.IKELog.Errorln("the nonce field is nil")
		// TODO: send error message to UE
		return
	}

	if len(notifications) != 0 {
		for _, notification := range notifications {
			switch notification.NotifyMessageType {
			case ike_message.NAT_DETECTION_SOURCE_IP:
				logger.IKELog.Debugln("received IKE Notify: NAT_DETECTION_SOURCE_IP")
				// Calculate local NAT_DETECTION_SOURCE_IP hash
				// : sha1(ispi | rspi | ueip | ueport)
				localDetectionData := make([]byte, 22)
				binary.BigEndian.PutUint64(localDetectionData[0:8], message.InitiatorSPI)
				binary.BigEndian.PutUint64(localDetectionData[8:16], message.ResponderSPI)
				copy(localDetectionData[16:20], ueAddr.IP.To4())
				binary.BigEndian.PutUint16(localDetectionData[20:22], uint16(ueAddr.Port))

				sha1HashFunction := sha1.New()
				if _, err := sha1HashFunction.Write(localDetectionData); err != nil {
					logger.IKELog.Errorf("hash function write error: %+v", err)
					return
				}

				if !bytes.Equal(notification.NotificationData, sha1HashFunction.Sum(nil)) {
					ueIsBehindNAT = true
				}
			case ike_message.NAT_DETECTION_DESTINATION_IP:
				logger.IKELog.Debugln("received IKE Notify: NAT_DETECTION_DESTINATION_IP")
				// Calculate local NAT_DETECTION_SOURCE_IP hash
				// : sha1(ispi | rspi | n3iwfip | n3iwfport)
				localDetectionData := make([]byte, 22)
				binary.BigEndian.PutUint64(localDetectionData[0:8], message.InitiatorSPI)
				binary.BigEndian.PutUint64(localDetectionData[8:16], message.ResponderSPI)
				copy(localDetectionData[16:20], n3iwfAddr.IP.To4())
				binary.BigEndian.PutUint16(localDetectionData[20:22], uint16(n3iwfAddr.Port))

				sha1HashFunction := sha1.New()
				if _, err := sha1HashFunction.Write(localDetectionData); err != nil {
					logger.IKELog.Errorf("hash function write error: %+v", err)
					return
				}

				if !bytes.Equal(notification.NotificationData, sha1HashFunction.Sum(nil)) {
					n3iwfIsBehindNAT = true
				}
			default:
			}
		}
	}

	// Create new IKE security association
	ikeSecurityAssociation := n3iwfSelf.NewIKESecurityAssociation()
	ikeSecurityAssociation.RemoteSPI = message.InitiatorSPI
	ikeSecurityAssociation.MessageID = message.MessageID
	ikeSecurityAssociation.UEIsBehindNAT = ueIsBehindNAT
	ikeSecurityAssociation.N3IWFIsBehindNAT = n3iwfIsBehindNAT

	// Record algorithm in context
	ikeSecurityAssociation.EncryptionAlgorithm = encryptionAlgorithmTransform
	ikeSecurityAssociation.IntegrityAlgorithm = integrityAlgorithmTransform
	ikeSecurityAssociation.PseudorandomFunction = pseudorandomFunctionTransform
	ikeSecurityAssociation.DiffieHellmanGroup = diffieHellmanGroupTransform

	// Record concatenated nonce
	ikeSecurityAssociation.ConcatenatedNonce = append(ikeSecurityAssociation.ConcatenatedNonce, concatenatedNonce...)
	// Record Diffie-Hellman shared key
	ikeSecurityAssociation.DiffieHellmanSharedKey = append(ikeSecurityAssociation.DiffieHellmanSharedKey, sharedKeyData...)

	if err := GenerateKeyForIKESA(ikeSecurityAssociation); err != nil {
		logger.IKELog.Errorf("generate key for IKE SA failed: %+v", err)
		return
	}

	// IKE response to UE
	responseIKEMessage.BuildIKEHeader(ikeSecurityAssociation.RemoteSPI, ikeSecurityAssociation.LocalSPI,
		ike_message.IKE_SA_INIT, ike_message.ResponseBitCheck, message.MessageID)

	// Calculate NAT_DETECTION_SOURCE_IP for NAT-T
	natDetectionSourceIP := make([]byte, 22)
	binary.BigEndian.PutUint64(natDetectionSourceIP[0:8], ikeSecurityAssociation.RemoteSPI)
	binary.BigEndian.PutUint64(natDetectionSourceIP[8:16], ikeSecurityAssociation.LocalSPI)
	copy(natDetectionSourceIP[16:20], n3iwfAddr.IP.To4())
	binary.BigEndian.PutUint16(natDetectionSourceIP[20:22], uint16(n3iwfAddr.Port))

	// Build and append notify payload for NAT_DETECTION_SOURCE_IP
	responseIKEMessage.Payloads.BuildNotification(
		ike_message.TypeNone, ike_message.NAT_DETECTION_SOURCE_IP, nil, natDetectionSourceIP)

	// Calculate NAT_DETECTION_DESTINATION_IP for NAT-T
	natDetectionDestinationIP := make([]byte, 22)
	binary.BigEndian.PutUint64(natDetectionDestinationIP[0:8], ikeSecurityAssociation.RemoteSPI)
	binary.BigEndian.PutUint64(natDetectionDestinationIP[8:16], ikeSecurityAssociation.LocalSPI)
	copy(natDetectionDestinationIP[16:20], ueAddr.IP.To4())
	binary.BigEndian.PutUint16(natDetectionDestinationIP[20:22], uint16(ueAddr.Port))

	// Build and append notify payload for NAT_DETECTION_DESTINATION_IP
	responseIKEMessage.Payloads.BuildNotification(
		ike_message.TypeNone, ike_message.NAT_DETECTION_DESTINATION_IP, nil, natDetectionDestinationIP)

	// Prepare authentication data - InitatorSignedOctet
	// InitatorSignedOctet = RealMessage1 | NonceRData | MACedIDForI
	// MACedIDForI is acquired in IKE_AUTH exchange
	receivedIKEMessageData, err := message.Encode()
	if err != nil {
		logger.IKELog.Errorln("encode message failed: %+v", err)
		return
	}
	ikeSecurityAssociation.RemoteUnsignedAuthentication = append(receivedIKEMessageData, localNonce...)

	// Prepare authentication data - ResponderSignedOctet
	// ResponderSignedOctet = RealMessage2 | NonceIData | MACedIDForR
	responseIKEMessageData, err := responseIKEMessage.Encode()
	if err != nil {
		logger.IKELog.Errorln("encoding IKE message failed: %+v", err)
		return
	}
	ikeSecurityAssociation.LocalUnsignedAuthentication = append(responseIKEMessageData, nonce.NonceData...)
	// MACedIDForR
	var idPayload ike_message.IKEPayloadContainer
	idPayload.BuildIdentificationResponder(ike_message.ID_FQDN, []byte(n3iwfSelf.Fqdn))
	idPayloadData, err := idPayload.Encode()
	if err != nil {
		logger.IKELog.Errorln("encode IKE payload failed: %+v", err)
		return
	}
	pseudorandomFunction, ok := NewPseudorandomFunction(ikeSecurityAssociation.SK_pr,
		ikeSecurityAssociation.PseudorandomFunction.TransformID)
	if !ok {
		logger.IKELog.Errorln("get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen")
		return
	}
	if _, err := pseudorandomFunction.Write(idPayloadData[4:]); err != nil {
		logger.IKELog.Errorf("pseudorandom function write error: %+v", err)
		return
	}
	ikeSecurityAssociation.LocalUnsignedAuthentication = append(ikeSecurityAssociation.LocalUnsignedAuthentication,
		pseudorandomFunction.Sum(nil)...)

	logger.IKELog.Debugf("local unsigned authentication data: %s", hex.Dump(ikeSecurityAssociation.LocalUnsignedAuthentication))

	// Send response to UE
	SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage)
}

// IKE_AUTH state
const (
	PreSignalling = iota
	EAPSignalling
	PostSignalling
)

func HandleIKEAUTH(udpConn *net.UDPConn, n3iwfAddr, ueAddr *net.UDPAddr, message *ike_message.IKEMessage) {
	logger.IKELog.Infoln("handle IKE_AUTH")

	var encryptedPayload *ike_message.Encrypted

	n3iwfSelf := context.N3IWFSelf()

	// Used for response
	responseIKEMessage := new(ike_message.IKEMessage)
	var responseIKEPayload ike_message.IKEPayloadContainer

	if message == nil {
		logger.IKELog.Error("IKE Message is nil")
		return
	}

	// parse IKE header and setup IKE context
	// check major version
	majorVersion := ((message.Version & 0xf0) >> 4)
	if majorVersion > 2 {
		logger.IKELog.Warnln("received an IKE message with higher major version")
		// send INFORMATIONAL type message with INVALID_MAJOR_VERSION Notify payload ( OUTSIDE IKE SA )
		responseIKEMessage.BuildIKEHeader(message.InitiatorSPI, message.ResponderSPI,
			ike_message.INFORMATIONAL, ike_message.ResponseBitCheck, message.MessageID)
		responseIKEMessage.Payloads.Reset()
		responseIKEMessage.Payloads.BuildNotification(ike_message.TypeNone, ike_message.INVALID_MAJOR_VERSION, nil, nil)

		SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage)

		return
	}

	// Find corresponding IKE security association
	localSPI := message.ResponderSPI
	ikeSecurityAssociation, ok := n3iwfSelf.IKESALoad(localSPI)
	if !ok {
		logger.IKELog.Warnln("unrecognized SPI")
		// send INFORMATIONAL type message with INVALID_IKE_SPI Notify payload ( OUTSIDE IKE SA )
		responseIKEMessage.BuildIKEHeader(message.InitiatorSPI, 0, ike_message.INFORMATIONAL,
			ike_message.ResponseBitCheck, message.MessageID)
		responseIKEMessage.Payloads.Reset()
		responseIKEMessage.Payloads.BuildNotification(ike_message.TypeNone, ike_message.INVALID_IKE_SPI, nil, nil)

		SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage)

		return
	}

	for _, ikePayload := range message.Payloads {
		switch ikePayload.Type() {
		case ike_message.TypeSK:
			encryptedPayload = ikePayload.(*ike_message.Encrypted)
		default:
			logger.IKELog.Warnf(
				"get IKE payload (type %d) in IKE_AUTH message, this payload will not be handled by IKE handler",
				ikePayload.Type())
		}
	}

	decryptedIKEPayload, err := DecryptProcedure(ikeSecurityAssociation, message, encryptedPayload)
	if err != nil {
		logger.IKELog.Errorf("decrypt IKE message failed: %+v", err)
		return
	}

	// Parse payloads
	var initiatorID *ike_message.IdentificationInitiator
	var certificateRequest *ike_message.CertificateRequest
	var certificate *ike_message.Certificate
	var securityAssociation *ike_message.SecurityAssociation
	var trafficSelectorInitiator *ike_message.TrafficSelectorInitiator
	var trafficSelectorResponder *ike_message.TrafficSelectorResponder
	var eap *ike_message.EAP
	var authentication *ike_message.Authentication
	var configuration *ike_message.Configuration

	for _, ikePayload := range decryptedIKEPayload {
		switch ikePayload.Type() {
		case ike_message.TypeIDi:
			initiatorID = ikePayload.(*ike_message.IdentificationInitiator)
		case ike_message.TypeCERTreq:
			certificateRequest = ikePayload.(*ike_message.CertificateRequest)
		case ike_message.TypeCERT:
			certificate = ikePayload.(*ike_message.Certificate)
		case ike_message.TypeSA:
			securityAssociation = ikePayload.(*ike_message.SecurityAssociation)
		case ike_message.TypeTSi:
			trafficSelectorInitiator = ikePayload.(*ike_message.TrafficSelectorInitiator)
		case ike_message.TypeTSr:
			trafficSelectorResponder = ikePayload.(*ike_message.TrafficSelectorResponder)
		case ike_message.TypeEAP:
			eap = ikePayload.(*ike_message.EAP)
		case ike_message.TypeAUTH:
			authentication = ikePayload.(*ike_message.Authentication)
		case ike_message.TypeCP:
			configuration = ikePayload.(*ike_message.Configuration)
		default:
			logger.IKELog.Warnf(
				"get IKE payload (type %d) in IKE_AUTH message, this payload will not be handled by IKE handler",
				ikePayload.Type())
		}
	}

	// NOTE: tune it
	transformPseudorandomFunction := ikeSecurityAssociation.PseudorandomFunction
	ikeSecurityAssociation.MessageID = message.MessageID

	switch ikeSecurityAssociation.State {
	case PreSignalling:
		if initiatorID != nil {
			logger.IKELog.Infoln("ecoding initiator for later IKE authentication")
			ikeSecurityAssociation.InitiatorID = initiatorID

			// Record maced identification for authentication
			idPayload := ike_message.IKEPayloadContainer{
				initiatorID,
			}
			idPayloadData, err := idPayload.Encode()
			if err != nil {
				logger.IKELog.Errorf("encoding ID payload message failed: %+v", err)
				return
			}
			pseudorandomFunction, ok := NewPseudorandomFunction(ikeSecurityAssociation.SK_pr,
				transformPseudorandomFunction.TransformID)
			if !ok {
				logger.IKELog.Errorln("get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen")
				return
			}
			if _, err := pseudorandomFunction.Write(idPayloadData[4:]); err != nil {
				logger.IKELog.Errorf("pseudorandom function write error: %+v", err)
				return
			}
			ikeSecurityAssociation.RemoteUnsignedAuthentication = append(ikeSecurityAssociation.RemoteUnsignedAuthentication, pseudorandomFunction.Sum(nil)...)
		} else {
			logger.IKELog.Errorln("the initiator identification field is nil")
			// TODO: send error message to UE
			return
		}

		// Certificate request and prepare coresponding certificate
		// RFC 7296 section 3.7:
		// The Certificate Request payload is processed by inspecting the
		// Cert Encoding field to determine whether the processor has any
		// certificates of this type.  If so, the Certification Authority field
		// is inspected to determine if the processor has any certificates that
		// can be validated up to one of the specified certification
		// authorities.  This can be a chain of certificates.
		if certificateRequest != nil {
			logger.IKELog.Infoln("UE request N3IWF certificate")
			if CompareRootCertificate(certificateRequest.CertificateEncoding, certificateRequest.CertificationAuthority) {
				// TODO: Complete N3IWF Certificate/Certificate Authority related procedure
				logger.IKELog.Infoln("certificate Request sent from UE matches N3IWF CA")
			}
		}

		if certificate != nil {
			logger.IKELog.Infoln("UE send its certficate")
			ikeSecurityAssociation.InitiatorCertificate = certificate
		}

		if securityAssociation != nil {
			logger.IKELog.Infoln("parsing security association")
			responseSecurityAssociation := new(ike_message.SecurityAssociation)

			for _, proposal := range securityAssociation.Proposals {
				var encryptionAlgorithmTransform *ike_message.Transform = nil
				var integrityAlgorithmTransform *ike_message.Transform = nil
				var diffieHellmanGroupTransform *ike_message.Transform = nil
				var extendedSequenceNumbersTransform *ike_message.Transform = nil

				if len(proposal.SPI) != 4 {
					continue // The SPI of ESP must be 32-bit
				}

				// check SPI
				spi := binary.BigEndian.Uint32(proposal.SPI)
				if _, ok := n3iwfSelf.ChildSA.Load(spi); ok {
					continue
				}

				if len(proposal.EncryptionAlgorithm) > 0 {
					for _, transform := range proposal.EncryptionAlgorithm {
						if is_Kernel_Supported(ike_message.TypeEncryptionAlgorithm, transform.TransformID,
							transform.AttributePresent, transform.AttributeValue) {
							encryptionAlgorithmTransform = transform
							break
						}
					}
					if encryptionAlgorithmTransform == nil {
						continue
					}
				} else {
					continue // mandatory
				}
				if len(proposal.PseudorandomFunction) > 0 {
					continue // Pseudorandom function is not used by ESP
				}
				if len(proposal.IntegrityAlgorithm) > 0 {
					for _, transform := range proposal.IntegrityAlgorithm {
						if is_Kernel_Supported(ike_message.TypeIntegrityAlgorithm, transform.TransformID,
							transform.AttributePresent, transform.AttributeValue) {
							integrityAlgorithmTransform = transform
							break
						}
					}
					if integrityAlgorithmTransform == nil {
						continue
					}
				} // Optional
				if len(proposal.DiffieHellmanGroup) > 0 {
					for _, transform := range proposal.DiffieHellmanGroup {
						if is_Kernel_Supported(ike_message.TypeDiffieHellmanGroup, transform.TransformID,
							transform.AttributePresent, transform.AttributeValue) {
							diffieHellmanGroupTransform = transform
							break
						}
					}
					if diffieHellmanGroupTransform == nil {
						continue
					}
				} // Optional
				if len(proposal.ExtendedSequenceNumbers) > 0 {
					for _, transform := range proposal.ExtendedSequenceNumbers {
						if is_Kernel_Supported(ike_message.TypeExtendedSequenceNumbers, transform.TransformID,
							transform.AttributePresent, transform.AttributeValue) {
							extendedSequenceNumbersTransform = transform
							break
						}
					}
					if extendedSequenceNumbersTransform == nil {
						continue
					}
				} else {
					continue // Mandatory
				}

				chosenProposal := responseSecurityAssociation.Proposals.BuildProposal(
					proposal.ProposalNumber, proposal.ProtocolID, proposal.SPI)
				chosenProposal.EncryptionAlgorithm = append(chosenProposal.EncryptionAlgorithm, encryptionAlgorithmTransform)
				chosenProposal.ExtendedSequenceNumbers = append(
					chosenProposal.ExtendedSequenceNumbers, extendedSequenceNumbersTransform)
				if integrityAlgorithmTransform != nil {
					chosenProposal.IntegrityAlgorithm = append(chosenProposal.IntegrityAlgorithm, integrityAlgorithmTransform)
				}
				if diffieHellmanGroupTransform != nil {
					chosenProposal.DiffieHellmanGroup = append(chosenProposal.DiffieHellmanGroup, diffieHellmanGroupTransform)
				}

				break
			}

			if len(responseSecurityAssociation.Proposals) == 0 {
				logger.IKELog.Warnln("no proposal chosen")
				// Respond NO_PROPOSAL_CHOSEN to UE
				// Build IKE message
				responseIKEMessage.BuildIKEHeader(message.InitiatorSPI, message.ResponderSPI,
					ike_message.IKE_AUTH, ike_message.ResponseBitCheck, message.MessageID)
				responseIKEMessage.Payloads.Reset()

				// Build response
				responseIKEPayload.Reset()

				// Notification
				responseIKEPayload.BuildNotification(ike_message.TypeNone, ike_message.NO_PROPOSAL_CHOSEN, nil, nil)

				if err := EncryptProcedure(ikeSecurityAssociation, responseIKEPayload, responseIKEMessage); err != nil {
					logger.IKELog.Errorf("encrypting IKE message failed: %+v", err)
					return
				}

				// Send IKE message to UE
				SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage)

				return
			}

			ikeSecurityAssociation.IKEAuthResponseSA = responseSecurityAssociation
		} else {
			logger.IKELog.Errorln("the security association field is nil")
			// TODO: send error message to UE
			return
		}

		if trafficSelectorInitiator != nil {
			logger.IKELog.Infoln("received traffic selector initiator from UE")
			ikeSecurityAssociation.TrafficSelectorInitiator = trafficSelectorInitiator
		} else {
			logger.IKELog.Errorln("the initiator traffic selector field is nil")
			// TODO: send error message to UE
			return
		}

		if trafficSelectorResponder != nil {
			logger.IKELog.Infoln("received traffic selector initiator from UE")
			ikeSecurityAssociation.TrafficSelectorResponder = trafficSelectorResponder
		} else {
			logger.IKELog.Errorln("the initiator traffic selector field is nil")
			// TODO: send error message to UE
			return
		}

		// Build response IKE message
		responseIKEMessage.BuildIKEHeader(message.InitiatorSPI, message.ResponderSPI,
			ike_message.IKE_AUTH, ike_message.ResponseBitCheck, message.MessageID)
		responseIKEMessage.Payloads.Reset()

		// Identification
		responseIKEPayload.BuildIdentificationResponder(ike_message.ID_FQDN, []byte(n3iwfSelf.Fqdn))

		// Certificate
		responseIKEPayload.BuildCertificate(ike_message.X509CertificateSignature, n3iwfSelf.N3iwfCertificate)

		// Authentication Data
		logger.IKELog.Debugf("local authentication data: %s", hex.Dump(ikeSecurityAssociation.LocalUnsignedAuthentication))
		sha1HashFunction := sha1.New()
		if _, err := sha1HashFunction.Write(ikeSecurityAssociation.LocalUnsignedAuthentication); err != nil {
			logger.IKELog.Errorf("hash function write error: %+v", err)
			return
		}

		signedAuth, err := rsa.SignPKCS1v15(rand.Reader, n3iwfSelf.N3iwfPrivateKey, crypto.SHA1, sha1HashFunction.Sum(nil))
		if err != nil {
			logger.IKELog.Errorf("sign authentication data failed: %+v", err)
		}

		responseIKEPayload.BuildAuthentication(ike_message.RSADigitalSignature, signedAuth)

		// EAP expanded 5G-Start
		var identifier uint8
		for {
			identifier, err = GenerateRandomUint8()
			if err != nil {
				logger.IKELog.Errorf("random number failed: %+v", err)
				return
			}
			if identifier != ikeSecurityAssociation.LastEAPIdentifier {
				ikeSecurityAssociation.LastEAPIdentifier = identifier
				break
			}
		}
		responseIKEPayload.BuildEAP5GStart(identifier)

		if err := EncryptProcedure(ikeSecurityAssociation, responseIKEPayload, responseIKEMessage); err != nil {
			logger.IKELog.Errorf("encrypting IKE message failed: %+v", err)
			return
		}

		// Shift state
		ikeSecurityAssociation.State++

		// Send IKE message to UE
		SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage)

	case EAPSignalling:
		// If success, N3IWF will send an UPLinkNASTransport to AMF
		if eap != nil {
			if eap.Code != ike_message.EAPCodeResponse {
				logger.IKELog.Errorln("received an EAP payload with code other than response. Drop the payload")
				return
			}
			if eap.Identifier != ikeSecurityAssociation.LastEAPIdentifier {
				logger.IKELog.Errorln("received an EAP payload with unmatched identifier. Drop the payload")
				return
			}

			eapTypeData := eap.EAPTypeData[0]
			var eapExpanded *ike_message.EAPExpanded

			switch eapTypeData.Type() {
			// TODO: handle
			// case ike_message.EAPTypeIdentity:
			// case ike_message.EAPTypeNotification:
			// case ike_message.EAPTypeNak:
			case ike_message.EAPTypeExpanded:
				eapExpanded = eapTypeData.(*ike_message.EAPExpanded)
			default:
				logger.IKELog.Errorf("received EAP packet with type other than EAP expanded type: %d", eapTypeData.Type())
				return
			}

			if eapExpanded.VendorID != ike_message.VendorID3GPP {
				logger.IKELog.Errorln("the peer sent EAP expended packet with wrong vendor ID. Drop the packet")
				return
			}
			if eapExpanded.VendorType != ike_message.VendorTypeEAP5G {
				logger.IKELog.Errorln("the peer sent EAP expanded packet with wrong vendor type. Drop the packet")
				return
			}

			eap5GMessageID, anParameters, nasPDU, err := UnmarshalEAP5GData(eapExpanded.VendorData)
			if err != nil {
				logger.IKELog.Errorf("unmarshalling EAP-5G packet failed: %+v", err)
				return
			}

			if eap5GMessageID == ike_message.EAP5GType5GStop {
				// Send EAP failure
				// Build IKE message
				responseIKEMessage.BuildIKEHeader(message.InitiatorSPI, message.ResponderSPI,
					ike_message.IKE_AUTH, ike_message.ResponseBitCheck, message.MessageID)
				responseIKEMessage.Payloads.Reset()

				// EAP
				identifier, err := GenerateRandomUint8()
				if err != nil {
					logger.IKELog.Errorf("generate random uint8 failed: %+v", err)
					return
				}
				responseIKEPayload.BuildEAPFailure(identifier)

				if err := EncryptProcedure(ikeSecurityAssociation, responseIKEPayload, responseIKEMessage); err != nil {
					logger.IKELog.Errorf("encrypting IKE message failed: %+v", err)
					return
				}

				// Send IKE message to UE
				SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage)
				return
			}

			// Send Initial UE Message or Uplink NAS Transport
			if anParameters != nil {
				// AMF selection
				selectedAMF := n3iwfSelf.AMFSelection(anParameters.GUAMI)
				if selectedAMF == nil {
					logger.IKELog.Warnln("no avalible AMF for this UE")
					return
				}

				// Create UE context
				ue := n3iwfSelf.NewN3iwfUe()

				// Relative context
				ikeSecurityAssociation.ThisUE = ue
				ue.N3IWFIKESecurityAssociation = ikeSecurityAssociation
				ue.AMF = selectedAMF

				// Store some information in conext
				ikeSecurityAssociation.MessageID = message.MessageID

				ue.IKEConnection = &context.UDPSocketInfo{
					Conn:      udpConn,
					N3IWFAddr: n3iwfAddr,
					UEAddr:    ueAddr,
				}
				ue.IPAddrv4 = ueAddr.IP.To4().String()
				ue.PortNumber = int32(ueAddr.Port)
				ue.RRCEstablishmentCause = int16(anParameters.EstablishmentCause.Value)

				// Send Initial UE Message
				ngap_message.SendInitialUEMessage(selectedAMF, ue, nasPDU)
			} else {
				ue := ikeSecurityAssociation.ThisUE
				amf := ue.AMF

				// Store some information in context
				ikeSecurityAssociation.MessageID = message.MessageID

				ue.IKEConnection = &context.UDPSocketInfo{
					Conn:      udpConn,
					N3IWFAddr: n3iwfAddr,
					UEAddr:    ueAddr,
				}

				// Send Uplink NAS Transport
				ngap_message.SendUplinkNASTransport(amf, ue, nasPDU)
			}
		} else {
			logger.IKELog.Errorln("EAP is nil")
		}

	case PostSignalling:
		// Load needed information
		thisUE := ikeSecurityAssociation.ThisUE

		// Prepare pseudorandom function for calculating/verifying authentication data
		pseudorandomFunction, ok := NewPseudorandomFunction(thisUE.Kn3iwf, transformPseudorandomFunction.TransformID)
		if !ok {
			logger.IKELog.Error("get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen")
			return
		}
		if _, err := pseudorandomFunction.Write([]byte("Key Pad for IKEv2")); err != nil {
			logger.IKELog.Errorf("pseudorandom function write error: %+v", err)
			return
		}
		secret := pseudorandomFunction.Sum(nil)
		pseudorandomFunction, ok = NewPseudorandomFunction(secret, transformPseudorandomFunction.TransformID)
		if !ok {
			logger.IKELog.Error("get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen")
			return
		}

		if authentication != nil {
			// Verifying remote AUTH
			pseudorandomFunction.Reset()
			if _, err := pseudorandomFunction.Write(ikeSecurityAssociation.RemoteUnsignedAuthentication); err != nil {
				logger.IKELog.Errorf("pseudorandom function write error: %+v", err)
				return
			}
			expectedAuthenticationData := pseudorandomFunction.Sum(nil)

			logger.IKELog.Debugf("expected Authentication Data: %s", hex.Dump(expectedAuthenticationData))
			// TODO: Finish authentication test for UE and N3IWF
			/*
				if !bytes.Equal(authentication.AuthenticationData, expectedAuthenticationData) {
					logger.IKELog.Warnln("peer authentication failed")
					// Inform UE the authentication has failed
					// Build IKE message
					responseIKEMessage.BuildIKEHeader(message.InitiatorSPI, message.ResponderSPI,
						ike_message.IKE_AUTH, ike_message.ResponseBitCheck, message.MessageID)
					responseIKEMessage.Payloads.Reset()

					// Notification
					responseIKEPayload.BuildNotification(ike_message.TypeNone, ike_message.AUTHENTICATION_FAILED, nil, nil)

					if err := EncryptProcedure(ikeSecurityAssociation, responseIKEPayload, responseIKEMessage); err != nil {
						logger.IKELog.Errorf("encrypting IKE message failed: %+v", err)
						return
					}

					// Send IKE message to UE
					SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage)
					return
				}
			*/
		} else {
			logger.IKELog.Warnln("peer authentication failed")
			// Inform UE the authentication has failed
			// Build IKE message
			responseIKEMessage.BuildIKEHeader(message.InitiatorSPI, message.ResponderSPI,
				ike_message.IKE_AUTH, ike_message.ResponseBitCheck, message.MessageID)
			responseIKEMessage.Payloads.Reset()

			// Notification
			responseIKEPayload.BuildNotification(ike_message.TypeNone, ike_message.AUTHENTICATION_FAILED, nil, nil)

			if err := EncryptProcedure(ikeSecurityAssociation, responseIKEPayload, responseIKEMessage); err != nil {
				logger.IKELog.Errorf("encrypting IKE message failed: %+v", err)
				return
			}

			// Send IKE message to UE
			SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage)
			return
		}

		// Parse configuration request to get if the UE has requested internal address,
		// and prepare configuration payload to UE
		var addrRequest bool = false

		if configuration != nil {
			logger.IKELog.Debugf("received configuration payload with type: %d", configuration.ConfigurationType)

			var attribute *ike_message.IndividualConfigurationAttribute
			for _, attribute = range configuration.ConfigurationAttribute {
				switch attribute.Type {
				case ike_message.INTERNAL_IP4_ADDRESS:
					addrRequest = true
					if len(attribute.Value) != 0 {
						logger.IKELog.Debugf("got client requested address: %d.%d.%d.%d",
							attribute.Value[0], attribute.Value[1], attribute.Value[2], attribute.Value[3])
					}
				default:
					logger.IKELog.Warnf("receive other type of configuration request: %d", attribute.Type)
				}
			}
		} else {
			logger.IKELog.Warnln("configuration is nil. UE did not sent any configuration request")
		}

		// Build response IKE message
		responseIKEMessage.BuildIKEHeader(message.InitiatorSPI, message.ResponderSPI,
			ike_message.IKE_AUTH, ike_message.ResponseBitCheck, message.MessageID)
		responseIKEMessage.Payloads.Reset()

		// Calculate local AUTH
		pseudorandomFunction.Reset()
		if _, err := pseudorandomFunction.Write(ikeSecurityAssociation.LocalUnsignedAuthentication); err != nil {
			logger.IKELog.Errorf("pseudorandom function write error: %+v", err)
			return
		}

		// Authentication
		responseIKEPayload.BuildAuthentication(
			ike_message.SharedKeyMesageIntegrityCode, pseudorandomFunction.Sum(nil))

		// Prepare configuration payload and traffic selector payload for initiator and responder
		var ueIPAddr, n3iwfIPAddr net.IP
		if addrRequest {
			// IP addresses (IPSec)
			ueIPAddr = n3iwfSelf.NewInternalUEIPAddr(thisUE)
			n3iwfIPAddr = net.ParseIP(n3iwfSelf.IpSecGatewayAddress)

			responseConfiguration := responseIKEPayload.BuildConfiguration(ike_message.CFG_REPLY)
			responseConfiguration.ConfigurationAttribute.BuildConfigurationAttribute(ike_message.INTERNAL_IP4_ADDRESS, ueIPAddr)
			responseConfiguration.ConfigurationAttribute.BuildConfigurationAttribute(
				ike_message.INTERNAL_IP4_NETMASK, n3iwfSelf.Subnet.Mask)

			thisUE.IPSecInnerIP = ueIPAddr
			if ipsecInnerIPAddr, err := net.ResolveIPAddr("ip", ueIPAddr.String()); err != nil {
				logger.IKELog.Errorf("resolve UE inner IP address failed: %+v", err)
				return
			} else {
				thisUE.IPSecInnerIPAddr = ipsecInnerIPAddr
			}
			logger.IKELog.Debugf("ueIPAddr: %+v", ueIPAddr)
		} else {
			logger.IKELog.Errorln("UE did not send any configuration request for its IP address")
			return
		}

		// Security Association
		responseIKEPayload = append(responseIKEPayload, ikeSecurityAssociation.IKEAuthResponseSA)

		// Traffic Selectors initiator/responder
		responseTrafficSelectorInitiator := responseIKEPayload.BuildTrafficSelectorInitiator()
		responseTrafficSelectorInitiator.TrafficSelectors.BuildIndividualTrafficSelector(
			ike_message.TS_IPV4_ADDR_RANGE, ike_message.IPProtocolAll, 0, 65535, ueIPAddr.To4(), ueIPAddr.To4())
		responseTrafficSelectorResponder := responseIKEPayload.BuildTrafficSelectorResponder()
		responseTrafficSelectorResponder.TrafficSelectors.BuildIndividualTrafficSelector(
			ike_message.TS_IPV4_ADDR_RANGE, ike_message.IPProtocolAll, 0, 65535, n3iwfIPAddr.To4(), n3iwfIPAddr.To4())

		// Record traffic selector to IKE security association
		ikeSecurityAssociation.TrafficSelectorInitiator = responseTrafficSelectorInitiator
		ikeSecurityAssociation.TrafficSelectorResponder = responseTrafficSelectorResponder

		// Get xfrm needed data
		// As specified in RFC 7296, ESP negotiate two child security association (pair) in one IKE_AUTH
		childSecurityAssociationContext, err := thisUE.CreateIKEChildSecurityAssociation(ikeSecurityAssociation.IKEAuthResponseSA)
		if err != nil {
			logger.IKELog.Errorf("create child security association context failed: %+v", err)
			return
		}
		err = parseIPAddressInformationToChildSecurityAssociation(childSecurityAssociationContext, ueAddr.IP,
			ikeSecurityAssociation.TrafficSelectorResponder.TrafficSelectors[0],
			ikeSecurityAssociation.TrafficSelectorInitiator.TrafficSelectors[0])
		if err != nil {
			logger.IKELog.Errorf("parse IP address to child security association failed: %+v", err)
			return
		}
		// Select TCP traffic
		childSecurityAssociationContext.SelectedIPProtocol = unix.IPPROTO_TCP

		if errGen := GenerateKeyForChildSA(ikeSecurityAssociation, childSecurityAssociationContext); errGen != nil {
			logger.IKELog.Errorf("generate key for child SA failed: %+v", errGen)
			return
		}
		// NAT-T concern
		if ikeSecurityAssociation.UEIsBehindNAT || ikeSecurityAssociation.N3IWFIsBehindNAT {
			childSecurityAssociationContext.EnableEncapsulate = true
			childSecurityAssociationContext.N3IWFPort = n3iwfAddr.Port
			childSecurityAssociationContext.NATPort = ueAddr.Port
		}

		// Notification(NAS_IP_ADDRESS)
		responseIKEPayload.BuildNotifyNAS_IP4_ADDRESS(n3iwfSelf.IpSecGatewayAddress)

		// Notification(NSA_TCP_PORT)
		responseIKEPayload.BuildNotifyNAS_TCP_PORT(n3iwfSelf.TcpPort)

		if errEncrypt := EncryptProcedure(ikeSecurityAssociation, responseIKEPayload, responseIKEMessage); errEncrypt != nil {
			logger.IKELog.Errorf("encrypting IKE message failed: %+v", errEncrypt)
			return
		}

		// Apply XFRM rules
		if err = ApplyXFRMRule(false, childSecurityAssociationContext); err != nil {
			logger.IKELog.Errorf("applying XFRM rules failed: %+v", err)
			return
		}

		// Send IKE message to UE
		SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage)

		// If needed, setup PDU session
		if thisUE.TemporaryPDUSessionSetupData != nil {
			for {
				if len(thisUE.TemporaryPDUSessionSetupData.UnactivatedPDUSession) != 0 {
					pduSessionID := thisUE.TemporaryPDUSessionSetupData.UnactivatedPDUSession[0]
					pduSession := thisUE.PduSessionList[pduSessionID]

					// Add MessageID for IKE security association
					ikeSecurityAssociation.MessageID++

					// Send CREATE_CHILD_SA to UE
					ikeMessage := new(ike_message.IKEMessage)
					var ikePayload ike_message.IKEPayloadContainer

					// Build IKE message
					ikeMessage.BuildIKEHeader(ikeSecurityAssociation.LocalSPI,
						ikeSecurityAssociation.RemoteSPI, ike_message.CREATE_CHILD_SA,
						ike_message.InitiatorBitCheck, ikeSecurityAssociation.MessageID)
					ikeMessage.Payloads.Reset()

					// Build SA
					requestSA := ikePayload.BuildSecurityAssociation()

					// Allocate SPI
					var spi uint32
					spiByte := make([]byte, 4)
					for {
						randomUint64 := GenerateRandomNumber().Uint64()
						if _, ok := n3iwfSelf.ChildSA.Load(uint32(randomUint64)); !ok {
							spi = uint32(randomUint64)
							break
						}
					}
					binary.BigEndian.PutUint32(spiByte, spi)

					// First Proposal - Proposal No.1
					proposal := requestSA.Proposals.BuildProposal(1, ike_message.TypeESP, spiByte)

					// Encryption transform
					var attributeType uint16 = ike_message.AttributeTypeKeyLength
					var attributeValue uint16 = 256
					proposal.EncryptionAlgorithm.BuildTransform(ike_message.TypeEncryptionAlgorithm,
						ike_message.ENCR_AES_CBC, &attributeType, &attributeValue, nil)
					// Integrity transform
					if pduSession.SecurityIntegrity {
						proposal.IntegrityAlgorithm.BuildTransform(
							ike_message.TypeIntegrityAlgorithm, ike_message.AUTH_HMAC_SHA1_96, nil, nil, nil)
					}
					// ESN transform
					proposal.ExtendedSequenceNumbers.BuildTransform(
						ike_message.TypeExtendedSequenceNumbers, ike_message.ESN_NO, nil, nil, nil)

					// Build Nonce
					nonceData := GenerateRandomNumber().Bytes()
					ikePayload.BuildNonce(nonceData)

					// Store nonce into context
					ikeSecurityAssociation.ConcatenatedNonce = nonceData

					// TSi
					ueIPAddr := thisUE.IPSecInnerIP
					tsi := ikePayload.BuildTrafficSelectorInitiator()
					tsi.TrafficSelectors.BuildIndividualTrafficSelector(ike_message.TS_IPV4_ADDR_RANGE, ike_message.IPProtocolAll,
						0, 65535, ueIPAddr, ueIPAddr)
					// TSr
					n3iwfIPAddr := net.ParseIP(n3iwfSelf.IpSecGatewayAddress)
					tsr := ikePayload.BuildTrafficSelectorResponder()
					tsr.TrafficSelectors.BuildIndividualTrafficSelector(ike_message.TS_IPV4_ADDR_RANGE, ike_message.IPProtocolAll,
						0, 65535, n3iwfIPAddr, n3iwfIPAddr)

					// Notify-Qos
					ikePayload.BuildNotify5G_QOS_INFO(uint8(pduSessionID), pduSession.QFIList, true, false, 0)

					// Notify-UP_IP_ADDRESS
					ikePayload.BuildNotifyUP_IP4_ADDRESS(n3iwfSelf.IpSecGatewayAddress)

					if err := EncryptProcedure(
						thisUE.N3IWFIKESecurityAssociation, ikePayload, ikeMessage); err != nil {
						logger.IKELog.Errorf("encrypting IKE message failed: %+v", err)
						thisUE.TemporaryPDUSessionSetupData.UnactivatedPDUSession = thisUE.TemporaryPDUSessionSetupData.UnactivatedPDUSession[1:]
						cause := ngapType.Cause{
							Present: ngapType.CausePresentTransport,
							Transport: &ngapType.CauseTransport{
								Value: ngapType.CauseTransportPresentTransportResourceUnavailable,
							},
						}
						transfer, err := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(cause, nil)
						if err != nil {
							logger.IKELog.Errorf("build PDU Session Resource Setup Unsuccessful Transfer failed: %+v", err)
							continue
						}
						ngap_message.AppendPDUSessionResourceFailedToSetupListCxtRes(
							thisUE.TemporaryPDUSessionSetupData.FailedListCxtRes, pduSessionID, transfer)
						continue
					}

					SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage)
					break
				} else {
					// Send Initial Context Setup Response to AMF
					ngap_message.SendInitialContextSetupResponse(thisUE.AMF, thisUE,
						thisUE.TemporaryPDUSessionSetupData.SetupListCxtRes,
						thisUE.TemporaryPDUSessionSetupData.FailedListCxtRes, nil)
					break
				}
			}
		} else {
			// Send Initial Context Setup Response to AMF
			ngap_message.SendInitialContextSetupResponse(thisUE.AMF, thisUE, nil, nil, nil)
		}
	}
}

func HandleCREATECHILDSA(udpConn *net.UDPConn, n3iwfAddr, ueAddr *net.UDPAddr, message *ike_message.IKEMessage) {
	logger.IKELog.Infoln("handle CREATE_CHILD_SA")

	var encryptedPayload *ike_message.Encrypted

	n3iwfSelf := context.N3IWFSelf()

	responseIKEMessage := new(ike_message.IKEMessage)

	if message == nil {
		logger.IKELog.Errorln("IKE Message is nil")
		return
	}

	// parse IKE header and setup IKE context
	// check major version
	majorVersion := ((message.Version & 0xf0) >> 4)
	if majorVersion > 2 {
		logger.IKELog.Warnln("received an IKE message with higher major version")
		// send INFORMATIONAL type message with INVALID_MAJOR_VERSION Notify payload ( OUTSIDE IKE SA )
		responseIKEMessage.BuildIKEHeader(message.InitiatorSPI, message.ResponderSPI,
			ike_message.INFORMATIONAL, ike_message.ResponseBitCheck, message.MessageID)
		responseIKEMessage.Payloads.Reset()
		responseIKEMessage.Payloads.BuildNotification(ike_message.TypeNone, ike_message.INVALID_MAJOR_VERSION, nil, nil)

		SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage)

		return
	}

	// Find corresponding IKE security association
	localSPI := message.InitiatorSPI
	ikeSecurityAssociation, ok := n3iwfSelf.IKESALoad(localSPI)
	if !ok {
		logger.IKELog.Warnln("unrecognized SPI")
		// send INFORMATIONAL type message with INVALID_IKE_SPI Notify payload ( OUTSIDE IKE SA )
		responseIKEMessage.BuildIKEHeader(message.InitiatorSPI, 0, ike_message.INFORMATIONAL,
			ike_message.ResponseBitCheck, message.MessageID)
		responseIKEMessage.Payloads.Reset()
		responseIKEMessage.Payloads.BuildNotification(ike_message.TypeNone, ike_message.INVALID_IKE_SPI, nil, nil)

		SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage)

		return
	}

	for _, ikePayload := range message.Payloads {
		switch ikePayload.Type() {
		case ike_message.TypeSK:
			encryptedPayload = ikePayload.(*ike_message.Encrypted)
		default:
			logger.IKELog.Warnf(
				"get IKE payload (type %d) in CREATE_CHILD_SA message, this payload will not be handled by IKE handler",
				ikePayload.Type())
		}
	}

	decryptedIKEPayload, err := DecryptProcedure(ikeSecurityAssociation, message, encryptedPayload)
	if err != nil {
		logger.IKELog.Errorf("decrypt IKE message failed: %+v", err)
		return
	}

	// Parse payloads
	var securityAssociation *ike_message.SecurityAssociation
	var nonce *ike_message.Nonce
	var trafficSelectorInitiator *ike_message.TrafficSelectorInitiator
	var trafficSelectorResponder *ike_message.TrafficSelectorResponder

	for _, ikePayload := range decryptedIKEPayload {
		switch ikePayload.Type() {
		case ike_message.TypeSA:
			securityAssociation = ikePayload.(*ike_message.SecurityAssociation)
		case ike_message.TypeNiNr:
			nonce = ikePayload.(*ike_message.Nonce)
		case ike_message.TypeTSi:
			trafficSelectorInitiator = ikePayload.(*ike_message.TrafficSelectorInitiator)
		case ike_message.TypeTSr:
			trafficSelectorResponder = ikePayload.(*ike_message.TrafficSelectorResponder)
		default:
			logger.IKELog.Warnf(
				"get IKE payload (type %d) in IKE_AUTH message, this payload will not be handled by IKE handler",
				ikePayload.Type())
		}
	}

	// Record message ID
	ikeSecurityAssociation.MessageID = message.MessageID

	// UE context
	thisUE := ikeSecurityAssociation.ThisUE
	if thisUE == nil {
		logger.IKELog.Errorln("UE context is nil")
		return
	}
	// PDU session information
	if thisUE.TemporaryPDUSessionSetupData == nil {
		logger.IKELog.Errorln("no PDU session information")
		return
	}
	temporaryPDUSessionSetupData := thisUE.TemporaryPDUSessionSetupData
	if len(temporaryPDUSessionSetupData.UnactivatedPDUSession) == 0 {
		logger.IKELog.Errorln("no unactivated PDU session information")
		return
	}
	pduSessionID := temporaryPDUSessionSetupData.UnactivatedPDUSession[0]
	pduSession, ok := thisUE.PduSessionList[pduSessionID]
	if !ok {
		logger.IKELog.Errorf("no such PDU session [PDU session ID: %d]", pduSessionID)
		return
	}

	// Check received message
	if securityAssociation == nil {
		logger.IKELog.Errorln("the security association field is nil")
		return
	}

	if trafficSelectorInitiator == nil {
		logger.IKELog.Errorln("the traffic selector initiator field is nil")
		return
	}

	if trafficSelectorResponder == nil {
		logger.IKELog.Errorln("the traffic selector responder field is nil")
		return
	}

	// Nonce
	if nonce != nil {
		ikeSecurityAssociation.ConcatenatedNonce = append(ikeSecurityAssociation.ConcatenatedNonce, nonce.NonceData...)
	} else {
		logger.IKELog.Errorln("the nonce field is nil")
		// TODO: send error message to UE
		return
	}

	// Get xfrm needed data
	// As specified in RFC 7296, ESP negotiate two child security association (pair) in one IKE_AUTH
	childSecurityAssociationContext, err := thisUE.CreateIKEChildSecurityAssociation(securityAssociation)
	if err != nil {
		logger.IKELog.Errorf("create child security association context failed: %+v", err)
		return
	}
	err = parseIPAddressInformationToChildSecurityAssociation(childSecurityAssociationContext, ueAddr.IP,
		trafficSelectorInitiator.TrafficSelectors[0], trafficSelectorResponder.TrafficSelectors[0])
	if err != nil {
		logger.IKELog.Errorf("parse IP address to child security association failed: %+v", err)
		return
	}
	// Select GRE traffic
	childSecurityAssociationContext.SelectedIPProtocol = unix.IPPROTO_GRE

	if errGen := GenerateKeyForChildSA(ikeSecurityAssociation, childSecurityAssociationContext); errGen != nil {
		logger.IKELog.Errorf("generate key for child SA failed: %+v", errGen)
		return
	}
	// NAT-T concern
	if ikeSecurityAssociation.UEIsBehindNAT || ikeSecurityAssociation.N3IWFIsBehindNAT {
		childSecurityAssociationContext.EnableEncapsulate = true
		childSecurityAssociationContext.N3IWFPort = n3iwfAddr.Port
		childSecurityAssociationContext.NATPort = ueAddr.Port
	}

	// Apply XFRM rules
	if err = ApplyXFRMRule(true, childSecurityAssociationContext); err != nil {
		logger.IKELog.Errorf("applying XFRM rules failed: %+v", err)
		return
	}

	// Append NGAP PDU session resource setup response transfer
	transfer, err := ngap_message.BuildPDUSessionResourceSetupResponseTransfer(pduSession)
	if err != nil {
		logger.IKELog.Errorf("build PDU session resource setup response transfer failed: %+v", err)
		return
	}
	ngap_message.AppendPDUSessionResourceSetupListSURes(
		temporaryPDUSessionSetupData.SetupListSURes, pduSessionID, transfer)

	// Remove handled PDU session setup request from queue
	temporaryPDUSessionSetupData.UnactivatedPDUSession = temporaryPDUSessionSetupData.UnactivatedPDUSession[1:]

	for {
		if len(temporaryPDUSessionSetupData.UnactivatedPDUSession) != 0 {
			ngapProcedure := temporaryPDUSessionSetupData.NGAPProcedureCode.Value
			pduSessionID := temporaryPDUSessionSetupData.UnactivatedPDUSession[0]
			pduSession := thisUE.PduSessionList[pduSessionID]

			// Add MessageID for IKE security association
			ikeSecurityAssociation.MessageID++

			// Send CREATE_CHILD_SA to UE
			ikeMessage := new(ike_message.IKEMessage)
			var ikePayload ike_message.IKEPayloadContainer

			// Build IKE message
			ikeMessage.BuildIKEHeader(ikeSecurityAssociation.LocalSPI,
				ikeSecurityAssociation.RemoteSPI, ike_message.CREATE_CHILD_SA,
				ike_message.InitiatorBitCheck, ikeSecurityAssociation.MessageID)
			ikeMessage.Payloads.Reset()

			// Build SA
			requestSA := ikePayload.BuildSecurityAssociation()

			// Allocate SPI
			var spi uint32
			spiByte := make([]byte, 4)
			for {
				randomUint64 := GenerateRandomNumber().Uint64()
				if _, ok := n3iwfSelf.ChildSA.Load(uint32(randomUint64)); !ok {
					spi = uint32(randomUint64)
					break
				}
			}
			binary.BigEndian.PutUint32(spiByte, spi)

			// First Proposal - Proposal No.1
			proposal := requestSA.Proposals.BuildProposal(1, ike_message.TypeESP, spiByte)

			// Encryption transform
			var attributeType uint16 = ike_message.AttributeTypeKeyLength
			var attributeValue uint16 = 256
			proposal.EncryptionAlgorithm.BuildTransform(ike_message.TypeEncryptionAlgorithm,
				ike_message.ENCR_AES_CBC, &attributeType, &attributeValue, nil)
			// Integrity transform
			if pduSession.SecurityIntegrity {
				proposal.IntegrityAlgorithm.BuildTransform(ike_message.TypeIntegrityAlgorithm,
					ike_message.AUTH_HMAC_MD5_96, nil, nil, nil)
			}
			// ESN transform
			proposal.ExtendedSequenceNumbers.BuildTransform(ike_message.TypeExtendedSequenceNumbers,
				ike_message.ESN_NO, nil, nil, nil)

			// Build Nonce
			nonceData := GenerateRandomNumber().Bytes()
			ikePayload.BuildNonce(nonceData)

			// Store nonce into context
			ikeSecurityAssociation.ConcatenatedNonce = nonceData

			// TSi
			ueIPAddr := thisUE.IPSecInnerIP
			tsi := ikePayload.BuildTrafficSelectorInitiator()
			tsi.TrafficSelectors.BuildIndividualTrafficSelector(ike_message.TS_IPV4_ADDR_RANGE, ike_message.IPProtocolAll,
				0, 65535, ueIPAddr, ueIPAddr)
			// TSr
			n3iwfIPAddr := net.ParseIP(n3iwfSelf.IpSecGatewayAddress)
			tsr := ikePayload.BuildTrafficSelectorResponder()
			tsr.TrafficSelectors.BuildIndividualTrafficSelector(ike_message.TS_IPV4_ADDR_RANGE, ike_message.IPProtocolAll,
				0, 65535, n3iwfIPAddr, n3iwfIPAddr)

			// Notify-Qos
			ikePayload.BuildNotify5G_QOS_INFO(uint8(pduSessionID), pduSession.QFIList, true, false, 0)

			// Notify-UP_IP_ADDRESS
			ikePayload.BuildNotifyUP_IP4_ADDRESS(n3iwfSelf.IpSecGatewayAddress)

			if err := EncryptProcedure(thisUE.N3IWFIKESecurityAssociation, ikePayload, ikeMessage); err != nil {
				logger.IKELog.Errorf("encrypting IKE message failed: %+v", err)
				temporaryPDUSessionSetupData.UnactivatedPDUSession = temporaryPDUSessionSetupData.UnactivatedPDUSession[1:]
				cause := ngapType.Cause{
					Present: ngapType.CausePresentTransport,
					Transport: &ngapType.CauseTransport{
						Value: ngapType.CauseTransportPresentTransportResourceUnavailable,
					},
				}
				transfer, err := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(cause, nil)
				if err != nil {
					logger.IKELog.Errorf("build PDU Session Resource Setup Unsuccessful Transfer Failed: %+v", err)
					continue
				}
				if ngapProcedure == ngapType.ProcedureCodeInitialContextSetup {
					ngap_message.AppendPDUSessionResourceFailedToSetupListCxtRes(
						temporaryPDUSessionSetupData.FailedListCxtRes, pduSessionID, transfer)
				} else {
					ngap_message.AppendPDUSessionResourceFailedToSetupListSURes(
						temporaryPDUSessionSetupData.FailedListSURes, pduSessionID, transfer)
				}
				continue
			}

			SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage)
			break
		} else {
			// Send Response to AMF
			ngapProcedure := temporaryPDUSessionSetupData.NGAPProcedureCode.Value
			if ngapProcedure == ngapType.ProcedureCodeInitialContextSetup {
				ngap_message.SendInitialContextSetupResponse(thisUE.AMF, thisUE,
					temporaryPDUSessionSetupData.SetupListCxtRes,
					temporaryPDUSessionSetupData.FailedListCxtRes, nil)
			} else {
				ngap_message.SendPDUSessionResourceSetupResponse(thisUE.AMF, thisUE,
					temporaryPDUSessionSetupData.SetupListSURes,
					temporaryPDUSessionSetupData.FailedListSURes, nil)
			}
			break
		}
	}
}

func is_supported(transformType uint8, transformID uint16, attributePresent bool, attributeValue uint16) bool {
	switch transformType {
	case ike_message.TypeEncryptionAlgorithm:
		switch transformID {
		case ike_message.ENCR_DES_IV64:
			return false
		case ike_message.ENCR_DES:
			return false
		case ike_message.ENCR_3DES:
			return false
		case ike_message.ENCR_RC5:
			return false
		case ike_message.ENCR_IDEA:
			return false
		case ike_message.ENCR_CAST:
			return false
		case ike_message.ENCR_BLOWFISH:
			return false
		case ike_message.ENCR_3IDEA:
			return false
		case ike_message.ENCR_DES_IV32:
			return false
		case ike_message.ENCR_NULL:
			return false
		case ike_message.ENCR_AES_CBC:
			if attributePresent {
				switch attributeValue {
				case 128:
					return true
				case 192:
					return true
				case 256:
					return true
				default:
					return false
				}
			} else {
				return false
			}
		case ike_message.ENCR_AES_CTR:
			return false
		default:
			return false
		}
	case ike_message.TypePseudorandomFunction:
		switch transformID {
		case ike_message.PRF_HMAC_MD5:
			return true
		case ike_message.PRF_HMAC_SHA1:
			return true
		case ike_message.PRF_HMAC_TIGER:
			return false
		default:
			return false
		}
	case ike_message.TypeIntegrityAlgorithm:
		switch transformID {
		case ike_message.AUTH_NONE:
			return false
		case ike_message.AUTH_HMAC_MD5_96:
			return true
		case ike_message.AUTH_HMAC_SHA1_96:
			return true
		case ike_message.AUTH_DES_MAC:
			return false
		case ike_message.AUTH_KPDK_MD5:
			return false
		case ike_message.AUTH_AES_XCBC_96:
			return false
		default:
			return false
		}
	case ike_message.TypeDiffieHellmanGroup:
		switch transformID {
		case ike_message.DH_NONE:
			return false
		case ike_message.DH_768_BIT_MODP:
			return false
		case ike_message.DH_1024_BIT_MODP:
			return true
		case ike_message.DH_1536_BIT_MODP:
			return false
		case ike_message.DH_2048_BIT_MODP:
			return true
		case ike_message.DH_3072_BIT_MODP:
			return false
		case ike_message.DH_4096_BIT_MODP:
			return false
		case ike_message.DH_6144_BIT_MODP:
			return false
		case ike_message.DH_8192_BIT_MODP:
			return false
		default:
			return false
		}
	default:
		return false
	}
}

func is_Kernel_Supported(
	transformType uint8, transformID uint16, attributePresent bool, attributeValue uint16,
) bool {
	switch transformType {
	case ike_message.TypeEncryptionAlgorithm:
		switch transformID {
		case ike_message.ENCR_DES_IV64:
			return false
		case ike_message.ENCR_DES:
			return true
		case ike_message.ENCR_3DES:
			return true
		case ike_message.ENCR_RC5:
			return false
		case ike_message.ENCR_IDEA:
			return false
		case ike_message.ENCR_CAST:
			if attributePresent {
				switch attributeValue {
				case 128:
					return true
				case 256:
					return false
				default:
					return false
				}
			} else {
				return false
			}
		case ike_message.ENCR_BLOWFISH:
			return true
		case ike_message.ENCR_3IDEA:
			return false
		case ike_message.ENCR_DES_IV32:
			return false
		case ike_message.ENCR_NULL:
			return true
		case ike_message.ENCR_AES_CBC:
			if attributePresent {
				switch attributeValue {
				case 128:
					return true
				case 192:
					return true
				case 256:
					return true
				default:
					return false
				}
			} else {
				return false
			}
		case ike_message.ENCR_AES_CTR:
			if attributePresent {
				switch attributeValue {
				case 128:
					return true
				case 192:
					return true
				case 256:
					return true
				default:
					return false
				}
			} else {
				return false
			}
		default:
			return false
		}
	case ike_message.TypeIntegrityAlgorithm:
		switch transformID {
		case ike_message.AUTH_NONE:
			return false
		case ike_message.AUTH_HMAC_MD5_96:
			return true
		case ike_message.AUTH_HMAC_SHA1_96:
			return true
		case ike_message.AUTH_DES_MAC:
			return false
		case ike_message.AUTH_KPDK_MD5:
			return false
		case ike_message.AUTH_AES_XCBC_96:
			return true
		default:
			return false
		}
	case ike_message.TypeDiffieHellmanGroup:
		switch transformID {
		case ike_message.DH_NONE:
			return false
		case ike_message.DH_768_BIT_MODP:
			return false
		case ike_message.DH_1024_BIT_MODP:
			return false
		case ike_message.DH_1536_BIT_MODP:
			return false
		case ike_message.DH_2048_BIT_MODP:
			return false
		case ike_message.DH_3072_BIT_MODP:
			return false
		case ike_message.DH_4096_BIT_MODP:
			return false
		case ike_message.DH_6144_BIT_MODP:
			return false
		case ike_message.DH_8192_BIT_MODP:
			return false
		default:
			return false
		}
	case ike_message.TypeExtendedSequenceNumbers:
		switch transformID {
		case ike_message.ESN_NO:
			return true
		case ike_message.ESN_NEED:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func parseIPAddressInformationToChildSecurityAssociation(
	childSecurityAssociation *context.ChildSecurityAssociation,
	uePublicIPAddr net.IP,
	trafficSelectorLocal *ike_message.IndividualTrafficSelector,
	trafficSelectorRemote *ike_message.IndividualTrafficSelector,
) error {
	if childSecurityAssociation == nil {
		return errors.New("childSecurityAssociation is nil")
	}

	childSecurityAssociation.PeerPublicIPAddr = uePublicIPAddr
	childSecurityAssociation.LocalPublicIPAddr = net.ParseIP(context.N3IWFSelf().IkeBindAddress)

	logger.IKELog.Debugf("local TS: %+v", trafficSelectorLocal.StartAddress)
	logger.IKELog.Debugf("remote TS: %+v", trafficSelectorRemote.StartAddress)

	childSecurityAssociation.TrafficSelectorLocal = net.IPNet{
		IP:   trafficSelectorLocal.StartAddress,
		Mask: []byte{255, 255, 255, 255},
	}

	childSecurityAssociation.TrafficSelectorRemote = net.IPNet{
		IP:   trafficSelectorRemote.StartAddress,
		Mask: []byte{255, 255, 255, 255},
	}

	return nil
}
