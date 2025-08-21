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
	"fmt"
	"math"
	"net"
	"sync/atomic"
	"time"

	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/factory"
	"github.com/omec-project/n3iwf/ike/message"
	"github.com/omec-project/n3iwf/ike/security"
	"github.com/omec-project/n3iwf/ike/security/dh"
	"github.com/omec-project/n3iwf/ike/security/encr"
	"github.com/omec-project/n3iwf/ike/security/integ"
	"github.com/omec-project/n3iwf/ike/security/prf"
	"github.com/omec-project/n3iwf/ike/xfrm"
	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/n3iwf/util"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Helper function to parse IKE payloads
func parseIKEPayloads(payloads []message.IKEPayload) map[message.IKEPayloadType]any {
	result := make(map[message.IKEPayloadType]any)
	for _, ikePayload := range payloads {
		typeID := ikePayload.Type()
		switch typeID {
		case message.TypeSA, message.TypeKE, message.TypeNiNr, message.TypeN,
			message.TypeIDi, message.TypeCERTreq, message.TypeCERT, message.TypeTSi,
			message.TypeTSr, message.TypeEAP, message.TypeAUTH, message.TypeCP:
			result[typeID] = ikePayload
		default:
			logger.IKELog.Warnf("get IKE payload (type %d), not handled", typeID)
		}
	}
	return result
}

// Helper for error response
func sendErrorResponse(udpConn *net.UDPConn, n3iwfAddr, ueAddr *net.UDPAddr, spiI, spiR uint64, msgType uint8, msgID uint32, notifyType uint16, key []byte) {
	var payload message.IKEPayloadContainer
	payload.Reset()
	payload.BuildNotification(message.TypeNone, notifyType, nil, key)
	msg := message.NewMessage(spiI, spiR, msgType, true, false, msgID, payload)
	if err := SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, msg, nil); err != nil {
		logger.IKELog.Errorf("sendErrorResponse: %v", err)
	}
}

func HandleIKESAINIT(udpConn *net.UDPConn, n3iwfAddr, ueAddr *net.UDPAddr, ikeMsg *message.IKEMessage, realMessage1 []byte) {
	logger.IKELog.Infoln("handle IKE_SA_INIT")

	payloads := parseIKEPayloads(ikeMsg.Payloads)
	securityAssociation, _ := payloads[message.TypeSA].(*message.SecurityAssociation)
	keyExcahge, _ := payloads[message.TypeKE].(*message.KeyExchange)
	nonce, _ := payloads[message.TypeNiNr].(*message.Nonce)
	var notifications []*message.Notification
	if n, ok := payloads[message.TypeN]; ok {
		notifications = append(notifications, n.(*message.Notification))
	}

	n3iwfCtx := context.N3IWFSelf()
	var responseIKEPayload message.IKEPayloadContainer
	var localNonce, concatenatedNonce []byte
	var chooseProposal message.ProposalContainer
	var localPublicValue []byte
	var chosenDiffieHellmanGroup uint16

	if securityAssociation == nil {
		logger.IKELog.Errorln("security association field is nil")
		sendErrorResponse(udpConn, n3iwfAddr, ueAddr, ikeMsg.InitiatorSPI, ikeMsg.ResponderSPI, message.IKE_SA_INIT, ikeMsg.MessageID, message.NO_PROPOSAL_CHOSEN, nil)
		return
	}
	responseSecurityAssociation := responseIKEPayload.BuildSecurityAssociation()
	chooseProposal = SelectProposal(securityAssociation.Proposals)
	responseSecurityAssociation.Proposals = append(responseSecurityAssociation.Proposals, chooseProposal...)

	if len(responseSecurityAssociation.Proposals) == 0 {
		logger.IKELog.Warnln("no proposal chosen")
		sendErrorResponse(udpConn, n3iwfAddr, ueAddr, ikeMsg.InitiatorSPI, ikeMsg.ResponderSPI, message.IKE_SA_INIT, ikeMsg.MessageID, message.NO_PROPOSAL_CHOSEN, nil)
		return
	}

	if keyExcahge == nil {
		logger.IKELog.Errorln("key exchange field is nil")
		return
	}
	chosenDiffieHellmanGroup = chooseProposal[0].DiffieHellmanGroup[0].TransformID
	if chosenDiffieHellmanGroup != keyExcahge.DiffieHellmanGroup {
		logger.IKELog.Warnln("Diffie-Hellman group mismatch")
		notificationData := make([]byte, 2)
		binary.BigEndian.PutUint16(notificationData, chosenDiffieHellmanGroup)
		sendErrorResponse(udpConn, n3iwfAddr, ueAddr, ikeMsg.InitiatorSPI, ikeMsg.ResponderSPI, message.IKE_SA_INIT, ikeMsg.MessageID, message.INVALID_KE_PAYLOAD, notificationData)
		return
	}

	if nonce == nil {
		logger.IKELog.Errorln("nonce field is nil")
		return
	}

	localNonceBigInt, err := security.GenerateRandomNumber()
	if err != nil {
		logger.IKELog.Errorf("HandleIKESAINIT: %v", err)
		return
	}
	localNonce = localNonceBigInt.Bytes()
	concatenatedNonce = append(nonce.NonceData, localNonce...)
	responseIKEPayload.BuildNonce(localNonce)

	ueBehindNAT, n3iwfBehindNAT, err := handleNATDetect(ikeMsg.InitiatorSPI, ikeMsg.ResponderSPI, notifications, ueAddr, n3iwfAddr)
	if err != nil {
		logger.IKELog.Errorf("Handle IKE_SA_INIT: %v", err)
		return
	}

	ikeSecurityAssociation := n3iwfCtx.NewIKESecurityAssociation()
	ikeSecurityAssociation.RemoteSPI = ikeMsg.InitiatorSPI
	ikeSecurityAssociation.InitiatorMessageID = ikeMsg.MessageID

	ikeSecurityAssociation.IKESAKey, localPublicValue, err = security.NewIKESAKey(chooseProposal[0], keyExcahge.KeyExchangeData, concatenatedNonce, ikeSecurityAssociation.RemoteSPI, ikeSecurityAssociation.LocalSPI)
	if err != nil {
		logger.IKELog.Errorf("handle IKE_SA_INIT: %v", err)
		return
	}

	logger.IKELog.Debugln(ikeSecurityAssociation.String())
	ikeSecurityAssociation.ConcatenatedNonce = append(ikeSecurityAssociation.ConcatenatedNonce, concatenatedNonce...)
	ikeSecurityAssociation.UeBehindNAT = ueBehindNAT
	ikeSecurityAssociation.N3iwfBehindNAT = n3iwfBehindNAT

	responseIKEPayload.BuildKeyExchange(chosenDiffieHellmanGroup, localPublicValue)
	if err = buildNATDetectNotifPayload(ikeSecurityAssociation, &responseIKEPayload, ueAddr, n3iwfAddr); err != nil {
		logger.IKELog.Warnf("handle IKE_SA_INIT: %v", err)
		return
	}

	responseIKEMessage := message.NewMessage(ikeMsg.InitiatorSPI, ikeSecurityAssociation.LocalSPI, message.IKE_SA_INIT, true, false, ikeMsg.MessageID, responseIKEPayload)
	ikeSecurityAssociation.InitiatorSignedOctets = append(realMessage1, localNonce...)

	responseIKEMessageData, err := responseIKEMessage.Encode()
	if err != nil {
		logger.IKELog.Errorf("encoding IKE ikeMsg failed: %+v", err)
		return
	}
	ikeSecurityAssociation.ResponderSignedOctets = append(responseIKEMessageData, nonce.NonceData...)
	var idPayload message.IKEPayloadContainer
	idPayload.BuildIdentificationResponder(message.ID_FQDN, []byte(n3iwfCtx.Fqdn))
	idPayloadData, err := idPayload.Encode()
	if err != nil {
		logger.IKELog.Errorf("encode IKE payload failed: %+v", err)
		return
	}
	ikeSecurityAssociation.Prf_r.Reset()
	_, err = ikeSecurityAssociation.Prf_r.Write(idPayloadData[4:])
	if err != nil {
		logger.IKELog.Errorf("pseudorandom function write error: %+v", err)
		return
	}
	ikeSecurityAssociation.ResponderSignedOctets = append(ikeSecurityAssociation.ResponderSignedOctets, ikeSecurityAssociation.Prf_r.Sum(nil)...) // MACedIDForR

	logger.IKELog.Debugf("local unsigned authentication data:\n%s", hex.Dump(ikeSecurityAssociation.ResponderSignedOctets))
	if err = SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage, nil); err != nil {
		logger.IKELog.Errorf("HandleIKESAINIT(): %v", err)
	}
}

// IKE_AUTH state
const (
	PreSignalling = iota
	EAPSignalling
	PostSignalling
	EndSignalling
	HandleCreateChildSA
)

func HandleIKEAUTH(udpConn *net.UDPConn, n3iwfAddr, ueAddr *net.UDPAddr,
	ikeMsg *message.IKEMessage, ikeSecurityAssociation *context.IKESecurityAssociation,
) {
	logger.IKELog.Debugln("handle IKE_AUTH")

	n3iwfCtx := context.N3IWFSelf()
	ipsecGwAddr := n3iwfCtx.IpSecGatewayAddress

	// Used for response
	var responseIKEPayload message.IKEPayloadContainer

	// Parse payloads
	var initiatorID *message.IdentificationInitiator
	var certificateRequest *message.CertificateRequest
	var certificate *message.Certificate
	var securityAssociation *message.SecurityAssociation
	var trafficSelectorInitiator *message.TrafficSelectorInitiator
	var trafficSelectorResponder *message.TrafficSelectorResponder
	var eap *message.EAP
	var authentication *message.Authentication
	var configuration *message.Configuration
	var ok bool

	for _, ikePayload := range ikeMsg.Payloads {
		switch ikePayload.Type() {
		case message.TypeIDi:
			initiatorID = ikePayload.(*message.IdentificationInitiator)
		case message.TypeCERTreq:
			certificateRequest = ikePayload.(*message.CertificateRequest)
		case message.TypeCERT:
			certificate = ikePayload.(*message.Certificate)
		case message.TypeSA:
			securityAssociation = ikePayload.(*message.SecurityAssociation)
		case message.TypeTSi:
			trafficSelectorInitiator = ikePayload.(*message.TrafficSelectorInitiator)
		case message.TypeTSr:
			trafficSelectorResponder = ikePayload.(*message.TrafficSelectorResponder)
		case message.TypeEAP:
			eap = ikePayload.(*message.EAP)
		case message.TypeAUTH:
			authentication = ikePayload.(*message.Authentication)
		case message.TypeCP:
			configuration = ikePayload.(*message.Configuration)
		default:
			logger.IKELog.Warnf(
				"get IKE payload (type %d) in IKE_AUTH ikeMsg, this payload will not be handled by IKE handler",
				ikePayload.Type())
		}
	}

	ikeSecurityAssociation.InitiatorMessageID = ikeMsg.MessageID

	switch ikeSecurityAssociation.State {
	case PreSignalling:
		if initiatorID == nil {
			logger.IKELog.Errorln("initiator identification field is nil")
			// TODO: send error ikeMsg to UE
			return
		}
		logger.IKELog.Debugln("encoding initiator for later IKE authentication")
		ikeSecurityAssociation.InitiatorID = initiatorID

		// Record maced identification for authentication
		idPayload := message.IKEPayloadContainer{
			initiatorID,
		}
		idPayloadData, err := idPayload.Encode()
		if err != nil {
			logger.IKELog.Errorf("encoding ID payload ikeMsg failed: %+v", err)
			return
		}
		ikeSecurityAssociation.Prf_i.Reset()
		if _, err := ikeSecurityAssociation.Prf_i.Write(idPayloadData[4:]); err != nil {
			logger.IKELog.Errorf("pseudorandom function write error: %v", err)
			return
		}
		ikeSecurityAssociation.InitiatorSignedOctets = append(ikeSecurityAssociation.InitiatorSignedOctets, ikeSecurityAssociation.Prf_i.Sum(nil)...)

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
			if security.CompareRootCertificate(n3iwfCtx.CertificateAuthority, certificateRequest.CertificateEncoding, certificateRequest.CertificationAuthority) {
				// TODO: Complete N3IWF Certificate/Certificate Authority related procedure
				logger.IKELog.Infoln("certificate Request sent from UE matches N3IWF CA")
			}
		}

		if certificate != nil {
			logger.IKELog.Infoln("UE send its certficate")
			ikeSecurityAssociation.InitiatorCertificate = certificate
		}

		if securityAssociation == nil {
			logger.IKELog.Errorln("security association field is nil")
			// TODO: send error ikeMsg to UE
			return
		}
		logger.IKELog.Debugln("parsing security association")
		responseSecurityAssociation := new(message.SecurityAssociation)

		for _, proposal := range securityAssociation.Proposals {
			var encryptionAlgorithmTransform *message.Transform = nil
			var integrityAlgorithmTransform *message.Transform = nil
			var diffieHellmanGroupTransform *message.Transform = nil
			var extendedSequenceNumbersTransform *message.Transform = nil

			if len(proposal.SPI) != 4 {
				continue // The SPI of ESP must be 32-bit
			}

			if len(proposal.EncryptionAlgorithm) > 0 {
				for _, transform := range proposal.EncryptionAlgorithm {
					if isTransformKernelSupported(message.TypeEncryptionAlgorithm, transform.TransformID,
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
					if isTransformKernelSupported(message.TypeIntegrityAlgorithm, transform.TransformID,
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
					if isTransformKernelSupported(message.TypeDiffieHellmanGroup, transform.TransformID,
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
					if isTransformKernelSupported(message.TypeExtendedSequenceNumbers, transform.TransformID,
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
			// Notification
			responseIKEPayload.BuildNotification(message.TypeNone, message.NO_PROPOSAL_CHOSEN, nil, nil)

			responseIKEMessage := message.NewMessage(ikeMsg.InitiatorSPI, ikeMsg.ResponderSPI,
				message.IKE_AUTH, true, false, ikeMsg.MessageID, responseIKEPayload)

			// Send IKE ikeMsg to UE
			err := SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage,
				ikeSecurityAssociation.IKESAKey)
			if err != nil {
				logger.IKELog.Errorf("HandleIKEAUTH(): %v", err)
			}
			return
		}

		ikeSecurityAssociation.IKEAuthResponseSA = responseSecurityAssociation

		if trafficSelectorInitiator == nil {
			logger.IKELog.Errorln("initiator traffic selector field is nil")
			// TODO: send error ikeMsg to UE
			return
		}
		logger.IKELog.Debugln("received traffic selector initiator from UE")
		ikeSecurityAssociation.TrafficSelectorInitiator = trafficSelectorInitiator

		if trafficSelectorResponder == nil {
			logger.IKELog.Errorln("responder traffic selector field is nil")
			// TODO: send error ikeMsg to UE
			return
		}
		logger.IKELog.Debugln("received traffic selector responder from UE")
		ikeSecurityAssociation.TrafficSelectorResponder = trafficSelectorResponder

		responseIKEPayload.Reset()
		// Identification
		responseIKEPayload.BuildIdentificationResponder(message.ID_FQDN, []byte(n3iwfCtx.Fqdn))

		// Certificate
		responseIKEPayload.BuildCertificate(message.X509CertificateSignature, n3iwfCtx.N3iwfCertificate)

		// Authentication Data
		logger.IKELog.Debugf("local authentication data:\n%s", hex.Dump(ikeSecurityAssociation.ResponderSignedOctets))
		sha1HashFunction := sha1.New()
		if _, err := sha1HashFunction.Write(ikeSecurityAssociation.ResponderSignedOctets); err != nil {
			logger.IKELog.Errorf("hash function write error: %+v", err)
			return
		}

		signedAuth, err := rsa.SignPKCS1v15(rand.Reader, n3iwfCtx.N3iwfPrivateKey, crypto.SHA1, sha1HashFunction.Sum(nil))
		if err != nil {
			logger.IKELog.Errorf("sign authentication data failed: %+v", err)
		}

		responseIKEPayload.BuildAuthentication(message.RSADigitalSignature, signedAuth)

		// EAP expanded 5G-Start
		var identifier uint8
		for {
			identifier, err = security.GenerateRandomUint8()
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

		responseIKEMessage := message.NewMessage(ikeMsg.InitiatorSPI, ikeMsg.ResponderSPI,
			message.IKE_AUTH, true, false, ikeMsg.MessageID, responseIKEPayload)

		// Shift state
		ikeSecurityAssociation.State++

		// Send IKE ikeMsg to UE
		err = SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage,
			ikeSecurityAssociation.IKESAKey)
		if err != nil {
			logger.IKELog.Errorf("HandleIKEAUTH(): %v", err)
			return
		}

	case EAPSignalling:
		// If success, N3IWF will send an UPLinkNASTransport to AMF
		if eap == nil {
			logger.IKELog.Errorln("EAP is nil")
			return
		}
		if eap.Code != message.EAPCodeResponse {
			logger.IKELog.Errorln("received an EAP payload with code other than response. Drop the payload")
			return
		}
		if eap.Identifier != ikeSecurityAssociation.LastEAPIdentifier {
			logger.IKELog.Errorln("received an EAP payload with unmatched identifier. Drop the payload")
			return
		}

		eapTypeData := eap.EAPTypeData[0]
		var eapExpanded *message.EAPExpanded

		switch eapTypeData.Type() {
		// TODO: handle
		// case message.EAPTypeIdentity:
		// case message.EAPTypeNotification:
		// case message.EAPTypeNak:
		case message.EAPTypeExpanded:
			eapExpanded = eapTypeData.(*message.EAPExpanded)
		default:
			logger.IKELog.Errorf("received EAP packet with type other than EAP expanded type: %d", eapTypeData.Type())
			return
		}

		if eapExpanded.VendorID != message.VendorID3GPP {
			logger.IKELog.Errorln("peer sent EAP expended packet with wrong vendor ID. Drop the packet")
			return
		}
		if eapExpanded.VendorType != message.VendorTypeEAP5G {
			logger.IKELog.Errorln("peer sent EAP expanded packet with wrong vendor type. Drop the packet")
			return
		}

		eap5GMessageID := eapExpanded.VendorData[0]
		logger.IKELog.Debugf("EAP5G MessageID: %+v", eap5GMessageID)

		if eap5GMessageID == message.EAP5GType5GStop {
			// Send EAP failure
			responseIKEPayload.Reset()

			// EAP
			identifier, err := security.GenerateRandomUint8()
			if err != nil {
				logger.IKELog.Errorf("generate random uint8 failed: %+v", err)
				return
			}
			responseIKEPayload.BuildEAPFailure(identifier)

			// Build IKE ikeMsg
			responseIKEMessage := message.NewMessage(ikeMsg.InitiatorSPI, ikeMsg.ResponderSPI,
				message.IKE_AUTH, true, false, ikeMsg.MessageID, responseIKEPayload)

			// Send IKE ikeMsg to UE
			err = SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage,
				ikeSecurityAssociation.IKESAKey)
			if err != nil {
				logger.IKELog.Errorf("HandleIKEAUTH(): %v", err)
			}
			return
		}

		var ranNgapId int64
		ranNgapId, ok = n3iwfCtx.NgapIdLoad(ikeSecurityAssociation.LocalSPI)
		if !ok {
			ranNgapId = 0
		}

		n3iwfCtx.NgapServer.RcvEventCh <- context.NewUnmarshalEAP5GDataEvt(
			ikeSecurityAssociation.LocalSPI,
			eapExpanded.VendorData,
			ikeSecurityAssociation.IkeUE != nil,
			ranNgapId,
		)

		ikeSecurityAssociation.IKEConnection = &context.UDPSocketInfo{
			Conn:      udpConn,
			N3IWFAddr: n3iwfAddr,
			UEAddr:    ueAddr,
		}

		ikeSecurityAssociation.InitiatorMessageID = ikeMsg.MessageID

	case PostSignalling:
		// Load needed information
		ikeUE := ikeSecurityAssociation.IkeUE

		// Prepare pseudorandom function for calculating/verifying authentication data
		pseudorandomFunction := ikeSecurityAssociation.PrfInfo.Init(ikeUE.Kn3iwf)
		if _, err := pseudorandomFunction.Write([]byte("Key Pad for IKEv2")); err != nil {
			logger.IKELog.Errorf("pseudorandom function write error: %+v", err)
			return
		}
		secret := pseudorandomFunction.Sum(nil)
		pseudorandomFunction = ikeSecurityAssociation.PrfInfo.Init(secret)

		if authentication != nil {
			// Verifying remote AUTH
			pseudorandomFunction.Reset()
			if _, err := pseudorandomFunction.Write(ikeSecurityAssociation.InitiatorSignedOctets); err != nil {
				logger.IKELog.Errorf("pseudorandom function write error: %+v", err)
				return
			}
			expectedAuthenticationData := pseudorandomFunction.Sum(nil)

			logger.IKELog.Debugf("Kn3iwf:\n%s", hex.Dump(ikeUE.Kn3iwf))
			logger.IKELog.Debugf("secret:\n%s", hex.Dump(secret))
			logger.IKELog.Debugf("InitiatorSignedOctets:\n%s", hex.Dump(ikeSecurityAssociation.InitiatorSignedOctets))
			logger.IKELog.Debugf("expected Authentication Data: %s", hex.Dump(expectedAuthenticationData))
			if !bytes.Equal(authentication.AuthenticationData, expectedAuthenticationData) {
				logger.IKELog.Warnln("peer authentication failed")
				// Inform UE the authentication has failed
				responseIKEPayload.Reset()

				// Notification
				responseIKEPayload.BuildNotification(
					message.TypeNone, message.AUTHENTICATION_FAILED, nil, nil)

				// Build IKE ikeMsg
				responseIKEMessage := message.NewMessage(ikeMsg.InitiatorSPI, ikeMsg.ResponderSPI,
					message.IKE_AUTH, true, false, ikeMsg.MessageID, responseIKEPayload)

				// Send IKE ikeMsg to UE
				if err := SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage,
					ikeSecurityAssociation.IKESAKey); err != nil {
					logger.IKELog.Errorf("HandleIKEAUTH(): %v", err)
				}
				return
			}
			logger.IKELog.Debugln("peer authentication success")
		} else {
			logger.IKELog.Warnln("peer authentication failed")
			// Inform UE the authentication has failed
			responseIKEPayload.Reset()

			// Notification
			responseIKEPayload.BuildNotification(message.TypeNone, message.AUTHENTICATION_FAILED, nil, nil)

			// Build IKE ikeMsg
			responseIKEMessage := message.NewMessage(ikeMsg.InitiatorSPI, ikeMsg.ResponderSPI,
				message.IKE_AUTH, true, false, ikeMsg.MessageID, responseIKEPayload)

			// Send IKE ikeMsg to UE
			if err := SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage,
				ikeSecurityAssociation.IKESAKey); err != nil {
				logger.IKELog.Errorf("HandleIKEAUTH(): %v", err)
			}
			return
		}

		// Parse configuration request to get if the UE has requested internal address,
		// and prepare configuration payload to UE
		var addrRequest bool = false

		if configuration != nil {
			logger.IKELog.Debugf("received configuration payload with type: %d", configuration.ConfigurationType)

			var attribute *message.IndividualConfigurationAttribute
			for _, attribute = range configuration.ConfigurationAttribute {
				switch attribute.Type {
				case message.INTERNAL_IP4_ADDRESS:
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

		responseIKEPayload.Reset()

		// Calculate local AUTH
		pseudorandomFunction.Reset()
		if _, err := pseudorandomFunction.Write(ikeSecurityAssociation.ResponderSignedOctets); err != nil {
			logger.IKELog.Errorf("pseudorandom function write error: %+v", err)
			return
		}

		// Authentication
		responseIKEPayload.BuildAuthentication(
			message.SharedKeyMesageIntegrityCode, pseudorandomFunction.Sum(nil))

		// Prepare configuration payload and traffic selector payload for initiator and responder
		var ueIPAddr, n3iwfIPAddr net.IP
		if !addrRequest {
			logger.IKELog.Errorln("UE did not send any configuration request for its IP address")
			return
		}
		// IP addresses (IPSec)
		ueIp := n3iwfCtx.NewInternalUEIPAddr(ikeUE)
		if ueIp == nil {
			logger.IKELog.Errorln("UE IP is nil")
			return
		}
		ueIPAddr = ueIp.To4()
		n3iwfIPAddr = net.ParseIP(ipsecGwAddr).To4()

		responseConfiguration := responseIKEPayload.BuildConfiguration(message.CFG_REPLY)
		responseConfiguration.ConfigurationAttribute.BuildConfigurationAttribute(message.INTERNAL_IP4_ADDRESS, ueIPAddr)
		responseConfiguration.ConfigurationAttribute.BuildConfigurationAttribute(message.INTERNAL_IP4_NETMASK, n3iwfCtx.Subnet.Mask)

		ikeUE.IPSecInnerIP = ueIPAddr
		ipsecInnerIPAddr, err := net.ResolveIPAddr("ip", ueIPAddr.String())
		if err != nil {
			logger.IKELog.Errorf("resolve UE inner IP address failed: %+v", err)
			return
		}
		ikeUE.IPSecInnerIPAddr = ipsecInnerIPAddr
		logger.IKELog.Debugf("ueIPAddr: %+v", ueIPAddr)

		// Security Association
		responseIKEPayload = append(responseIKEPayload, ikeSecurityAssociation.IKEAuthResponseSA)

		// Traffic Selectors initiator/responder
		responseTrafficSelectorInitiator := responseIKEPayload.BuildTrafficSelectorInitiator()
		responseTrafficSelectorInitiator.TrafficSelectors.BuildIndividualTrafficSelector(
			message.TS_IPV4_ADDR_RANGE, message.IPProtocolAll, 0, 65535, ueIPAddr.To4(), ueIPAddr.To4())
		responseTrafficSelectorResponder := responseIKEPayload.BuildTrafficSelectorResponder()
		responseTrafficSelectorResponder.TrafficSelectors.BuildIndividualTrafficSelector(
			message.TS_IPV4_ADDR_RANGE, message.IPProtocolAll, 0, 65535, n3iwfIPAddr.To4(), n3iwfIPAddr.To4())

		// Record traffic selector to IKE security association
		ikeSecurityAssociation.TrafficSelectorInitiator = responseTrafficSelectorInitiator
		ikeSecurityAssociation.TrafficSelectorResponder = responseTrafficSelectorResponder

		// Get data needed by xfrm

		// Allocate N3IWF inbound SPI
		var inboundSPI uint32
		inboundSPIByte := make([]byte, 4)
		for {
			buf := make([]byte, 4)
			_, err = rand.Read(buf)
			if err != nil {
				logger.IKELog.Errorf("handle IKE_AUTH Generate ChildSA inboundSPI: %v", err)
				return
			}
			randomUint32 := binary.BigEndian.Uint32(buf)
			// check if the inbound SPI havn't been allocated by N3IWF
			if _, ok := n3iwfCtx.ChildSA.Load(randomUint32); !ok {
				inboundSPI = randomUint32
				break
			}
		}
		binary.BigEndian.PutUint32(inboundSPIByte, inboundSPI)

		outboundSPI := binary.BigEndian.Uint32(ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].SPI)
		logger.IKELog.Debugf("inbound SPI: %+v, outbound SPI: %+v", inboundSPI, outboundSPI)

		// SPI field of IKEAuthResponseSA is used to save outbound SPI temporarily.
		// After N3IWF produced its inbound SPI, the field will be overwritten with the SPI.
		ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].SPI = inboundSPIByte

		// Consider 0x01 as the speicified index for IKE_AUTH exchange
		ikeUE.CreateHalfChildSA(0x01, inboundSPI, -1)
		childSecurityAssociationContext, err := ikeUE.CompleteChildSA(0x01, outboundSPI, ikeSecurityAssociation.IKEAuthResponseSA)
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

		if err := childSecurityAssociationContext.ChildSAKey.GenerateKeyForChildSA(ikeSecurityAssociation.IKESAKey, ikeSecurityAssociation.ConcatenatedNonce); err != nil {
			logger.IKELog.Errorf("generate key for child SA failed: %+v", err)
			return
		}
		// NAT-T concern
		if ikeSecurityAssociation.UeBehindNAT || ikeSecurityAssociation.N3iwfBehindNAT {
			childSecurityAssociationContext.EnableEncapsulate = true
			childSecurityAssociationContext.N3IWFPort = n3iwfAddr.Port
			childSecurityAssociationContext.NATPort = ueAddr.Port
		}

		// Notification(NAS_IP_ADDRESS)
		responseIKEPayload.BuildNotifyNAS_IP4_ADDRESS(ipsecGwAddr)

		// Notification(NSA_TCP_PORT)
		responseIKEPayload.BuildNotifyNAS_TCP_PORT(n3iwfCtx.TcpPort)

		// Build IKE ikeMsg
		responseIKEMessage := message.NewMessage(ikeMsg.InitiatorSPI, ikeMsg.ResponderSPI,
			message.IKE_AUTH, true, false, ikeMsg.MessageID, responseIKEPayload)

		childSecurityAssociationContext.LocalIsInitiator = false
		// Apply XFRM rules
		// IPsec for CP always use default XFRM interface
		if err = xfrm.ApplyXFRMRule(false, n3iwfCtx.XfrmInterfaceId, childSecurityAssociationContext); err != nil {
			logger.IKELog.Errorf("applying XFRM rules failed: %+v", err)
			return
		}
		logger.IKELog.Debugln(childSecurityAssociationContext.String(n3iwfCtx.XfrmInterfaceId))

		// Send IKE ikeMsg to UE
		if err = SendIKEMessageToUE(udpConn, n3iwfAddr, ueAddr, responseIKEMessage,
			ikeSecurityAssociation.IKESAKey); err != nil {
			logger.IKELog.Errorf("HandleIKEAUTH(): %v", err)
			return
		}

		ranNgapId, ok := n3iwfCtx.NgapIdLoad(ikeUE.N3IWFIKESecurityAssociation.LocalSPI)
		if !ok {
			logger.IKELog.Errorf("cannot get RanNgapId from SPI: %+v", ikeUE.N3IWFIKESecurityAssociation.LocalSPI)
			return
		}

		ikeSecurityAssociation.State++

		// After this, N3IWF will forward NAS with Child SA (IPSec SA)
		n3iwfCtx.NgapServer.RcvEventCh <- context.NewStartTCPSignalNASMsgEvt(ranNgapId)

		// Get TempPDUSessionSetupData from NGAP to setup PDU session if needed
		n3iwfCtx.NgapServer.RcvEventCh <- context.NewGetNGAPContextEvt(ranNgapId, []int64{context.CxtTempPDUSessionSetupData})
	}
}

func HandleCREATECHILDSA(udpConn *net.UDPConn, n3iwfAddr, ueAddr *net.UDPAddr, ikeMsg *message.IKEMessage, ikeSecurityAssociation *context.IKESecurityAssociation) {
	logger.IKELog.Debugln("handle CREATE_CHILD_SA")

	n3iwfCtx := context.N3IWFSelf()

	if !ikeSecurityAssociation.IKEConnection.UEAddr.IP.Equal(ueAddr.IP) ||
		!ikeSecurityAssociation.IKEConnection.N3IWFAddr.IP.Equal(n3iwfAddr.IP) {
		logger.IKELog.Warnf("get unexpteced IP in SPI: %016x", ikeSecurityAssociation.LocalSPI)
		return
	}

	// Parse payloads
	var securityAssociation *message.SecurityAssociation
	var nonce *message.Nonce
	var trafficSelectorInitiator *message.TrafficSelectorInitiator
	var trafficSelectorResponder *message.TrafficSelectorResponder

	for _, ikePayload := range ikeMsg.Payloads {
		switch ikePayload.Type() {
		case message.TypeSA:
			securityAssociation = ikePayload.(*message.SecurityAssociation)
		case message.TypeNiNr:
			nonce = ikePayload.(*message.Nonce)
		case message.TypeTSi:
			trafficSelectorInitiator = ikePayload.(*message.TrafficSelectorInitiator)
		case message.TypeTSr:
			trafficSelectorResponder = ikePayload.(*message.TrafficSelectorResponder)
		default:
			logger.IKELog.Warnf(
				"get IKE payload (type %d) in CREATE_CHILD_SA ikeMsg, this payload will not be handled by IKE handler",
				ikePayload.Type())
		}
	}

	// Check received ikeMsg
	if securityAssociation == nil {
		logger.IKELog.Errorln("security association field is nil")
		return
	}

	if trafficSelectorInitiator == nil {
		logger.IKELog.Errorln("traffic selector initiator field is nil")
		return
	}

	if trafficSelectorResponder == nil {
		logger.IKELog.Errorln("traffic selector responder field is nil")
		return
	}

	// Nonce
	if nonce == nil {
		logger.IKELog.Errorln("nonce field is nil")
		// TODO: send error ikeMsg to UE
		return
	}
	ikeSecurityAssociation.ConcatenatedNonce = append(ikeSecurityAssociation.ConcatenatedNonce, nonce.NonceData...)

	ikeSecurityAssociation.TemporaryIkeMsg = &context.IkeMsgTemporaryData{
		SecurityAssociation:      securityAssociation,
		TrafficSelectorInitiator: trafficSelectorInitiator,
		TrafficSelectorResponder: trafficSelectorResponder,
	}

	ranNgapId, ok := n3iwfCtx.NgapIdLoad(ikeSecurityAssociation.LocalSPI)
	if !ok {
		logger.IKELog.Errorf("cannot get RanNgapID from SPI: %+v", ikeSecurityAssociation.LocalSPI)
		return
	}

	ngapCxtReqNumlist := []int64{context.CxtTempPDUSessionSetupData}

	n3iwfCtx.NgapServer.RcvEventCh <- context.NewGetNGAPContextEvt(ranNgapId, ngapCxtReqNumlist)
}

func continueCreateChildSA(ikeSecurityAssociation *context.IKESecurityAssociation,
	temporaryPDUSessionSetupData *context.PDUSessionSetupTemporaryData,
) {
	n3iwfCtx := context.N3IWFSelf()
	ipsecGwAddr := n3iwfCtx.IpSecGatewayAddress

	// UE context
	ikeUe := ikeSecurityAssociation.IkeUE
	if ikeUe == nil {
		logger.IKELog.Errorln("UE context is nil")
		return
	}

	// PDU session information
	if temporaryPDUSessionSetupData == nil {
		logger.IKELog.Errorln("no PDU session information")
		return
	}

	if len(temporaryPDUSessionSetupData.UnactivatedPDUSession) == 0 {
		logger.IKELog.Errorln("no unactivated PDU session information")
		return
	}

	temporaryIkeMsg := ikeSecurityAssociation.TemporaryIkeMsg
	ikeConnection := ikeSecurityAssociation.IKEConnection

	// Get xfrm needed data
	// As specified in RFC 7296, ESP negotiate two child security association (pair) in one exchange
	// Message ID is used to be a index to pair two SPI in serveral IKE messages.
	outboundSPI := binary.BigEndian.Uint32(temporaryIkeMsg.SecurityAssociation.Proposals[0].SPI)
	childSecurityAssociationContext, err := ikeUe.CompleteChildSA(
		ikeSecurityAssociation.ResponderMessageID, outboundSPI, temporaryIkeMsg.SecurityAssociation)
	if err != nil {
		logger.IKELog.Errorf("create child security association context failed: %+v", err)
		return
	}

	// Build TSi if there is no one in the response
	if len(temporaryIkeMsg.TrafficSelectorInitiator.TrafficSelectors) == 0 {
		logger.IKELog.Warnln("there is no TSi in CREATE_CHILD_SA response")
		n3iwfIPAddr := net.ParseIP(ipsecGwAddr)
		temporaryIkeMsg.TrafficSelectorInitiator.TrafficSelectors.BuildIndividualTrafficSelector(
			message.TS_IPV4_ADDR_RANGE, message.IPProtocolAll,
			0, 65535, n3iwfIPAddr, n3iwfIPAddr)
	}

	// Build TSr if there is no one in the response
	if len(temporaryIkeMsg.TrafficSelectorResponder.TrafficSelectors) == 0 {
		logger.IKELog.Warnln("there is no TSr in CREATE_CHILD_SA response")
		ueIPAddr := ikeUe.IPSecInnerIP
		temporaryIkeMsg.TrafficSelectorResponder.TrafficSelectors.BuildIndividualTrafficSelector(
			message.TS_IPV4_ADDR_RANGE, message.IPProtocolAll,
			0, 65535, ueIPAddr, ueIPAddr)
	}

	err = parseIPAddressInformationToChildSecurityAssociation(childSecurityAssociationContext,
		ikeConnection.UEAddr.IP,
		temporaryIkeMsg.TrafficSelectorInitiator.TrafficSelectors[0],
		temporaryIkeMsg.TrafficSelectorResponder.TrafficSelectors[0])
	if err != nil {
		logger.IKELog.Errorf("parse IP address to child security association failed: %+v", err)
		return
	}
	// Select GRE traffic
	childSecurityAssociationContext.SelectedIPProtocol = unix.IPPROTO_GRE

	if err := childSecurityAssociationContext.ChildSAKey.GenerateKeyForChildSA(ikeSecurityAssociation.IKESAKey, ikeSecurityAssociation.ConcatenatedNonce); err != nil {
		logger.IKELog.Errorf("generate key for child SA failed: %+v", err)
		return
	}
	// NAT-T concern
	if ikeSecurityAssociation.UeBehindNAT || ikeSecurityAssociation.N3iwfBehindNAT {
		childSecurityAssociationContext.EnableEncapsulate = true
		childSecurityAssociationContext.N3IWFPort = ikeConnection.N3IWFAddr.Port
		childSecurityAssociationContext.NATPort = ikeConnection.UEAddr.Port
	}

	newXfrmiId := n3iwfCtx.XfrmInterfaceId

	// The additional PDU session will be separated from default xfrm interface
	// to avoid SPD entry collision
	if ikeUe.PduSessionListLen > 1 {
		// Setup XFRM interface for ipsec
		var linkIPSec netlink.Link
		n3iwfIPAddr := net.ParseIP(ipsecGwAddr).To4()
		n3iwfIPAddrAndSubnet := net.IPNet{IP: n3iwfIPAddr, Mask: n3iwfCtx.Subnet.Mask}
		newXfrmiId += n3iwfCtx.XfrmInterfaceId + n3iwfCtx.XfrmIfaceIdOffsetForUP
		newXfrmiName := fmt.Sprintf("%s-%d", n3iwfCtx.XfrmInterfaceName, newXfrmiId)

		if linkIPSec, err = xfrm.SetupIPsecXfrmi(newXfrmiName, n3iwfCtx.XfrmParentIfaceName, newXfrmiId, n3iwfIPAddrAndSubnet); err != nil {
			logger.IKELog.Errorf("setup XFRM interface %s fail: %+v", newXfrmiName, err)
			return
		}

		logger.IKELog.Infof("setup XFRM interface: %s", newXfrmiName)
		n3iwfCtx.XfrmIfaces.LoadOrStore(newXfrmiId, linkIPSec)
		childSecurityAssociationContext.XfrmIface = linkIPSec
		n3iwfCtx.XfrmIfaceIdOffsetForUP++
	} else {
		linkIPSec, ok := n3iwfCtx.XfrmIfaces.Load(newXfrmiId)
		if !ok {
			logger.IKELog.Warnf("cannot find the XFRM interface with if_id: %d", newXfrmiId)
			return
		}
		childSecurityAssociationContext.XfrmIface = linkIPSec.(netlink.Link)
	}

	// Apply XFRM rules
	childSecurityAssociationContext.LocalIsInitiator = true
	if err = xfrm.ApplyXFRMRule(true, newXfrmiId, childSecurityAssociationContext); err != nil {
		logger.IKELog.Errorf("applying XFRM rules failed: %+v", err)
		return
	}
	logger.IKELog.Debugln(childSecurityAssociationContext.String(newXfrmiId))

	ranNgapId, ok := n3iwfCtx.NgapIdLoad(ikeSecurityAssociation.LocalSPI)
	if !ok {
		logger.IKELog.Errorf("cannot get RanNgapId from SPI: %+v", ikeSecurityAssociation.LocalSPI)
		return
	}
	// Forward NAS ikeMsg related to PDU Seesion Establishment Accept to UE
	n3iwfCtx.NgapServer.RcvEventCh <- context.NewSendNASMsgEvt(ranNgapId)

	temporaryPDUSessionSetupData.FailedErrStr = append(temporaryPDUSessionSetupData.FailedErrStr, context.ErrNil)

	ikeSecurityAssociation.ResponderMessageID++

	// If needed, setup another PDU session
	CreatePDUSessionChildSA(ikeUe, temporaryPDUSessionSetupData)
}

func HandleInformational(udpConn *net.UDPConn, n3iwfAddr, ueAddr *net.UDPAddr, ikeMsg *message.IKEMessage, ikeSecurityAssociation *context.IKESecurityAssociation) {
	logger.IKELog.Debugln("handle Informational")

	var deletePayload *message.Delete
	var err error
	responseIKEPayload := new(message.IKEPayloadContainer)

	n3iwfIke := ikeSecurityAssociation.IkeUE

	if n3iwfIke.N3IWFIKESecurityAssociation.DPDReqRetransTimer != nil {
		n3iwfIke.N3IWFIKESecurityAssociation.DPDReqRetransTimer.Stop()
		n3iwfIke.N3IWFIKESecurityAssociation.DPDReqRetransTimer = nil
		atomic.StoreInt32(&n3iwfIke.N3IWFIKESecurityAssociation.CurrentRetryTimes, 0)
	}

	for _, ikePayload := range ikeMsg.Payloads {
		switch ikePayload.Type() {
		case message.TypeD:
			deletePayload = ikePayload.(*message.Delete)
		default:
			logger.IKELog.Warnf(
				"get IKE payload (type %d) in Inoformational ikeMsg, this payload will not be handled by IKE handler",
				ikePayload.Type())
		}
	}

	if deletePayload != nil {
		responseIKEPayload, err = handleDeletePayload(deletePayload, ikeMsg.IsResponse(), ikeSecurityAssociation)
		if err != nil {
			logger.IKELog.Errorf("HandleInformational(): %v", err)
			return
		}
	}

	if ikeMsg.IsResponse() {
		ikeSecurityAssociation.ResponderMessageID++
	} else { // Get Request ikeMsg
		SendUEInformationExchange(ikeSecurityAssociation, ikeSecurityAssociation.IKESAKey,
			responseIKEPayload, false, true, ikeMsg.MessageID,
			udpConn, ueAddr, n3iwfAddr)
	}
}

func HandleEvent(ikeEvt context.IkeEvt) {
	logger.IKELog.Debugln("handle IKE event")

	switch ikeEvt.Type() {
	case context.UnmarshalEAP5GDataResponse:
		HandleUnmarshalEAP5GDataResponse(ikeEvt)
	case context.SendEAP5GFailureMsg:
		HandleSendEAP5GFailureMsg(ikeEvt)
	case context.SendEAPSuccessMsg:
		HandleSendEAPSuccessMsg(ikeEvt)
	case context.SendEAPNASMsg:
		HandleSendEAPNASMsg(ikeEvt)
	case context.CreatePDUSession:
		HandleCreatePDUSession(ikeEvt)
	case context.IKEDeleteRequest:
		HandleIKEDeleteEvt(ikeEvt)
	case context.SendChildSADeleteRequest:
		HandleSendChildSADeleteRequest(ikeEvt)
	case context.IKEContextUpdate:
		HandleIKEContextUpdate(ikeEvt)
	case context.GetNGAPContextResponse:
		HandleGetNGAPContextResponse(ikeEvt)
	default:
		logger.IKELog.Errorf("undefined IKE event type: %d", ikeEvt.Type())
		return
	}
}

func HandleUnmarshalEAP5GDataResponse(ikeEvt context.IkeEvt) {
	logger.IKELog.Debugln("handle UnmarshalEAP5GDataResponse event")

	unmarshalEAP5GDataResponseEvt := ikeEvt.(*context.UnmarshalEAP5GDataResponseEvt)
	localSPI := unmarshalEAP5GDataResponseEvt.LocalSPI
	ranUeNgapId := unmarshalEAP5GDataResponseEvt.RanUeNgapId
	nasPDU := unmarshalEAP5GDataResponseEvt.NasPDU

	n3iwfCtx := context.N3IWFSelf()
	ikeSecurityAssociation, _ := n3iwfCtx.IKESALoad(localSPI)

	// Create UE context
	ikeUe := n3iwfCtx.NewN3iwfIkeUe(localSPI)

	// Relative context
	ikeSecurityAssociation.IkeUE = ikeUe
	ikeUe.N3IWFIKESecurityAssociation = ikeSecurityAssociation
	ikeUe.IKEConnection = ikeSecurityAssociation.IKEConnection

	n3iwfCtx.IkeSpiNgapIdMapping(ikeUe.N3IWFIKESecurityAssociation.LocalSPI, ranUeNgapId)

	n3iwfCtx.NgapServer.RcvEventCh <- context.NewSendInitialUEMessageEvt(
		ranUeNgapId,
		ikeSecurityAssociation.IKEConnection.UEAddr.IP.To4().String(),
		ikeSecurityAssociation.IKEConnection.UEAddr.Port,
		nasPDU,
	)
}

func HandleSendEAP5GFailureMsg(ikeEvt context.IkeEvt) {
	logger.IKELog.Debugln("handle SendEAP5GFailureMsg event")

	sendEAP5GFailureMsgEvt := ikeEvt.(*context.SendEAP5GFailureMsgEvt)
	errMsg := sendEAP5GFailureMsgEvt.ErrMsg
	localSPI := sendEAP5GFailureMsgEvt.LocalSPI

	n3iwfCtx := context.N3IWFSelf()
	ikeSecurityAssociation, _ := n3iwfCtx.IKESALoad(localSPI)
	logger.IKELog.Warnf("EAP Failure: %s", errMsg.Error())

	var responseIKEPayload message.IKEPayloadContainer
	// Send EAP failure

	// EAP
	identifier, err := security.GenerateRandomUint8()
	if err != nil {
		logger.IKELog.Errorf("generate random uint8 failed: %+v", err)
		return
	}
	responseIKEPayload.BuildEAPFailure(identifier)

	// Build IKE ikeMsg
	responseIKEMessage := message.NewMessage(ikeSecurityAssociation.RemoteSPI, ikeSecurityAssociation.LocalSPI,
		message.IKE_AUTH, true, false, ikeSecurityAssociation.InitiatorMessageID, responseIKEPayload)

	// Send IKE ikeMsg to UE
	err = SendIKEMessageToUE(ikeSecurityAssociation.IKEConnection.Conn,
		ikeSecurityAssociation.IKEConnection.N3IWFAddr, ikeSecurityAssociation.IKEConnection.UEAddr,
		responseIKEMessage, ikeSecurityAssociation.IKESAKey)
	if err != nil {
		logger.IKELog.Errorf("HandleSendEAP5GFailureMsg(): %v", err)
	}
}

func HandleSendEAPSuccessMsg(ikeEvt context.IkeEvt) {
	logger.IKELog.Debugln("handle SendEAPSuccessMsg event")

	sendEAPSuccessMsgEvt := ikeEvt.(*context.SendEAPSuccessMsgEvt)
	localSPI := sendEAPSuccessMsgEvt.LocalSPI
	kn3iwf := sendEAPSuccessMsgEvt.Kn3iwf
	pduSessionListLen := sendEAPSuccessMsgEvt.PduSessionListLen

	n3iwfCtx := context.N3IWFSelf()
	ikeSecurityAssociation, _ := n3iwfCtx.IKESALoad(localSPI)

	if kn3iwf != nil {
		ikeSecurityAssociation.IkeUE.Kn3iwf = kn3iwf
	}

	ikeSecurityAssociation.IkeUE.PduSessionListLen = pduSessionListLen

	var responseIKEPayload message.IKEPayloadContainer

	responseIKEPayload.Reset()

	var identifier uint8
	var err error
	for {
		identifier, err = security.GenerateRandomUint8()
		if err != nil {
			logger.IKELog.Errorf("HandleSendEAPSuccessMsg() rand: %v", err)
			return
		}
		if identifier != ikeSecurityAssociation.LastEAPIdentifier {
			ikeSecurityAssociation.LastEAPIdentifier = identifier
			break
		}
	}

	responseIKEPayload.BuildEAPSuccess(identifier)

	// Build IKE ikeMsg
	responseIKEMessage := message.NewMessage(ikeSecurityAssociation.RemoteSPI,
		ikeSecurityAssociation.LocalSPI, message.IKE_AUTH, true, false,
		ikeSecurityAssociation.InitiatorMessageID, responseIKEPayload)

	// Send IKE ikeMsg to UE
	err = SendIKEMessageToUE(ikeSecurityAssociation.IKEConnection.Conn,
		ikeSecurityAssociation.IKEConnection.N3IWFAddr,
		ikeSecurityAssociation.IKEConnection.UEAddr, responseIKEMessage,
		ikeSecurityAssociation.IKESAKey)
	if err != nil {
		logger.IKELog.Errorf("HandleSendEAPSuccessMsg(): %v", err)
		return
	}

	ikeSecurityAssociation.State++
}

func HandleSendEAPNASMsg(ikeEvt context.IkeEvt) {
	logger.IKELog.Debugln("handle SendEAPNASMsg event")

	sendEAPNASMsgEvt := ikeEvt.(*context.SendEAPNASMsgEvt)
	localSPI := sendEAPNASMsgEvt.LocalSPI
	nasPDU := sendEAPNASMsgEvt.NasPDU

	n3iwfCtx := context.N3IWFSelf()
	ikeSecurityAssociation, _ := n3iwfCtx.IKESALoad(localSPI)

	var responseIKEPayload message.IKEPayloadContainer
	responseIKEPayload.Reset()

	var identifier uint8
	var err error
	for {
		identifier, err = security.GenerateRandomUint8()
		if err != nil {
			logger.IKELog.Errorf("HandleSendEAPNASMsg() rand: %v", err)
			return
		}
		if identifier != ikeSecurityAssociation.LastEAPIdentifier {
			ikeSecurityAssociation.LastEAPIdentifier = identifier
			break
		}
	}

	err = responseIKEPayload.BuildEAP5GNAS(identifier, nasPDU)
	if err != nil {
		logger.IKELog.Errorf("HandleSendEAPNASMsg() BuildEAP5GNAS: %v", err)
		return
	}

	// Build IKE ikeMsg
	responseIKEMessage := message.NewMessage(ikeSecurityAssociation.RemoteSPI,
		ikeSecurityAssociation.LocalSPI, message.IKE_AUTH, true, false,
		ikeSecurityAssociation.InitiatorMessageID, responseIKEPayload)

	// Send IKE ikeMsg to UE
	err = SendIKEMessageToUE(ikeSecurityAssociation.IKEConnection.Conn,
		ikeSecurityAssociation.IKEConnection.N3IWFAddr,
		ikeSecurityAssociation.IKEConnection.UEAddr, responseIKEMessage,
		ikeSecurityAssociation.IKESAKey)
	if err != nil {
		logger.IKELog.Errorf("HandleSendEAPNASMsg(): %v", err)
	}
}

func HandleCreatePDUSession(ikeEvt context.IkeEvt) {
	logger.IKELog.Debugln("handle CreatePDUSession event")

	createPDUSessionEvt := ikeEvt.(*context.CreatePDUSessionEvt)
	localSPI := createPDUSessionEvt.LocalSPI
	temporaryPDUSessionSetupData := createPDUSessionEvt.TempPDUSessionSetupData

	n3iwfCtx := context.N3IWFSelf()
	ikeSecurityAssociation, _ := n3iwfCtx.IKESALoad(localSPI)

	ikeSecurityAssociation.IkeUE.PduSessionListLen = createPDUSessionEvt.PduSessionListLen

	CreatePDUSessionChildSA(ikeSecurityAssociation.IkeUE, temporaryPDUSessionSetupData)
}

func HandleIKEDeleteEvt(ikeEvt context.IkeEvt) {
	logger.IKELog.Debugln("handle IKEDeleteRequest event")

	ikeDeleteRequest := ikeEvt.(*context.IKEDeleteRequestEvt)
	localSPI := ikeDeleteRequest.LocalSPI

	SendIKEDeleteRequest(context.N3IWFSelf(), localSPI)

	// In normal case, should wait response and then remove ikeUe.
	// Remove ikeUe here to prevent no response received.
	// Even response replied, it will be discarded.
	err := removeIkeUe(localSPI)
	if err != nil {
		logger.IKELog.Errorf("HandleIKEDeleteEvt(): %v", err)
	}
}

func removeIkeUe(localSPI uint64) error {
	n3iwfCtx := context.N3IWFSelf()
	ikeUe, ok := n3iwfCtx.IkeUePoolLoad(localSPI)
	if !ok {
		return fmt.Errorf("cannot get IkeUE from SPI: %016x", localSPI)
	}
	err := ikeUe.Remove()
	if err != nil {
		return fmt.Errorf("delete IkeUe error: %w", err)
	}
	return nil
}

func HandleSendChildSADeleteRequest(ikeEvt context.IkeEvt) {
	logger.IKELog.Debugln("handle SendChildSADeleteRequest event")

	sendChildSADeleteRequestEvt := ikeEvt.(*context.SendChildSADeleteRequestEvt)
	localSPI := sendChildSADeleteRequestEvt.LocalSPI
	releaseIdList := sendChildSADeleteRequestEvt.ReleaseIdList

	ikeUe, ok := context.N3IWFSelf().IkeUePoolLoad(localSPI)
	if !ok {
		logger.IKELog.Errorf("cannot get IkeUE from SPI: %+v", localSPI)
		return
	}
	SendChildSADeleteRequest(ikeUe, releaseIdList)
}

func HandleIKEContextUpdate(ikeEvt context.IkeEvt) {
	logger.IKELog.Debugln("handle IKEContextUpdate event")

	ikeContextUpdateEvt := ikeEvt.(*context.IKEContextUpdateEvt)
	localSPI := ikeContextUpdateEvt.LocalSPI
	kn3iwf := ikeContextUpdateEvt.Kn3iwf

	ikeUe, ok := context.N3IWFSelf().IkeUePoolLoad(localSPI)
	if !ok {
		logger.IKELog.Errorf("cannot get IkeUE from SPI: %+v", localSPI)
		return
	}

	if kn3iwf != nil {
		ikeUe.Kn3iwf = kn3iwf
	}
}

func HandleGetNGAPContextResponse(ikeEvt context.IkeEvt) {
	logger.IKELog.Debugln("handle GetNGAPContextResponse event")

	getNGAPContextRepEvt := ikeEvt.(*context.GetNGAPContextRepEvt)
	localSPI := getNGAPContextRepEvt.LocalSPI
	ngapCxtReqNumlist := getNGAPContextRepEvt.NgapCxtReqNumlist
	ngapCxt := getNGAPContextRepEvt.NgapCxt

	n3iwfCtx := context.N3IWFSelf()
	ikeSecurityAssociation, _ := n3iwfCtx.IKESALoad(localSPI)

	var tempPDUSessionSetupData *context.PDUSessionSetupTemporaryData

	for i, num := range ngapCxtReqNumlist {
		switch num {
		case context.CxtTempPDUSessionSetupData:
			tempPDUSessionSetupData = ngapCxt[i].(*context.PDUSessionSetupTemporaryData)
		default:
			logger.IKELog.Errorf("receive undefined NGAP context request number: %d", num)
		}
	}

	switch ikeSecurityAssociation.State {
	case EndSignalling:
		CreatePDUSessionChildSA(ikeSecurityAssociation.IkeUE, tempPDUSessionSetupData)
		ikeSecurityAssociation.State++
		go StartDPD(ikeSecurityAssociation.IkeUE)
	case HandleCreateChildSA:
		continueCreateChildSA(ikeSecurityAssociation, tempPDUSessionSetupData)
	}
}

func CreatePDUSessionChildSA(ikeUe *context.N3IWFIkeUe,
	temporaryPDUSessionSetupData *context.PDUSessionSetupTemporaryData,
) {
	n3iwfCtx := context.N3IWFSelf()
	ipsecGwAddr := n3iwfCtx.IpSecGatewayAddress

	ikeSecurityAssociation := ikeUe.N3IWFIKESecurityAssociation

	ranNgapId, ok := n3iwfCtx.NgapIdLoad(ikeUe.N3IWFIKESecurityAssociation.LocalSPI)
	if !ok {
		logger.IKELog.Errorf("cannot get RanNgapId from SPI: %+v", ikeUe.N3IWFIKESecurityAssociation.LocalSPI)
		return
	}

	for {
		if len(temporaryPDUSessionSetupData.UnactivatedPDUSession) > temporaryPDUSessionSetupData.Index {
			pduSession := temporaryPDUSessionSetupData.UnactivatedPDUSession[temporaryPDUSessionSetupData.Index]
			pduSessionID := pduSession.Id

			// Send CREATE_CHILD_SA to UE
			var responseIKEPayload message.IKEPayloadContainer
			errStr := context.ErrNil

			responseIKEPayload.Reset()

			// Build SA
			requestSA := responseIKEPayload.BuildSecurityAssociation()

			// Allocate SPI
			var spi uint32
			spiByte := make([]byte, 4)
			for {
				var err error
				buf := make([]byte, 4)
				_, err = rand.Read(buf)
				if err != nil {
					logger.IKELog.Errorf("createPDUSessionChildSA Generate SPI: %v", err)
					return
				}
				randomUint32 := binary.BigEndian.Uint32(buf)
				if _, ok := n3iwfCtx.ChildSA.Load(randomUint32); !ok {
					spi = randomUint32
					break
				}
			}
			binary.BigEndian.PutUint32(spiByte, spi)

			// First Proposal - Proposal No.1
			proposal := requestSA.Proposals.BuildProposal(1, message.TypeESP, spiByte)

			// Encryption transform
			encrTranform, err := encr.ToTransform(ikeSecurityAssociation.EncrInfo)
			if err != nil {
				logger.IKELog.Errorf("encr ToTransform error: %v", err)
				break
			}

			proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm,
				encrTranform)
			// Integrity transform
			if pduSession.SecurityIntegrity {
				proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm,
					integ.ToTransform(ikeSecurityAssociation.IntegInfo))
			}

			// ESN transform
			proposal.ExtendedSequenceNumbers.BuildTransform(message.TypeExtendedSequenceNumbers, message.ESN_DISABLE, nil, nil, nil)

			ikeUe.CreateHalfChildSA(ikeSecurityAssociation.ResponderMessageID, spi, pduSessionID)

			// Build Nonce
			nonceDataBigInt, errGen := security.GenerateRandomNumber()
			if errGen != nil {
				logger.IKELog.Errorf("createPDUSessionChildSA Build Nonce: %v", errGen)
				return
			}
			nonceData := nonceDataBigInt.Bytes()
			responseIKEPayload.BuildNonce(nonceData)

			// Store nonce into context
			ikeSecurityAssociation.ConcatenatedNonce = nonceData

			// TSi
			n3iwfIPAddr := net.ParseIP(ipsecGwAddr)
			tsi := responseIKEPayload.BuildTrafficSelectorInitiator()
			tsi.TrafficSelectors.BuildIndividualTrafficSelector(
				message.TS_IPV4_ADDR_RANGE, message.IPProtocolAll,
				0, 65535, n3iwfIPAddr.To4(), n3iwfIPAddr.To4())

			// TSr
			ueIPAddr := ikeUe.IPSecInnerIP
			tsr := responseIKEPayload.BuildTrafficSelectorResponder()
			tsr.TrafficSelectors.BuildIndividualTrafficSelector(message.TS_IPV4_ADDR_RANGE, message.IPProtocolAll,
				0, 65535, ueIPAddr.To4(), ueIPAddr.To4())

			if pduSessionID < 0 || pduSessionID > math.MaxUint8 {
				logger.IKELog.Errorf("createPDUSessionChildSA pduSessionID exceeds uint8 range: %d", pduSessionID)
				break
			}
			// Notify-Qos
			err = responseIKEPayload.BuildNotify5G_QOS_INFO(uint8(pduSessionID), pduSession.QFIList, true, false, 0)
			if err != nil {
				logger.IKELog.Errorf("createPDUSessionChildSA error: %v", err)
				break
			}

			// Notify-UP_IP_ADDRESS
			responseIKEPayload.BuildNotifyUP_IP4_ADDRESS(ipsecGwAddr)

			temporaryPDUSessionSetupData.Index++

			// Build IKE ikeMsg
			ikeMessage := message.NewMessage(ikeSecurityAssociation.RemoteSPI, ikeSecurityAssociation.LocalSPI,
				message.CREATE_CHILD_SA, false, false, ikeSecurityAssociation.ResponderMessageID,
				responseIKEPayload)

			err = SendIKEMessageToUE(ikeSecurityAssociation.IKEConnection.Conn,
				ikeSecurityAssociation.IKEConnection.N3IWFAddr,
				ikeSecurityAssociation.IKEConnection.UEAddr, ikeMessage,
				ikeSecurityAssociation.IKESAKey)
			if err != nil {
				logger.IKELog.Errorf("createPDUSessionChildSA error: %v", err)
				errStr = context.ErrTransportResourceUnavailable
				temporaryPDUSessionSetupData.FailedErrStr = append(temporaryPDUSessionSetupData.FailedErrStr,
					errStr)
			} else {
				temporaryPDUSessionSetupData.FailedErrStr = append(temporaryPDUSessionSetupData.FailedErrStr,
					errStr)
				break
			}
		} else {
			n3iwfCtx.NgapServer.RcvEventCh <- context.NewSendPDUSessionResourceSetupResEvt(ranNgapId)
			break
		}
	}
}

func StartDPD(ikeUe *context.N3IWFIkeUe) {
	defer util.RecoverWithLog(logger.IKELog)

	ikeUe.N3IWFIKESecurityAssociation.IKESAClosedCh = make(chan struct{})

	n3iwfCtx := context.N3IWFSelf()
	ikeSA := ikeUe.N3IWFIKESecurityAssociation

	liveness := factory.N3iwfConfig.Configuration.LivenessCheck
	if liveness.Enable {
		ikeSA.IsUseDPD = true
		timer := time.NewTicker(liveness.TransFreq)
		for {
			select {
			case <-ikeSA.IKESAClosedCh:
				close(ikeSA.IKESAClosedCh)
				timer.Stop()
				return
			case <-timer.C:
				var payload *message.IKEPayloadContainer
				SendUEInformationExchange(ikeSA, ikeSA.IKESAKey, payload, false, false,
					ikeSA.ResponderMessageID, ikeUe.IKEConnection.Conn, ikeUe.IKEConnection.UEAddr,
					ikeUe.IKEConnection.N3IWFAddr)

				var DPDReqRetransTime time.Duration = 2 * time.Second // TODO: make it configurable
				ikeSA.DPDReqRetransTimer = context.NewDPDPeriodicTimer(
					DPDReqRetransTime, liveness.MaxRetryTimes, ikeSA,
					func() {
						logger.IKELog.Errorf("UE is down")
						ranNgapId, ok := n3iwfCtx.NgapIdLoad(ikeSA.LocalSPI)
						if !ok {
							logger.IKELog.Infof("cannot find ranNgapId form SPI: %+v",
								ikeSA.LocalSPI)
							return
						}

						n3iwfCtx.NgapServer.RcvEventCh <- context.NewSendUEContextReleaseRequestEvt(
							ranNgapId, context.ErrRadioConnWithUeLost,
						)

						ikeSA.DPDReqRetransTimer = nil
						timer.Stop()
					})
			}
		}
	}
}

func handleNATDetect(initiatorSPI, responderSPI uint64, notifications []*message.Notification, ueAddr, n3iwfAddr *net.UDPAddr) (bool, bool, error) {
	ueBehindNAT := false
	n3iwfBehindNAT := false

	srcNatDData, err := generateNATDetectHash(initiatorSPI, responderSPI, ueAddr)
	if err != nil {
		return false, false, fmt.Errorf("handle NATD: %w", err)
	}

	dstNatDData, err := generateNATDetectHash(initiatorSPI, responderSPI, n3iwfAddr)
	if err != nil {
		return false, false, fmt.Errorf("handle NATD: %w", err)
	}

	for _, notification := range notifications {
		switch notification.NotifyMessageType {
		case message.NAT_DETECTION_SOURCE_IP:
			logger.IKELog.Debugln("received IKE Notify: NAT_DETECTION_SOURCE_IP")
			if !bytes.Equal(notification.NotificationData, srcNatDData) {
				logger.IKELog.Debugf("UE(SPI: %016x) is behind NAT", responderSPI)
				ueBehindNAT = true
			}
		case message.NAT_DETECTION_DESTINATION_IP:
			logger.IKELog.Debugln("received IKE Notify: NAT_DETECTION_DESTINATION_IP")
			if !bytes.Equal(notification.NotificationData, dstNatDData) {
				logger.IKELog.Debugf("N3IWF is behind NAT")
				n3iwfBehindNAT = true
			}
		default:
		}
	}
	return ueBehindNAT, n3iwfBehindNAT, nil
}

func generateNATDetectHash(
	initiatorSPI, responderSPI uint64,
	addr *net.UDPAddr,
) ([]byte, error) {
	// Calculate NAT_DETECTION hash for NAT-T
	// : sha1(ispi | rspi | ip | port)
	natdData := make([]byte, 22)
	binary.BigEndian.PutUint64(natdData[0:8], initiatorSPI)
	binary.BigEndian.PutUint64(natdData[8:16], responderSPI)
	copy(natdData[16:20], addr.IP.To4())
	binary.BigEndian.PutUint16(natdData[20:22], uint16(addr.Port)) // #nosec G115

	sha1HashFunction := sha1.New() // #nosec G401
	_, err := sha1HashFunction.Write(natdData)
	if err != nil {
		return nil, fmt.Errorf("generate NATD Hash: %w", err)
	}
	return sha1HashFunction.Sum(nil), nil
}

func buildNATDetectNotifPayload(ikeSA *context.IKESecurityAssociation,
	payload *message.IKEPayloadContainer,
	ueAddr, n3iwfAddr *net.UDPAddr,
) error {
	srcNatDHash, err := generateNATDetectHash(ikeSA.RemoteSPI, ikeSA.LocalSPI, n3iwfAddr)
	if err != nil {
		return fmt.Errorf("build NATD: %w", err)
	}
	// Build and append notify payload for NAT_DETECTION_SOURCE_IP
	payload.BuildNotification(
		message.TypeNone, message.NAT_DETECTION_SOURCE_IP, nil, srcNatDHash)

	dstNatDHash, err := generateNATDetectHash(ikeSA.RemoteSPI, ikeSA.LocalSPI, ueAddr)
	if err != nil {
		return fmt.Errorf("build NATD: %w", err)
	}
	// Build and append notify payload for NAT_DETECTION_DESTINATION_IP
	payload.BuildNotification(
		message.TypeNone, message.NAT_DETECTION_DESTINATION_IP, nil, dstNatDHash)

	return nil
}

func handleDeletePayload(payload *message.Delete, isResponse bool,
	ikeSecurityAssociation *context.IKESecurityAssociation) (
	*message.IKEPayloadContainer, error,
) {
	var evt context.NgapEvt
	var err error
	n3iwfCtx := context.N3IWFSelf()
	n3iwfIke := ikeSecurityAssociation.IkeUE
	responseIKEPayload := new(message.IKEPayloadContainer)

	ranNgapId, ok := n3iwfCtx.NgapIdLoad(n3iwfIke.N3IWFIKESecurityAssociation.LocalSPI)
	if !ok {
		return nil, fmt.Errorf("cannot get RanNgapId from SPI: %+v",
			n3iwfIke.N3IWFIKESecurityAssociation.LocalSPI)
	}

	switch payload.ProtocolID {
	case message.TypeIKE:
		if !isResponse {
			err = n3iwfIke.Remove()
			if err != nil {
				return nil, fmt.Errorf("delete IkeUe Context error: %w", err)
			}
		}

		evt = context.NewSendUEContextReleaseEvt(ranNgapId)
	case message.TypeESP:
		var deletSPIs []uint32
		var deletPduIds []int64
		if !isResponse {
			deletSPIs, deletPduIds, err = deleteChildSAFromSPIList(n3iwfIke, payload.SPIs)
			if err != nil {
				return nil, fmt.Errorf("handleDeletePayload: %w", err)
			}
			responseIKEPayload.BuildDeletePayload(message.TypeESP, 4, uint16(len(deletSPIs)), deletSPIs)
		}

		evt = context.NewSendPDUSessionResourceReleaseEvt(ranNgapId, deletPduIds)
	default:
		return nil, fmt.Errorf("get Protocol ID %d in Informational delete payload, "+
			"this payload will not be handled by IKE handler", payload.ProtocolID)
	}
	n3iwfCtx.NgapServer.RcvEventCh <- evt
	return responseIKEPayload, nil
}

func isTransformKernelSupported(transformType uint8, transformID uint16, attributePresent bool, attributeValue uint16) bool {
	switch transformType {
	case message.TypeEncryptionAlgorithm:
		switch transformID {
		case message.ENCR_DES_IV64:
			return false
		case message.ENCR_DES:
			return true
		case message.ENCR_3DES:
			return true
		case message.ENCR_RC5:
			return false
		case message.ENCR_IDEA:
			return false
		case message.ENCR_CAST:
			if !attributePresent {
				return false
			}
			switch attributeValue {
			case 128:
				return true
			case 256:
				return false
			default:
				return false
			}
		case message.ENCR_BLOWFISH:
			return true
		case message.ENCR_3IDEA:
			return false
		case message.ENCR_DES_IV32:
			return false
		case message.ENCR_NULL:
			return true
		case message.ENCR_AES_CBC:
			if !attributePresent {
				return false
			}
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
		case message.ENCR_AES_CTR:
			if !attributePresent {
				return false
			}
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
		default:
			return false
		}
	case message.TypeIntegrityAlgorithm:
		switch transformID {
		case message.AUTH_NONE:
			return false
		case message.AUTH_HMAC_MD5_96:
			return true
		case message.AUTH_HMAC_SHA1_96:
			return true
		case message.AUTH_DES_MAC:
			return false
		case message.AUTH_KPDK_MD5:
			return false
		case message.AUTH_AES_XCBC_96:
			return true
		case message.AUTH_HMAC_SHA2_256_128:
			return true
		default:
			return false
		}
	case message.TypeDiffieHellmanGroup:
		switch transformID {
		// case message.DH_NONE:
		// 	return false
		// case message.DH_768_BIT_MODP:
		// 	return false
		// case message.DH_1024_BIT_MODP:
		// 	return false
		// case message.DH_1536_BIT_MODP:
		// 	return false
		// case message.DH_2048_BIT_MODP:
		// 	return false
		// case message.DH_3072_BIT_MODP:
		// 	return false
		// case message.DH_4096_BIT_MODP:
		// 	return false
		// case message.DH_6144_BIT_MODP:
		// 	return false
		// case message.DH_8192_BIT_MODP:
		// 	return false
		default:
			return false
		}
	case message.TypeExtendedSequenceNumbers:
		switch transformID {
		case message.ESN_ENABLE:
			return true
		case message.ESN_DISABLE:
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
	trafficSelectorLocal *message.IndividualTrafficSelector,
	trafficSelectorRemote *message.IndividualTrafficSelector,
) error {
	if childSecurityAssociation == nil {
		return fmt.Errorf("childSecurityAssociation is nil")
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

func SelectProposal(proposals message.ProposalContainer) message.ProposalContainer {
	var chooseProposal message.ProposalContainer

	for _, proposal := range proposals {
		// We need ENCR, PRF, INTEG, DH, but not ESN

		var encryptionAlgorithmTransform, pseudorandomFunctionTransform *message.Transform
		var integrityAlgorithmTransform, diffieHellmanGroupTransform *message.Transform
		var chooseDH dh.DHType
		var chooseEncr encr.ENCRType
		var chooseInte integ.INTEGType
		var choosePrf prf.PRFType

		for _, transform := range proposal.DiffieHellmanGroup {
			dhType := dh.DecodeTransform(transform)
			if dhType != nil {
				if diffieHellmanGroupTransform == nil {
					diffieHellmanGroupTransform = transform
					chooseDH = dhType
				}
			}
		}
		if chooseDH == nil {
			continue // mandatory
		}

		for _, transform := range proposal.EncryptionAlgorithm {
			encrType := encr.DecodeTransform(transform)
			if encrType != nil {
				if encryptionAlgorithmTransform == nil {
					encryptionAlgorithmTransform = transform
					chooseEncr = encrType
				}
			}
		}
		if chooseEncr == nil {
			continue // mandatory
		}

		for _, transform := range proposal.IntegrityAlgorithm {
			integType := integ.DecodeTransform(transform)
			if integType != nil {
				if integrityAlgorithmTransform == nil {
					integrityAlgorithmTransform = transform
					chooseInte = integType
				}
			}
		}
		if chooseInte == nil {
			continue // mandatory
		}

		for _, transform := range proposal.PseudorandomFunction {
			prfType := prf.DecodeTransform(transform)
			if prfType != nil {
				if pseudorandomFunctionTransform == nil {
					pseudorandomFunctionTransform = transform
					choosePrf = prfType
				}
			}
		}
		if choosePrf == nil {
			continue // mandatory
		}
		if len(proposal.ExtendedSequenceNumbers) > 0 {
			continue // No ESN
		}

		// Construct chosen proposal, with ENCR, PRF, INTEG, DH, and each contains
		// one transform expectively
		chosenProposal := chooseProposal.BuildProposal(proposal.ProposalNumber, proposal.ProtocolID, nil)
		chosenProposal.EncryptionAlgorithm = append(chosenProposal.EncryptionAlgorithm, encryptionAlgorithmTransform)
		chosenProposal.IntegrityAlgorithm = append(chosenProposal.IntegrityAlgorithm, integrityAlgorithmTransform)
		chosenProposal.PseudorandomFunction = append(chosenProposal.PseudorandomFunction, pseudorandomFunctionTransform)
		chosenProposal.DiffieHellmanGroup = append(chosenProposal.DiffieHellmanGroup, diffieHellmanGroupTransform)
		break
	}
	return chooseProposal
}

func deleteChildSAFromSPIList(ikeUe *context.N3IWFIkeUe, spiList []uint32) (
	[]uint32, []int64, error,
) {
	var deleteSPIs []uint32
	var deletePduIds []int64

	for _, spi := range spiList {
		found := false
		for _, childSA := range ikeUe.N3IWFChildSecurityAssociation {
			if childSA.OutboundSPI == spi {
				found = true
				deleteSPIs = append(deleteSPIs, childSA.InboundSPI)

				if len(childSA.PDUSessionIds) == 0 {
					return nil, nil, fmt.Errorf("child_SA SPI: 0x%08x does not have PDU session id", spi)
				}
				deletePduIds = append(deletePduIds, childSA.PDUSessionIds[0])

				err := ikeUe.DeleteChildSA(childSA)
				if err != nil {
					return nil, nil, fmt.Errorf("DeleteChildSAFromSPIList: %w", err)
				}
				break
			}
		}
		if !found {
			logger.IKELog.Warnf("get unknown Child_SA with SPI: 0x%08x", spi)
		}
	}

	return deleteSPIs, deletePduIds, nil
}
