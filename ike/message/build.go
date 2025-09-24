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
	"net"
)

// Utility: assign slice directly if empty, else append
func assignOrAppend(dst, src []byte) []byte {
	if len(dst) == 0 {
		return src
	}
	return append(dst, src...)
}

func (container *IKEPayloadContainer) Reset() {
	*container = nil
}

// Notification
func (container *IKEPayloadContainer) BuildNotification(
	protocolID uint8,
	notifyMessageType uint16,
	spi []byte,
	notificationData []byte,
) {
	notification := new(Notification)
	notification.ProtocolID = protocolID
	notification.NotifyMessageType = notifyMessageType
	notification.SPI = assignOrAppend(nil, spi)
	notification.NotificationData = assignOrAppend(nil, notificationData)
	*container = append(*container, notification)
}

// Certificate
func (container *IKEPayloadContainer) BuildCertificate(certificateEncode uint8, certificateData []byte) {
	certificate := new(Certificate)
	certificate.CertificateEncoding = certificateEncode
	certificate.CertificateData = assignOrAppend(nil, certificateData)
	*container = append(*container, certificate)
}

// Encrypted
func (container *IKEPayloadContainer) BuildEncrypted(nextPayload IKEPayloadType, encryptedData []byte) *Encrypted {
	encrypted := new(Encrypted)
	encrypted.NextPayload = nextPayload
	encrypted.EncryptedData = assignOrAppend(nil, encryptedData)
	*container = append(*container, encrypted)
	return encrypted
}

// Key Exchange
func (container *IKEPayloadContainer) BuildKeyExchange(diffiehellmanGroup uint16, keyExchangeData []byte) {
	keyExchange := new(KeyExchange)
	keyExchange.DiffieHellmanGroup = diffiehellmanGroup
	keyExchange.KeyExchangeData = assignOrAppend(nil, keyExchangeData)
	*container = append(*container, keyExchange)
}

// Identification
func (container *IKEPayloadContainer) BuildIdentificationInitiator(idType uint8, idData []byte) {
	identification := new(IdentificationInitiator)
	identification.IDType = idType
	identification.IDData = assignOrAppend(nil, idData)
	*container = append(*container, identification)
}

func (container *IKEPayloadContainer) BuildIdentificationResponder(idType uint8, idData []byte) {
	identification := new(IdentificationResponder)
	identification.IDType = idType
	identification.IDData = assignOrAppend(nil, idData)
	*container = append(*container, identification)
}

// Authentication
func (container *IKEPayloadContainer) BuildAuthentication(authenticationMethod uint8, authenticationData []byte) {
	authentication := new(Authentication)
	authentication.AuthenticationMethod = authenticationMethod
	authentication.AuthenticationData = assignOrAppend(nil, authenticationData)
	*container = append(*container, authentication)
}

// Configuration
func (container *IKEPayloadContainer) BuildConfiguration(configurationType uint8) *Configuration {
	configuration := new(Configuration)
	configuration.ConfigurationType = configurationType
	*container = append(*container, configuration)
	return configuration
}

func (container *ConfigurationAttributeContainer) Reset() {
	*container = nil
}

func (container *ConfigurationAttributeContainer) BuildConfigurationAttribute(
	attributeType uint16,
	attributeValue []byte,
) {
	configurationAttribute := new(IndividualConfigurationAttribute)
	configurationAttribute.Type = attributeType
	configurationAttribute.Value = assignOrAppend(nil, attributeValue)
	*container = append(*container, configurationAttribute)
}

// Nonce
func (container *IKEPayloadContainer) BuildNonce(nonceData []byte) {
	nonce := new(Nonce)
	nonce.NonceData = assignOrAppend(nil, nonceData)
	*container = append(*container, nonce)
}

// Traffic Selector
func (container *IKEPayloadContainer) BuildTrafficSelectorInitiator() *TrafficSelectorInitiator {
	tsInitiator := new(TrafficSelectorInitiator)
	*container = append(*container, tsInitiator)
	return tsInitiator
}

func (container *IKEPayloadContainer) BuildTrafficSelectorResponder() *TrafficSelectorResponder {
	tsResponder := new(TrafficSelectorResponder)
	*container = append(*container, tsResponder)
	return tsResponder
}

func (container *IndividualTrafficSelectorContainer) Reset() {
	*container = nil
}

func (container *IndividualTrafficSelectorContainer) BuildIndividualTrafficSelector(
	tsType uint8,
	ipProtocolID uint8,
	startPort uint16,
	endPort uint16,
	startAddr []byte,
	endAddr []byte,
) {
	ts := new(IndividualTrafficSelector)
	ts.TSType = tsType
	ts.IPProtocolID = ipProtocolID
	ts.StartPort = startPort
	ts.EndPort = endPort
	ts.StartAddress = assignOrAppend(nil, startAddr)
	ts.EndAddress = assignOrAppend(nil, endAddr)
	*container = append(*container, ts)
}

// Security Association
func (container *IKEPayloadContainer) BuildSecurityAssociation() *SecurityAssociation {
	sa := new(SecurityAssociation)
	*container = append(*container, sa)
	return sa
}

func (container *ProposalContainer) Reset() {
	*container = nil
}

func (container *ProposalContainer) BuildProposal(proposalNumber uint8, protocolID uint8, spi []byte) *Proposal {
	proposal := new(Proposal)
	proposal.ProposalNumber = proposalNumber
	proposal.ProtocolID = protocolID
	proposal.SPI = assignOrAppend(nil, spi)
	*container = append(*container, proposal)
	return proposal
}

// Delete Payload
func (container *IKEPayloadContainer) BuildDeletePayload(protocolID uint8, spiSize uint8, numberOfSPI uint16, spis []uint32) {
	deletePayload := new(Delete)
	deletePayload.ProtocolID = protocolID
	deletePayload.SPISize = spiSize
	deletePayload.NumberOfSPI = numberOfSPI
	deletePayload.SPIs = spis
	*container = append(*container, deletePayload)
}

func (container *TransformContainer) Reset() {
	*container = nil
}

func (container *TransformContainer) BuildTransform(
	transformType uint8,
	transformID uint16,
	attributeType *uint16,
	attributeValue *uint16,
	variableLengthAttributeValue []byte,
) {
	transform := new(Transform)
	transform.TransformType = transformType
	transform.TransformID = transformID
	if attributeType != nil {
		transform.AttributePresent = true
		transform.AttributeType = *attributeType
		if attributeValue != nil {
			transform.AttributeFormat = AttributeFormatUseTV
			transform.AttributeValue = *attributeValue
		} else if len(variableLengthAttributeValue) != 0 {
			transform.AttributeFormat = AttributeFormatUseTLV
			transform.VariableLengthAttributeValue = assignOrAppend(nil, variableLengthAttributeValue)
		} else {
			return
		}
	} else {
		transform.AttributePresent = false
	}
	*container = append(*container, transform)
}

// EAP
func (container *IKEPayloadContainer) BuildEAP(code uint8, identifier uint8) *EAP {
	eap := new(EAP)
	eap.Code = code
	eap.Identifier = identifier
	*container = append(*container, eap)
	return eap
}

func (container *IKEPayloadContainer) BuildEAPSuccess(identifier uint8) {
	eap := new(EAP)
	eap.Code = EAPCodeSuccess
	eap.Identifier = identifier
	*container = append(*container, eap)
}

func (container *IKEPayloadContainer) BuildEAPFailure(identifier uint8) {
	eap := new(EAP)
	eap.Code = EAPCodeFailure
	eap.Identifier = identifier
	*container = append(*container, eap)
}

func (container *EAPTypeDataContainer) BuildEAPExpanded(vendorID uint32, vendorType uint32, vendorData []byte) {
	eapExpanded := new(EAPExpanded)
	eapExpanded.VendorID = vendorID
	eapExpanded.VendorType = vendorType
	eapExpanded.VendorData = assignOrAppend(nil, vendorData)
	*container = append(*container, eapExpanded)
}

func (container *IKEPayloadContainer) BuildEAP5GStart(identifier uint8) {
	eap := container.BuildEAP(EAPCodeRequest, identifier)
	eap.EAPTypeData.BuildEAPExpanded(VendorID3GPP, VendorTypeEAP5G, []byte{EAP5GType5GStart, EAP5GSpareValue})
}

func (container *IKEPayloadContainer) BuildEAP5GNAS(identifier uint8, nasPDU []byte) error {
	if len(nasPDU) == 0 {
		return errors.New("NASPDU is nil")
	}
	header := make([]byte, 4)
	header[0] = EAP5GType5GNAS
	if len(nasPDU) > math.MaxUint16 {
		return fmt.Errorf("nasPDU length exceeds uint16 limit: %d", len(nasPDU))
	}
	binary.BigEndian.PutUint16(header[2:4], uint16(len(nasPDU)))
	vendorData := append(header, nasPDU...)
	eap := container.BuildEAP(EAPCodeRequest, identifier)
	eap.EAPTypeData.BuildEAPExpanded(VendorID3GPP, VendorTypeEAP5G, vendorData)
	return nil
}

func (container *IKEPayloadContainer) BuildNotify5G_QOS_INFO(pduSessionID uint8,
	qfiList []uint8, isDefault bool, isDSCPSpecified bool, dscp uint8,
) error {
	if len(qfiList) > math.MaxUint8 {
		return fmt.Errorf("qfiList is too long")
	}
	notifyData := []byte{0, pduSessionID, uint8(len(qfiList))}
	notifyData = append(notifyData, qfiList...)
	var flags uint8
	if isDefault {
		flags |= NotifyType5G_QOS_INFOBitDCSICheck
	}
	if isDSCPSpecified {
		flags |= NotifyType5G_QOS_INFOBitDSCPICheck
	}
	notifyData = append(notifyData, flags)
	if isDSCPSpecified {
		notifyData = append(notifyData, dscp)
	}
	if len(notifyData) > math.MaxUint8 {
		return fmt.Errorf("notifyData is too long")
	}
	notifyData[0] = uint8(len(notifyData))
	container.BuildNotification(TypeNone, Vendor3GPPNotifyType5G_QOS_INFO, nil, notifyData)
	return nil
}

func (container *IKEPayloadContainer) BuildNotifyNAS_IP4_ADDRESS(nasIPAddr string) {
	if nasIPAddr == "" {
		return
	}
	ipAddrByte := net.ParseIP(nasIPAddr).To4()
	container.BuildNotification(TypeNone, Vendor3GPPNotifyTypeNAS_IP4_ADDRESS, nil, ipAddrByte)
}

func (container *IKEPayloadContainer) BuildNotifyUP_IP4_ADDRESS(upIPAddr string) {
	if upIPAddr == "" {
		return
	}
	ipAddrByte := net.ParseIP(upIPAddr).To4()
	container.BuildNotification(TypeNone, Vendor3GPPNotifyTypeUP_IP4_ADDRESS, nil, ipAddrByte)
}

func (container *IKEPayloadContainer) BuildNotifyNAS_TCP_PORT(port uint16) {
	if port == 0 {
		return
	}
	portData := make([]byte, 2)
	binary.BigEndian.PutUint16(portData, port)
	container.BuildNotification(TypeNone, Vendor3GPPNotifyTypeNAS_TCP_PORT, nil, portData)
}
