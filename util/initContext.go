// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"strings"

	"git.cs.nctu.edu.tw/calee/sctp"
	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/factory"
	"github.com/omec-project/n3iwf/logger"
)

const (
	NGAP_SCTP_PORT    int = 38412
	requiredTacLength int = 6
	requiredSstLength int = 2
	requiredSdLength  int = 6
)

func InitN3IWFContext() bool {
	var ok bool

	if factory.N3iwfConfig.Configuration == nil {
		logger.ContextLog.Errorln("no N3IWF configuration found")
		return false
	}

	n3iwfContext := context.N3IWFSelf()

	// N3IWF NF information
	n3iwfContext.NfInfo = factory.N3iwfConfig.Configuration.N3iwfInfo
	if ok = formatSupportedTAList(&n3iwfContext.NfInfo); !ok {
		return false
	}

	// AMF SCTP addresses
	if len(factory.N3iwfConfig.Configuration.AmfSctpAddresses) == 0 {
		logger.ContextLog.Errorln("no AMF specified")
		return false
	}
	for _, amfAddress := range factory.N3iwfConfig.Configuration.AmfSctpAddresses {
		amfSCTPAddr := new(sctp.SCTPAddr)
		// IP addresses
		for _, ipAddrStr := range amfAddress.IpAddresses {
			ipAddr, err := net.ResolveIPAddr("ip", ipAddrStr)
			if err != nil {
				logger.ContextLog.Errorf("resolve AMF IP address failed: %+v", err)
				return false
			}
			amfSCTPAddr.IPAddrs = append(amfSCTPAddr.IPAddrs, *ipAddr)
		}
		// Port
		amfSCTPAddr.Port = amfAddress.Port
		if amfAddress.Port == 0 {
			amfSCTPAddr.Port = NGAP_SCTP_PORT
		}
		// Append to context
		n3iwfContext.AmfSctpAddresses = append(n3iwfContext.AmfSctpAddresses, amfSCTPAddr)
	}

	// Local SCTP address
	if factory.N3iwfConfig.Configuration.LocalSctpAddress == "" {
		logger.ContextLog.Errorln("Local SCTP bind address is empty")
		return false
	}
	localSCTPAddr := new(sctp.SCTPAddr)
	// IP address
	ipAddr, err := net.ResolveIPAddr("ip", factory.N3iwfConfig.Configuration.LocalSctpAddress)
	if err != nil {
		logger.ContextLog.Errorf("resolve local IP address for N2 failed: %+v", err)
		return false
	}
	localSCTPAddr.IPAddrs = append(localSCTPAddr.IPAddrs, *ipAddr)
	// Port
	localSCTPAddr.Port = NGAP_SCTP_PORT
	n3iwfContext.LocalSctpAddress = localSCTPAddr

	// IKE bind address
	if factory.N3iwfConfig.Configuration.IkeBindAddress == "" {
		logger.ContextLog.Errorln("IKE bind address is empty")
		return false
	}
	n3iwfContext.IkeBindAddress = factory.N3iwfConfig.Configuration.IkeBindAddress

	// IPSec gateway address
	if factory.N3iwfConfig.Configuration.IpSecAddress == "" {
		logger.ContextLog.Errorln("IPSec interface address is empty")
		return false
	}
	n3iwfContext.IpSecGatewayAddress = factory.N3iwfConfig.Configuration.IpSecAddress

	// GTP bind address
	if factory.N3iwfConfig.Configuration.GtpBindAddress == "" {
		logger.ContextLog.Errorln("GTP bind address is empty")
		return false
	}
	n3iwfContext.GtpBindAddress = factory.N3iwfConfig.Configuration.GtpBindAddress

	// TCP port
	if factory.N3iwfConfig.Configuration.TcpPort == 0 {
		logger.ContextLog.Errorln("TCP port is not defined")
		return false
	}
	n3iwfContext.TcpPort = factory.N3iwfConfig.Configuration.TcpPort

	// FQDN
	if factory.N3iwfConfig.Configuration.Fqdn == "" {
		logger.ContextLog.Errorln("FQDN is empty")
		return false
	}
	n3iwfContext.Fqdn = factory.N3iwfConfig.Configuration.Fqdn

	// Private key
	if factory.N3iwfConfig.Configuration.PrivateKey == "" {
		logger.ContextLog.Errorln("no private key file path specified")
		return false
	}
	content, err := os.ReadFile(factory.N3iwfConfig.Configuration.PrivateKey)
	if err != nil {
		logger.ContextLog.Errorf("cannot read private key data from file: %+v", err)
		return false
	}
	block, _ := pem.Decode(content)
	if block == nil {
		logger.ContextLog.Errorln("parse pem failed")
		return false
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		logger.ContextLog.Warnf("parse PKCS8 private key failed: %+v", err)
		logger.ContextLog.Infoln("parse using PKCS1")
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			logger.ContextLog.Errorf("parse PKCS1 private key failed: %+v", err)
			return false
		}
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		logger.ContextLog.Errorln("private key is not an rsa private key")
		return false
	}
	n3iwfContext.N3iwfPrivateKey = rsaKey

	// Certificate authority
	if factory.N3iwfConfig.Configuration.CertificateAuthority == "" {
		logger.ContextLog.Errorln("no certificate authority file path specified")
		return false
	}
	content, err = os.ReadFile(factory.N3iwfConfig.Configuration.CertificateAuthority)
	if err != nil {
		logger.ContextLog.Errorf("cannot read certificate authority data from file: %+v", err)
		return false
	}
	block, _ = pem.Decode(content)
	if block == nil {
		logger.ContextLog.Errorln("parse pem failed")
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logger.ContextLog.Errorf("parse certificate authority failed: %+v", err)
		return false
	}
	sha1Hash := sha1.New()
	if _, err := sha1Hash.Write(cert.RawSubjectPublicKeyInfo); err != nil {
		logger.ContextLog.Errorf("hash function writing failed: %+v", err)
		return false
	}
	n3iwfContext.CertificateAuthority = sha1Hash.Sum(nil)

	// Certificate
	if factory.N3iwfConfig.Configuration.Certificate == "" {
		logger.ContextLog.Errorln("no certificate file path specified")
		return false
	}
	content, err = os.ReadFile(factory.N3iwfConfig.Configuration.Certificate)
	if err != nil {
		logger.ContextLog.Errorf("cannot read certificate data from file: %+v", err)
		return false
	}
	block, _ = pem.Decode(content)
	if block == nil {
		logger.ContextLog.Errorln("parse pem failed")
		return false
	}
	n3iwfContext.N3iwfCertificate = block.Bytes

	// UE IP address range
	if factory.N3iwfConfig.Configuration.IpSecAddress == "" {
		logger.ContextLog.Errorln("UE IP address range is empty")
		return false
	}
	_, ueNetworkAddr, err := net.ParseCIDR(factory.N3iwfConfig.Configuration.IpSecAddress)
	if err != nil {
		logger.ContextLog.Errorf("parse CIDR failed: %+v", err)
		return false
	}
	n3iwfContext.Subnet = ueNetworkAddr

	return true
}

func formatSupportedTAList(info *context.N3iwfNfInfo) bool {
	for taListIndex := range info.SupportedTaList {
		supportedTAItem := &info.SupportedTaList[taListIndex]

		// Checking Tac
		tacLength := len(supportedTAItem.Tac)
		if tacLength == 0 {
			logger.ContextLog.Errorln("Tac is mandatory")
			return false
		}
		switch {
		case tacLength < requiredTacLength:
			logger.ContextLog.Debugf("detected configuration Tac length < %d", requiredTacLength)
			supportedTAItem.Tac = strings.Repeat("0", 6-len(supportedTAItem.Tac)) + supportedTAItem.Tac
			logger.ContextLog.Debugf("changed to %s", supportedTAItem.Tac)
		case tacLength > requiredTacLength:
			logger.ContextLog.Errorf("detected configuration Tac length > %d", requiredTacLength)
			return false
		}

		// Checking Sst and Sd
		for plmnListIndex := range supportedTAItem.BroadcastPLMNList {
			broadcastPLMNItem := &supportedTAItem.BroadcastPLMNList[plmnListIndex]

			for sliceListIndex := range broadcastPLMNItem.TaiSliceSupportList {
				sliceSupportItem := &broadcastPLMNItem.TaiSliceSupportList[sliceListIndex]

				// Sst
				sstLength := len(sliceSupportItem.Snssai.Sst)
				if sstLength == 0 {
					logger.ContextLog.Errorln("Sst is mandatory")
					return false
				}

				switch {
				case sstLength < requiredSstLength:
					logger.ContextLog.Debugf("detected configuration Sst length < %d", requiredSstLength)
					sliceSupportItem.Snssai.Sst = "0" + sliceSupportItem.Snssai.Sst
					logger.ContextLog.Debugf("change to %s", sliceSupportItem.Snssai.Sst)
				case sstLength > requiredSstLength:
					logger.ContextLog.Errorf("detected configuration Sst length > %d", requiredSstLength)
					return false
				}

				// Sd
				sdLength := len(sliceSupportItem.Snssai.Sd)
				if sdLength != 0 {
					switch {
					case sdLength < requiredSdLength:
						logger.ContextLog.Debugf("detected configuration Sd length < %d", requiredSdLength)
						sliceSupportItem.Snssai.Sd = strings.Repeat("0", 6-len(sliceSupportItem.Snssai.Sd)) + sliceSupportItem.Snssai.Sd
						logger.ContextLog.Debugf("change to %s", sliceSupportItem.Snssai.Sd)
					case sdLength > requiredSdLength:
						logger.ContextLog.Errorf("detected configuration Sd length > %d", requiredSdLength)
						return false
					}
				}
			}
		}
	}

	return true
}
