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

func InitN3IWFContext() bool {
	var ok bool

	if factory.N3iwfConfig.Configuration == nil {
		logger.ContextLog.Errorln("no N3IWF configuration found")
		return false
	}

	n3iwfContext := context.N3IWFSelf()

	// N3IWF NF information
	n3iwfContext.NFInfo = factory.N3iwfConfig.Configuration.N3IWFInfo
	if ok = formatSupportedTAList(&n3iwfContext.NFInfo); !ok {
		return false
	}

	// AMF SCTP addresses
	if len(factory.N3iwfConfig.Configuration.AMFSCTPAddresses) == 0 {
		logger.ContextLog.Errorln("no AMF specified")
		return false
	} else {
		for _, amfAddress := range factory.N3iwfConfig.Configuration.AMFSCTPAddresses {
			amfSCTPAddr := new(sctp.SCTPAddr)
			// IP addresses
			for _, ipAddrStr := range amfAddress.IPAddresses {
				if ipAddr, err := net.ResolveIPAddr("ip", ipAddrStr); err != nil {
					logger.ContextLog.Errorf("resolve AMF IP address failed: %+v", err)
					return false
				} else {
					amfSCTPAddr.IPAddrs = append(amfSCTPAddr.IPAddrs, *ipAddr)
				}
			}
			// Port
			if amfAddress.Port == 0 {
				amfSCTPAddr.Port = 38412
			} else {
				amfSCTPAddr.Port = amfAddress.Port
			}
			// Append to context
			n3iwfContext.AMFSCTPAddresses = append(n3iwfContext.AMFSCTPAddresses, amfSCTPAddr)
		}
	}

	// IKE bind address
	if factory.N3iwfConfig.Configuration.IKEBindAddr == "" {
		logger.ContextLog.Errorln("IKE bind address is empty")
		return false
	} else {
		n3iwfContext.IKEBindAddress = factory.N3iwfConfig.Configuration.IKEBindAddr
	}

	// IPSec gateway address
	if factory.N3iwfConfig.Configuration.IPSecGatewayAddr == "" {
		logger.ContextLog.Errorln("IPSec interface address is empty")
		return false
	} else {
		n3iwfContext.IPSecGatewayAddress = factory.N3iwfConfig.Configuration.IPSecGatewayAddr
	}

	// GTP bind address
	if factory.N3iwfConfig.Configuration.GTPBindAddr == "" {
		logger.ContextLog.Errorln("GTP bind address is empty")
		return false
	} else {
		n3iwfContext.GTPBindAddress = factory.N3iwfConfig.Configuration.GTPBindAddr
	}

	// TCP port
	if factory.N3iwfConfig.Configuration.TCPPort == 0 {
		logger.ContextLog.Errorln("TCP port is not defined")
		return false
	} else {
		n3iwfContext.TCPPort = factory.N3iwfConfig.Configuration.TCPPort
	}

	// FQDN
	if factory.N3iwfConfig.Configuration.FQDN == "" {
		logger.ContextLog.Errorln("FQDN is empty")
		return false
	} else {
		n3iwfContext.FQDN = factory.N3iwfConfig.Configuration.FQDN
	}

	// Private key
	{
		var keyPath string

		if factory.N3iwfConfig.Configuration.PrivateKey != "" {
			keyPath = factory.N3iwfConfig.Configuration.PrivateKey
		} else {
			logger.ContextLog.Errorln("no private key file path specified")
		}

		content, err := os.ReadFile(keyPath)
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
				logger.ContextLog.Errorf("parse PKCS1 pricate key failed: %+v", err)
				return false
			}
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			logger.ContextLog.Errorln("private key is not an rsa private key")
			return false
		}

		n3iwfContext.N3IWFPrivateKey = rsaKey
	}

	// Certificate authority
	{
		var keyPath string

		if factory.N3iwfConfig.Configuration.CertificateAuthority != "" {
			keyPath = factory.N3iwfConfig.Configuration.CertificateAuthority
		} else {
			logger.ContextLog.Errorln("no certificate authority file path specified")
		}

		// Read .pem
		content, err := os.ReadFile(keyPath)
		if err != nil {
			logger.ContextLog.Errorf("cannot read certificate authority data from file: %+v", err)
			return false
		}
		// Decode pem
		block, _ := pem.Decode(content)
		if block == nil {
			logger.ContextLog.Errorln("parse pem failed")
			return false
		}
		// Parse DER-encoded x509 certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			logger.ContextLog.Errorf("parse certificate authority failed: %+v", err)
			return false
		}
		// Get sha1 hash of subject public key info
		sha1Hash := sha1.New()
		if _, err := sha1Hash.Write(cert.RawSubjectPublicKeyInfo); err != nil {
			logger.ContextLog.Errorf("hash function writing failed: %+v", err)
			return false
		}

		n3iwfContext.CertificateAuthority = sha1Hash.Sum(nil)
	}

	// Certificate
	{
		var keyPath string

		if factory.N3iwfConfig.Configuration.Certificate != "" {
			keyPath = factory.N3iwfConfig.Configuration.Certificate
		} else {
			logger.ContextLog.Errorln("no certificate file path specified")
		}

		// Read .pem
		content, err := os.ReadFile(keyPath)
		if err != nil {
			logger.ContextLog.Errorf("cannot read certificate data from file: %+v", err)
			return false
		}
		// Decode pem
		block, _ := pem.Decode(content)
		if block == nil {
			logger.ContextLog.Errorln("parse pem failed")
			return false
		}

		n3iwfContext.N3IWFCertificate = block.Bytes
	}

	// UE IP address range
	if factory.N3iwfConfig.Configuration.UEIPAddressRange == "" {
		logger.ContextLog.Errorln("UE IP address range is empty")
		return false
	} else {
		_, ueIPRange, err := net.ParseCIDR(factory.N3iwfConfig.Configuration.UEIPAddressRange)
		if err != nil {
			logger.ContextLog.Errorf("parse CIDR failed: %+v", err)
			return false
		}
		n3iwfContext.Subnet = ueIPRange
	}

	if factory.N3iwfConfig.Configuration.InterfaceMark == 0 {
		logger.ContextLog.Warnln("IPSec interface mark is not defined, set to default value 7")
		n3iwfContext.Mark = 7
	} else {
		n3iwfContext.Mark = factory.N3iwfConfig.Configuration.InterfaceMark
	}

	return true
}

func formatSupportedTAList(info *context.N3IWFNFInfo) bool {
	for taListIndex := range info.SupportedTAList {
		supportedTAItem := &info.SupportedTAList[taListIndex]

		// Checking TAC
		if supportedTAItem.TAC == "" {
			logger.ContextLog.Errorln("TAC is mandatory")
			return false
		}
		if len(supportedTAItem.TAC) < 6 {
			logger.ContextLog.Debugln("detect configuration TAC length < 6")
			supportedTAItem.TAC = strings.Repeat("0", 6-len(supportedTAItem.TAC)) + supportedTAItem.TAC
			logger.ContextLog.Debugf("changed to %s", supportedTAItem.TAC)
		} else if len(supportedTAItem.TAC) > 6 {
			logger.ContextLog.Errorln("detect configuration TAC length > 6")
			return false
		}

		// Checking SST and SD
		for plmnListIndex := range supportedTAItem.BroadcastPLMNList {
			broadcastPLMNItem := &supportedTAItem.BroadcastPLMNList[plmnListIndex]

			for sliceListIndex := range broadcastPLMNItem.TAISliceSupportList {
				sliceSupportItem := &broadcastPLMNItem.TAISliceSupportList[sliceListIndex]

				// SST
				if sliceSupportItem.SNSSAI.SST == "" {
					logger.ContextLog.Errorln("SST is mandatory")
				}
				if len(sliceSupportItem.SNSSAI.SST) < 2 {
					logger.ContextLog.Debugln("detect configuration SST length < 2")
					sliceSupportItem.SNSSAI.SST = "0" + sliceSupportItem.SNSSAI.SST
					logger.ContextLog.Debugf("change to %s", sliceSupportItem.SNSSAI.SST)
				} else if len(sliceSupportItem.SNSSAI.SST) > 2 {
					logger.ContextLog.Errorln("detect configuration SST length > 2")
					return false
				}

				// SD
				if sliceSupportItem.SNSSAI.SD != "" {
					if len(sliceSupportItem.SNSSAI.SD) < 6 {
						logger.ContextLog.Debugln("detect configuration SD length < 6")
						sliceSupportItem.SNSSAI.SD = strings.Repeat("0", 6-len(sliceSupportItem.SNSSAI.SD)) + sliceSupportItem.SNSSAI.SD
						logger.ContextLog.Debugf("change to %s", sliceSupportItem.SNSSAI.SD)
					} else if len(sliceSupportItem.SNSSAI.SD) > 6 {
						logger.ContextLog.Errorln("detect configuration SD length > 6")
						return false
					}
				}
			}
		}
	}

	return true
}
