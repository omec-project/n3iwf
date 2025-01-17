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
	n3iwfContext.NfInfo = factory.N3iwfConfig.Configuration.N3iwfInfo
	if ok = formatSupportedTAList(&n3iwfContext.NfInfo); !ok {
		return false
	}

	// AMF SCTP addresses
	if len(factory.N3iwfConfig.Configuration.AmfSctpAddresses) == 0 {
		logger.ContextLog.Errorln("no AMF specified")
		return false
	} else {
		for _, amfAddress := range factory.N3iwfConfig.Configuration.AmfSctpAddresses {
			amfSCTPAddr := new(sctp.SCTPAddr)
			// IP addresses
			for _, ipAddrStr := range amfAddress.IpAddresses {
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
			n3iwfContext.AmfSctpAddresses = append(n3iwfContext.AmfSctpAddresses, amfSCTPAddr)
		}
	}

	// IKE bind address
	if factory.N3iwfConfig.Configuration.IkeBindAddress == "" {
		logger.ContextLog.Errorln("IKE bind address is empty")
		return false
	} else {
		n3iwfContext.IkeBindAddress = factory.N3iwfConfig.Configuration.IkeBindAddress
	}

	// IPSec gateway address
	if factory.N3iwfConfig.Configuration.IpSecAddress == "" {
		logger.ContextLog.Errorln("IPSec interface address is empty")
		return false
	} else {
		n3iwfContext.IpSecGatewayAddress = factory.N3iwfConfig.Configuration.IpSecAddress
	}

	// GTP bind address
	if factory.N3iwfConfig.Configuration.GtpBindAddress == "" {
		logger.ContextLog.Errorln("GTP bind address is empty")
		return false
	} else {
		n3iwfContext.GtpBindAddress = factory.N3iwfConfig.Configuration.GtpBindAddress
	}

	// TCP port
	if factory.N3iwfConfig.Configuration.TcpPort == 0 {
		logger.ContextLog.Errorln("TCP port is not defined")
		return false
	} else {
		n3iwfContext.TcpPort = factory.N3iwfConfig.Configuration.TcpPort
	}

	// FQDN
	if factory.N3iwfConfig.Configuration.Fqdn == "" {
		logger.ContextLog.Errorln("FQDN is empty")
		return false
	} else {
		n3iwfContext.Fqdn = factory.N3iwfConfig.Configuration.Fqdn
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

		n3iwfContext.N3iwfPrivateKey = rsaKey
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

		n3iwfContext.N3iwfCertificate = block.Bytes
	}

	// UE IP address range
	if factory.N3iwfConfig.Configuration.UeIpNetwork == "" {
		logger.ContextLog.Errorln("UE IP address range is empty")
		return false
	} else {
		_, ueNetworkAddr, err := net.ParseCIDR(factory.N3iwfConfig.Configuration.UeIpNetwork)
		if err != nil {
			logger.ContextLog.Errorf("parse CIDR failed: %+v", err)
			return false
		}
		n3iwfContext.Subnet = ueNetworkAddr
	}

	if factory.N3iwfConfig.Configuration.InterfaceMark == 0 {
		logger.ContextLog.Warnln("IPSec interface mark is not defined, set to default value 7")
		n3iwfContext.Mark = 7
	} else {
		n3iwfContext.Mark = factory.N3iwfConfig.Configuration.InterfaceMark
	}

	return true
}

func formatSupportedTAList(info *context.N3iwfNfInfo) bool {
	for taListIndex := range info.SupportedTaList {
		supportedTAItem := &info.SupportedTaList[taListIndex]

		// Checking Tac
		if supportedTAItem.Tac == "" {
			logger.ContextLog.Errorln("Tac is mandatory")
			return false
		}
		if len(supportedTAItem.Tac) < 6 {
			logger.ContextLog.Debugln("detect configuration Tac length < 6")
			supportedTAItem.Tac = strings.Repeat("0", 6-len(supportedTAItem.Tac)) + supportedTAItem.Tac
			logger.ContextLog.Debugf("changed to %s", supportedTAItem.Tac)
		} else if len(supportedTAItem.Tac) > 6 {
			logger.ContextLog.Errorln("detect configuration Tac length > 6")
			return false
		}

		// Checking Sst and Sd
		for plmnListIndex := range supportedTAItem.BroadcastPLMNList {
			broadcastPLMNItem := &supportedTAItem.BroadcastPLMNList[plmnListIndex]

			for sliceListIndex := range broadcastPLMNItem.TaiSliceSupportList {
				sliceSupportItem := &broadcastPLMNItem.TaiSliceSupportList[sliceListIndex]

				// Sst
				if sliceSupportItem.Snssai.Sst == "" {
					logger.ContextLog.Errorln("Sst is mandatory")
				}
				if len(sliceSupportItem.Snssai.Sst) < 2 {
					logger.ContextLog.Debugln("detect configuration Sst length < 2")
					sliceSupportItem.Snssai.Sst = "0" + sliceSupportItem.Snssai.Sst
					logger.ContextLog.Debugf("change to %s", sliceSupportItem.Snssai.Sst)
				} else if len(sliceSupportItem.Snssai.Sst) > 2 {
					logger.ContextLog.Errorln("detect configuration Sst length > 2")
					return false
				}

				// Sd
				if sliceSupportItem.Snssai.Sd != "" {
					if len(sliceSupportItem.Snssai.Sd) < 6 {
						logger.ContextLog.Debugln("detect configuration Sd length < 6")
						sliceSupportItem.Snssai.Sd = strings.Repeat("0", 6-len(sliceSupportItem.Snssai.Sd)) + sliceSupportItem.Snssai.Sd
						logger.ContextLog.Debugf("change to %s", sliceSupportItem.Snssai.Sd)
					} else if len(sliceSupportItem.Snssai.Sd) > 6 {
						logger.ContextLog.Errorln("detect configuration Sd length > 6")
						return false
					}
				}
			}
		}
	}

	return true
}
