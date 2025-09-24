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
	"fmt"
	"math"
	"net"
	"os"
	"strings"

	"github.com/ishidawataru/sctp"
	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/factory"
	"github.com/omec-project/n3iwf/logger"
)

const (
	ngap_sctp_port           int    = 38412
	requiredTacLength        int    = 6
	requiredSdLength         int    = 6
	defaultXfrmInterfaceId   uint32 = 7
	defaultXfrmInterfaceName string = "ipsec"
)

func InitN3IWFContext() bool {
	n3iwfCfg := factory.N3iwfConfig.Configuration
	if n3iwfCfg == nil {
		logger.CtxLog.Errorln("no N3IWF configuration found")
		return false
	}

	n := context.N3IWFSelf()

	// N3IWF NF information
	n.NfInfo = n3iwfCfg.N3iwfInfo
	if !formatSupportedTAList(&n.NfInfo) {
		return false
	}

	// AMF SCTP addresses
	if len(n3iwfCfg.AmfSctpAddresses) == 0 {
		logger.CtxLog.Errorln("no AMF specified")
		return false
	}
	for _, amfAddress := range n3iwfCfg.AmfSctpAddresses {
		amfSCTPAddr := new(sctp.SCTPAddr)
		for _, ipAddrStr := range amfAddress.IpAddresses {
			ipAddr, err := net.ResolveIPAddr("ip", ipAddrStr)
			if err != nil {
				logger.CtxLog.Errorf("resolve AMF IP address failed: %+v", err)
				return false
			}
			amfSCTPAddr.IPAddrs = append(amfSCTPAddr.IPAddrs, *ipAddr)
		}
		amfSCTPAddr.Port = amfAddress.Port
		if amfAddress.Port == 0 {
			amfSCTPAddr.Port = ngap_sctp_port
		}
		n.AmfSctpAddresses = append(n.AmfSctpAddresses, amfSCTPAddr)
	}

	// Local SCTP address
	if !checkEmpty(n3iwfCfg.LocalSctpAddress, "local SCTP bind address is empty") {
		return false
	}
	localSCTPAddr := new(sctp.SCTPAddr)
	ipAddr, err := net.ResolveIPAddr("ip", n3iwfCfg.LocalSctpAddress)
	if err != nil {
		logger.CtxLog.Errorf("resolve local IP address for N2 failed: %+v", err)
		return false
	}
	localSCTPAddr.IPAddrs = append(localSCTPAddr.IPAddrs, *ipAddr)
	localSCTPAddr.Port = ngap_sctp_port
	n.LocalSctpAddress = localSCTPAddr

	// IKE bind address
	if !checkEmpty(n3iwfCfg.IkeBindAddress, "IKE bind address is empty") {
		return false
	}
	n.IkeBindAddress = n3iwfCfg.IkeBindAddress

	// IPSec gateway address
	if !checkEmpty(n3iwfCfg.IpSecAddress, "IPSec interface address is empty") {
		return false
	}
	n3iwfIpAddr, _, err := net.ParseCIDR(n3iwfCfg.IpSecAddress)
	if err != nil {
		logger.CtxLog.Errorf("parse IpSecAddress failed: %+v", err)
		return false
	}
	n.IpSecGatewayAddress = n3iwfIpAddr.String()

	// UE IP address range
	_, ueNetworkAddr, err := net.ParseCIDR(n3iwfCfg.IpSecAddress)
	if err != nil {
		logger.CtxLog.Errorf("parse CIDR failed: %+v", err)
		return false
	}
	n.Subnet = ueNetworkAddr

	// GTP bind address
	if !checkEmpty(n3iwfCfg.GtpBindAddress, "GTP bind address is empty") {
		return false
	}
	n.GtpBindAddress = n3iwfCfg.GtpBindAddress

	// TCP port
	if n3iwfCfg.TcpPort == 0 {
		logger.CtxLog.Errorln("TCP port is not defined")
		return false
	}
	n.TcpPort = n3iwfCfg.TcpPort

	// FQDN
	if !checkEmpty(n3iwfCfg.Fqdn, "FQDN is empty") {
		return false
	}
	n.Fqdn = n3iwfCfg.Fqdn

	// Private key
	if !checkEmpty(n3iwfCfg.PrivateKey, "no private key file path specified") {
		return false
	}
	content, ok := readFile(n3iwfCfg.PrivateKey, "cannot read private key data from file")
	if !ok {
		return false
	}
	block, _ := pem.Decode(content)
	if block == nil {
		logger.CtxLog.Errorln("parse pem failed")
		return false
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		logger.CtxLog.Warnf("parse PKCS8 private key failed: %+v", err)
		logger.CtxLog.Infoln("parse using PKCS1")
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			logger.CtxLog.Errorf("parse PKCS1 private key failed: %+v", err)
			return false
		}
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		logger.CtxLog.Errorln("private key is not an rsa private key")
		return false
	}
	n.N3iwfPrivateKey = rsaKey

	// Certificate authority
	if !checkEmpty(n3iwfCfg.CertificateAuthority, "no certificate authority file path specified") {
		return false
	}
	content, ok = readFile(n3iwfCfg.CertificateAuthority, "cannot read certificate authority data from file")
	if !ok {
		return false
	}
	block, _ = pem.Decode(content)
	if block == nil {
		logger.CtxLog.Errorln("parse pem failed")
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logger.CtxLog.Errorf("parse certificate authority failed: %+v", err)
		return false
	}
	sha1Hash := sha1.New()
	if _, err := sha1Hash.Write(cert.RawSubjectPublicKeyInfo); err != nil {
		logger.CtxLog.Errorf("hash function writing failed: %+v", err)
		return false
	}
	n.CertificateAuthority = sha1Hash.Sum(nil)

	// Certificate
	if !checkEmpty(n3iwfCfg.Certificate, "no certificate file path specified") {
		return false
	}
	content, ok = readFile(n3iwfCfg.Certificate, "cannot read certificate data from file")
	if !ok {
		return false
	}
	block, _ = pem.Decode(content)
	if block == nil {
		logger.CtxLog.Errorln("parse pem failed")
		return false
	}
	n.N3iwfCertificate = block.Bytes

	// XFRM related
	ikeBindIfaceName, err := getInterfaceName(n3iwfCfg.IkeBindAddress)
	if err != nil {
		logger.CtxLog.Error(err)
		return false
	}
	n.XfrmParentIfaceName = ikeBindIfaceName

	n.XfrmInterfaceName = n3iwfCfg.XfrmInterfaceName
	if n.XfrmInterfaceName == "" {
		n.XfrmInterfaceName = defaultXfrmInterfaceName
		logger.CtxLog.Warnln("XFRM interface Name is empty, set to default", n.XfrmInterfaceName)
	}

	n.XfrmInterfaceId = n3iwfCfg.XfrmInterfaceId
	if n.XfrmInterfaceId == 0 {
		n.XfrmInterfaceId = defaultXfrmInterfaceId
		logger.CtxLog.Warnln("XFRM interface id is not defined, set to default value", n.XfrmInterfaceId)
	}

	return true
}

// Helper to check empty string config
func checkEmpty(val, msg string) bool {
	if val == "" {
		logger.CtxLog.Errorln(msg)
		return false
	}
	return true
}

// Helper to read file content
func readFile(path, errMsg string) ([]byte, bool) {
	content, err := os.ReadFile(path)
	if err != nil {
		logger.CtxLog.Errorf("%s: %+v", errMsg, err)
		return nil, false
	}
	return content, true
}

func formatSupportedTAList(info *context.N3iwfNfInfo) bool {
	for taListIndex := range info.SupportedTaList {
		supportedTAItem := &info.SupportedTaList[taListIndex]

		// Checking Tac
		tacLength := len(supportedTAItem.Tac)
		if tacLength == 0 {
			logger.CtxLog.Errorln("tac is mandatory")
			return false
		}
		switch {
		case tacLength < requiredTacLength:
			logger.CtxLog.Debugf("detected configuration Tac length < %d", requiredTacLength)
			supportedTAItem.Tac = strings.Repeat("0", 6-len(supportedTAItem.Tac)) + supportedTAItem.Tac
			logger.CtxLog.Debugf("changed to %s", supportedTAItem.Tac)
		case tacLength > requiredTacLength:
			logger.CtxLog.Errorf("detected configuration Tac length > %d", requiredTacLength)
			return false
		}

		// Checking Sst and Sd
		for plmnListIndex := range supportedTAItem.BroadcastPlmnList {
			broadcastPLMNItem := &supportedTAItem.BroadcastPlmnList[plmnListIndex]

			for sliceListIndex := range broadcastPLMNItem.TaiSliceSupportList {
				sliceSupportItem := &broadcastPLMNItem.TaiSliceSupportList[sliceListIndex]

				// Sst
				sst := sliceSupportItem.Snssai.Sst
				if sst == 0 {
					logger.CtxLog.Errorln("sst is mandatory")
					return false
				}

				if sst > math.MaxUint8 {
					logger.CtxLog.Errorf("detect configuration sst length > %d", sst)
					return false
				}

				// Sd
				if sliceSupportItem.Snssai.Sd == "" {
					logger.CtxLog.Infoln("Snssai does not include sd")
					continue
				}
				sdLength := len(sliceSupportItem.Snssai.Sd)
				if sdLength > requiredSdLength {
					logger.CtxLog.Errorf("detected configuration sd length > %d", requiredSdLength)
					return false
				}
				if sdLength < requiredSdLength {
					logger.CtxLog.Debugf("detected configuration sd length < %d", requiredSdLength)
					sliceSupportItem.Snssai.Sd = strings.Repeat("0", 6-sdLength) + sliceSupportItem.Snssai.Sd
					logger.CtxLog.Debugf("change to %s", sliceSupportItem.Snssai.Sd)
				}
			}
		}
	}

	return true
}

func getInterfaceName(IPAddress string) (interfaceName string, err error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	res, err := net.ResolveIPAddr("ip4", IPAddress)
	if err != nil {
		return "", fmt.Errorf("error resolving address '%s': %v", IPAddress, err)
	}
	IPAddress = res.String()

	for _, inter := range interfaces {
		addrs, err := inter.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			if IPAddress == addr.String()[0:strings.Index(addr.String(), "/")] {
				return inter.Name, nil
			}
		}
	}
	return "", fmt.Errorf("cannot find interface name")
}
