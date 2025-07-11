// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"crypto/rand"
	"crypto/rsa"
	"math"
	"math/big"
	"net"
	"sync"

	"git.cs.nctu.edu.tw/calee/sctp"
	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/ngap/ngapType"
	"github.com/omec-project/util/idgenerator"
	gtpv1 "github.com/wmnsk/go-gtp/gtpv1"
	"golang.org/x/net/ipv4"
)

var n3iwfContext = N3IWFContext{}

type N3IWFContext struct {
	NfInfo           N3iwfNfInfo
	AmfSctpAddresses []*sctp.SCTPAddr
	LocalSctpAddress *sctp.SCTPAddr

	// ID generator
	RanUuNgapIdGenerator *idgenerator.IDGenerator
	TeidGenerator        *idgenerator.IDGenerator

	// Pools
	UePool                 sync.Map // map[int64]*N3IWFUe, RanUeNgapID as key
	AmfPool                sync.Map // map[string]*N3IWFAMF, SCTPAddr as key
	AmfReInitAvailableList sync.Map // map[string]bool, SCTPAddr as key
	IkeSA                  sync.Map // map[uint64]*IKESecurityAssociation, SPI as key
	ChildSA                sync.Map // map[uint32]*ChildSecurityAssociation, SPI as key
	GtpConnectionUPF       sync.Map // map[string]*gtpv1.UPlaneConn, UPF address as key
	AllocatedUeIpAddress   sync.Map // map[string]*N3IWFUe, IPAddr as key
	AllocatedUeTeid        sync.Map // map[uint32]*N3IWFUe, TEID as key

	// N3IWF FQDN
	Fqdn string

	// Security data
	CertificateAuthority []byte
	N3iwfCertificate     []byte
	N3iwfPrivateKey      *rsa.PrivateKey

	// UEIPAddressRange
	Subnet *net.IPNet

	// Network interface mark for xfrm
	Mark uint32

	// N3IWF local address
	IkeBindAddress      string
	IpSecGatewayAddress string
	GtpBindAddress      string
	TcpPort             uint16

	// N3IWF NWu interface IPv4 packet connection
	NWuIPv4PacketConn *ipv4.PacketConn
}

func init() {
	// init ID generator
	n3iwfContext.RanUuNgapIdGenerator = idgenerator.NewGenerator(0, math.MaxInt64)
	n3iwfContext.TeidGenerator = idgenerator.NewGenerator(1, math.MaxUint32)
}

// Create new N3IWF context
func N3IWFSelf() *N3IWFContext {
	return &n3iwfContext
}

func (context *N3IWFContext) NewN3iwfUe() *N3IWFUe {
	ranUeNgapId, err := context.RanUuNgapIdGenerator.Allocate()
	if err != nil {
		logger.ContextLog.Errorf("new N3IWF UE failed: %+v", err)
		return nil
	}
	n3iwfUe := new(N3IWFUe)
	n3iwfUe.init(ranUeNgapId)
	context.UePool.Store(ranUeNgapId, n3iwfUe)
	return n3iwfUe
}

func (context *N3IWFContext) DeleteN3iwfUe(ranUeNgapId int64) {
	context.UePool.Delete(ranUeNgapId)
}

func (context *N3IWFContext) UePoolLoad(ranUeNgapId int64) (*N3IWFUe, bool) {
	ue, ok := context.UePool.Load(ranUeNgapId)
	if ok {
		return ue.(*N3IWFUe), ok
	} else {
		return nil, ok
	}
}

func (context *N3IWFContext) NewN3iwfAmf(sctpAddr string, conn *sctp.SCTPConn) *N3IWFAMF {
	amf := new(N3IWFAMF)
	amf.init(sctpAddr, conn)
	if item, loaded := context.AmfPool.LoadOrStore(sctpAddr, amf); loaded {
		logger.ContextLog.Warnln("AMF entry already exists")
		return item.(*N3IWFAMF)
	} else {
		return amf
	}
}

func (context *N3IWFContext) DeleteN3iwfAmf(sctpAddr string) {
	context.AmfPool.Delete(sctpAddr)
}

func (context *N3IWFContext) AMFPoolLoad(sctpAddr string) (*N3IWFAMF, bool) {
	amf, ok := context.AmfPool.Load(sctpAddr)
	if ok {
		return amf.(*N3IWFAMF), ok
	} else {
		return nil, ok
	}
}

func (context *N3IWFContext) DeleteAMFReInitAvailableFlag(sctpAddr string) {
	context.AmfReInitAvailableList.Delete(sctpAddr)
}

func (context *N3IWFContext) AMFReInitAvailableListLoad(sctpAddr string) (bool, bool) {
	flag, ok := context.AmfReInitAvailableList.Load(sctpAddr)
	if ok {
		return flag.(bool), ok
	} else {
		return true, ok
	}
}

func (context *N3IWFContext) AMFReInitAvailableListStore(sctpAddr string, flag bool) {
	context.AmfReInitAvailableList.Store(sctpAddr, flag)
}

func (context *N3IWFContext) NewIKESecurityAssociation() *IKESecurityAssociation {
	ikeSecurityAssociation := new(IKESecurityAssociation)

	var maxSPI *big.Int = new(big.Int).SetUint64(math.MaxUint64)
	var localSPIuint64 uint64

	for {
		localSPI, err := rand.Int(rand.Reader, maxSPI)
		if err != nil {
			logger.ContextLog.Errorln("error occurs when generate new IKE SPI")
			return nil
		}
		localSPIuint64 = localSPI.Uint64()
		if _, duplicate := context.IkeSA.LoadOrStore(localSPIuint64, ikeSecurityAssociation); !duplicate {
			break
		}
	}

	ikeSecurityAssociation.LocalSPI = localSPIuint64

	return ikeSecurityAssociation
}

func (context *N3IWFContext) DeleteIKESecurityAssociation(spi uint64) {
	context.IkeSA.Delete(spi)
}

func (context *N3IWFContext) IKESALoad(spi uint64) (*IKESecurityAssociation, bool) {
	securityAssociation, ok := context.IkeSA.Load(spi)
	if ok {
		return securityAssociation.(*IKESecurityAssociation), ok
	} else {
		return nil, ok
	}
}

func (context *N3IWFContext) DeleteGTPConnection(upfAddr string) {
	context.GtpConnectionUPF.Delete(upfAddr)
}

func (context *N3IWFContext) GTPConnectionWithUPFLoad(upfAddr string) (*gtpv1.UPlaneConn, bool) {
	conn, ok := context.GtpConnectionUPF.Load(upfAddr)
	if ok {
		return conn.(*gtpv1.UPlaneConn), ok
	} else {
		return nil, ok
	}
}

func (context *N3IWFContext) GTPConnectionWithUPFStore(upfAddr string, conn *gtpv1.UPlaneConn) {
	context.GtpConnectionUPF.Store(upfAddr, conn)
}

func (context *N3IWFContext) NewInternalUEIPAddr(ue *N3IWFUe) net.IP {
	var ueIPAddr net.IP

	// TODO: Check number of allocated IP to detect running out of IPs
	for {
		ueIPAddr = generateRandomIPinRange(context.Subnet)
		if ueIPAddr != nil {
			if ueIPAddr.String() == context.IpSecGatewayAddress {
				continue
			}
			if _, ok := context.AllocatedUeIpAddress.LoadOrStore(ueIPAddr.String(), ue); !ok {
				break
			}
		}
	}

	return ueIPAddr
}

func (context *N3IWFContext) DeleteInternalUEIPAddr(ipAddr string) {
	context.AllocatedUeIpAddress.Delete(ipAddr)
}

func (context *N3IWFContext) AllocatedUEIPAddressLoad(ipAddr string) (*N3IWFUe, bool) {
	ue, ok := context.AllocatedUeIpAddress.Load(ipAddr)
	if ok {
		return ue.(*N3IWFUe), ok
	} else {
		return nil, ok
	}
}

func (context *N3IWFContext) NewTEID(ue *N3IWFUe) uint32 {
	teid64, err := context.TeidGenerator.Allocate()
	if err != nil {
		logger.ContextLog.Errorf("new TEID failed: %+v", err)
		return 0
	}
	teid32 := uint32(teid64)

	context.AllocatedUeTeid.Store(teid32, ue)

	return teid32
}

func (context *N3IWFContext) DeleteTEID(teid uint32) {
	context.AllocatedUeTeid.Delete(teid)
}

func (context *N3IWFContext) AllocatedUETEIDLoad(teid uint32) (*N3IWFUe, bool) {
	ue, ok := context.AllocatedUeTeid.Load(teid)
	if ok {
		return ue.(*N3IWFUe), ok
	} else {
		return nil, ok
	}
}

func (context *N3IWFContext) AMFSelection(ueSpecifiedGUAMI *ngapType.GUAMI) *N3IWFAMF {
	var availableAMF *N3IWFAMF
	context.AmfPool.Range(func(key, value any) bool {
		amf := value.(*N3IWFAMF)
		if amf.FindAvailableAMFByCompareGUAMI(ueSpecifiedGUAMI) {
			availableAMF = amf
			return false
		} else {
			return true
		}
	})
	return availableAMF
}

func generateRandomIPinRange(subnet *net.IPNet) net.IP {
	ipAddr := make([]byte, 4)
	randomNumber := make([]byte, 4)

	_, err := rand.Read(randomNumber)
	if err != nil {
		logger.ContextLog.Errorf("generate random number for IP address failed: %+v", err)
		return nil
	}

	// TODO: eliminate network name, gateway, and broadcast
	for i := range randomNumber[:4] {
		alter := randomNumber[i] & (subnet.Mask[i] ^ 255)
		ipAddr[i] = subnet.IP[i] + alter
	}

	return net.IPv4(ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3])
}
