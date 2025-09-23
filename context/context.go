// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math"
	"math/big"
	"net"
	"sync"

	"github.com/ishidawataru/sctp"
	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/ngap/ngapType"
	"github.com/omec-project/util/idgenerator"
	gtpv1 "github.com/wmnsk/go-gtp/gtpv1"
	"golang.org/x/net/ipv4"
)

var n3iwfContext N3IWFContext

type N3IWFContext struct {
	NfInfo           N3iwfNfInfo
	AmfSctpAddresses []*sctp.SCTPAddr
	LocalSctpAddress *sctp.SCTPAddr

	// ID generator
	RanUuNgapIdGenerator *idgenerator.IDGenerator
	TeidGenerator        *idgenerator.IDGenerator

	// Pools
	AmfPool                sync.Map // map[string]*N3IWFAMF, SCTPAddr as key
	AmfReInitAvailableList sync.Map // map[string]bool, SCTPAddr as key
	IkeSA                  sync.Map // map[uint64]*IKESecurityAssociation, SPI as key
	ChildSA                sync.Map // map[uint32]*ChildSecurityAssociation, inboundSPI as key
	GtpConnectionUPF       sync.Map // map[string]*gtpv1.UPlaneConn, UPF address as key
	AllocatedUeIpAddress   sync.Map // map[string]*N3IWFIkeUe, IPAddr as key
	AllocatedUeTeid        sync.Map // map[uint32]*N3IWFRanUe, TEID as key
	IkeUePool              sync.Map // map[uint64]*N3IWFIkeUe, SPI as key
	RanUePool              sync.Map // map[int64]*N3IWFRanUe, RanUeNgapID as key
	IkeSpiToNgapId         sync.Map // map[uint64]RanUeNgapID, SPI as key
	NgapIdToIkeSpi         sync.Map // map[uint64]SPI, RanUeNgapID as key

	// N3IWF FQDN
	Fqdn string

	// Security data
	CertificateAuthority []byte
	N3iwfCertificate     []byte
	N3iwfPrivateKey      *rsa.PrivateKey

	// UEIPAddressRange
	Subnet *net.IPNet

	// XFRM interface
	XfrmInterfaceId     uint32
	XfrmIfaces          sync.Map // map[uint32]*netlink.Link, XfrmInterfaceId as key
	XfrmInterfaceName   string
	XfrmParentIfaceName string

	// Every UE's first UP IPsec will use default XFRM interface, additoinal UP IPsec will offset its XFRM id
	XfrmIfaceIdOffsetForUP uint32

	// N3IWF local address
	IkeBindAddress      string
	IpSecGatewayAddress string
	GtpBindAddress      string
	TcpPort             uint16

	// N3IWF NWu interface IPv4 packet connection
	NWuIPv4PacketConn *ipv4.PacketConn

	Ctx context.Context
	Wg  sync.WaitGroup

	NgapServer *NgapServer
	IkeServer  *IkeServer
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

func (context *N3IWFContext) NewN3iwfIkeUe(spi uint64) *N3IWFIkeUe {
	n3iwfIkeUe := new(N3IWFIkeUe)
	n3iwfIkeUe.init()
	context.IkeUePool.Store(spi, n3iwfIkeUe)
	return n3iwfIkeUe
}

func (context *N3IWFContext) NewN3iwfRanUe() *N3IWFRanUe {
	ranUeNgapId, err := context.RanUuNgapIdGenerator.Allocate()
	if err != nil {
		logger.ContextLog.Errorf("new N3IWF UE failed: %+v", err)
		return nil
	}
	n3iwfRanUe := new(N3IWFRanUe)
	n3iwfRanUe.init(ranUeNgapId)
	context.RanUePool.Store(ranUeNgapId, n3iwfRanUe)
	n3iwfRanUe.TemporaryPDUSessionSetupData = new(PDUSessionSetupTemporaryData)

	return n3iwfRanUe
}

func (context *N3IWFContext) DeleteRanUe(ranUeNgapId int64) {
	context.RanUePool.Delete(ranUeNgapId)
	context.DeleteIkeSPIFromNgapId(ranUeNgapId)
}

func (context *N3IWFContext) DeleteIKEUe(spi uint64) {
	context.IkeUePool.Delete(spi)
	context.DeleteNgapIdFromIkeSPI(spi)
}

func (context *N3IWFContext) IkeUePoolLoad(spi uint64) (*N3IWFIkeUe, bool) {
	if ikeUe, ok := context.IkeUePool.Load(spi); ok {
		return ikeUe.(*N3IWFIkeUe), true
	}
	return nil, false
}

func (context *N3IWFContext) RanUePoolLoad(ranUeNgapId int64) (*N3IWFRanUe, bool) {
	if ranUe, ok := context.RanUePool.Load(ranUeNgapId); ok {
		return ranUe.(*N3IWFRanUe), true
	}
	return nil, false
}

func (context *N3IWFContext) AllocatedUEIPAddressLoad(ipAddr string) (*N3IWFIkeUe, bool) {
	if ikeUe, ok := context.AllocatedUeIpAddress.Load(ipAddr); ok {
		return ikeUe.(*N3IWFIkeUe), true
	}
	return nil, false
}

func (context *N3IWFContext) AllocatedUETEIDLoad(teid uint32) (*N3IWFRanUe, bool) {
	if ranUe, ok := context.AllocatedUeTeid.Load(teid); ok {
		return ranUe.(*N3IWFRanUe), true
	}
	return nil, false
}

func (context *N3IWFContext) IkeSpiNgapIdMapping(spi uint64, ranUeNgapId int64) {
	context.IkeSpiToNgapId.Store(spi, ranUeNgapId)
	context.NgapIdToIkeSpi.Store(ranUeNgapId, spi)
}

func (context *N3IWFContext) IkeSpiLoad(ranUeNgapId int64) (uint64, bool) {
	if spi, ok := context.NgapIdToIkeSpi.Load(ranUeNgapId); ok {
		return spi.(uint64), true
	}
	return 0, false
}

func (context *N3IWFContext) NgapIdLoad(spi uint64) (int64, bool) {
	if ranNgapId, ok := context.IkeSpiToNgapId.Load(spi); ok {
		return ranNgapId.(int64), true
	}
	return 0, false
}

func (context *N3IWFContext) DeleteNgapIdFromIkeSPI(spi uint64) {
	context.IkeSpiToNgapId.Delete(spi)
}

func (context *N3IWFContext) DeleteIkeSPIFromNgapId(ranUeNgapId int64) {
	context.NgapIdToIkeSpi.Delete(ranUeNgapId)
}

func (context *N3IWFContext) RanUeLoadFromIkeSPI(spi uint64) (*N3IWFRanUe, error) {
	ranNgapId, ok := context.IkeSpiToNgapId.Load(spi)
	if !ok {
		return nil, fmt.Errorf("cannot find RanNgapId from IkeUe SPI: %+v", spi)
	}

	ranUe, err := context.RanUePoolLoad(ranNgapId.(int64))
	if !err {
		return nil, fmt.Errorf("cannot find RanUE from RanNgapId: %+v", ranNgapId)
	}
	return ranUe, nil
}

func (context *N3IWFContext) IkeUeLoadFromNgapId(ranUeNgapId int64) (*N3IWFIkeUe, error) {
	spi, ok := context.NgapIdToIkeSpi.Load(ranUeNgapId)
	if !ok {
		return nil, fmt.Errorf("cannot find SPI from NgapId: %d", ranUeNgapId)
	}
	ikeUe, err := context.IkeUePoolLoad(spi.(uint64))
	if !err {
		return nil, fmt.Errorf("cannot find IkeUe from spi: %+v", spi)
	}
	return ikeUe, nil
}

func (context *N3IWFContext) NewN3iwfAmf(sctpAddr string, conn *sctp.SCTPConn) *N3IWFAMF {
	amf := new(N3IWFAMF)
	amf.init(sctpAddr, conn)
	if item, loaded := context.AmfPool.LoadOrStore(sctpAddr, amf); loaded {
		logger.ContextLog.Warnln("AMF entry already exists")
		return item.(*N3IWFAMF)
	}
	return amf
}

func (context *N3IWFContext) DeleteN3iwfAmf(sctpAddr string) {
	context.AmfPool.Delete(sctpAddr)
}

func (context *N3IWFContext) AMFPoolLoad(sctpAddr string) (*N3IWFAMF, bool) {
	if amf, ok := context.AmfPool.Load(sctpAddr); ok {
		return amf.(*N3IWFAMF), true
	}
	return nil, false
}

func (context *N3IWFContext) DeleteAMFReInitAvailableFlag(sctpAddr string) {
	context.AmfReInitAvailableList.Delete(sctpAddr)
}

func (context *N3IWFContext) AMFReInitAvailableListLoad(sctpAddr string) (bool, bool) {
	if flag, ok := context.AmfReInitAvailableList.Load(sctpAddr); ok {
		return flag.(bool), true
	}
	return true, false
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
	if securityAssociation, ok := context.IkeSA.Load(spi); ok {
		return securityAssociation.(*IKESecurityAssociation), true
	}
	return nil, false
}

func (context *N3IWFContext) DeleteGTPConnection(upfAddr string) {
	context.GtpConnectionUPF.Delete(upfAddr)
}

func (context *N3IWFContext) GTPConnectionWithUPFLoad(upfAddr string) (*gtpv1.UPlaneConn, bool) {
	if conn, ok := context.GtpConnectionUPF.Load(upfAddr); ok {
		return conn.(*gtpv1.UPlaneConn), true
	}
	return nil, false
}

func (context *N3IWFContext) GTPConnectionWithUPFStore(upfAddr string, conn *gtpv1.UPlaneConn) {
	context.GtpConnectionUPF.Store(upfAddr, conn)
}

func (context *N3IWFContext) NewInternalUEIPAddr(ikeUe *N3IWFIkeUe) net.IP {
	var ueIPAddr net.IP

	// TODO: Check number of allocated IP to detect running out of IPs
	for {
		ueIPAddr = generateRandomIPinRange(context.Subnet)
		if ueIPAddr != nil {
			if ueIPAddr.String() == context.IpSecGatewayAddress {
				continue
			}
			if _, ok := context.AllocatedUeIpAddress.LoadOrStore(ueIPAddr.String(), ikeUe); !ok {
				break
			}
		}
	}

	return ueIPAddr
}

func (context *N3IWFContext) DeleteInternalUEIPAddr(ipAddr string) {
	context.AllocatedUeIpAddress.Delete(ipAddr)
}

func (context *N3IWFContext) NewTEID(ranUe *N3IWFRanUe) uint32 {
	teid64, err := context.TeidGenerator.Allocate()
	if err != nil {
		logger.ContextLog.Errorf("new TEID failed: %+v", err)
		return 0
	}
	teid32 := uint32(teid64)

	context.AllocatedUeTeid.Store(teid32, ranUe)

	return teid32
}

func (context *N3IWFContext) DeleteTEID(teid uint32) {
	context.TeidGenerator.FreeID(int64(teid))
	context.AllocatedUeTeid.Delete(teid)
}

func (context *N3IWFContext) AMFSelection(ueSpecifiedGUAMI *ngapType.GUAMI,
	ueSpecifiedPLMNId *ngapType.PLMNIdentity,
) *N3IWFAMF {
	var availableAMF *N3IWFAMF
	context.AmfPool.Range(func(key, value any) bool {
		amf := value.(*N3IWFAMF)
		if amf.FindAvailableAMFByCompareGUAMI(ueSpecifiedGUAMI) {
			availableAMF = amf
			return false
		}
		// Fail to find through GUAMI served by UE. Try again using SelectedPLMNId
		if amf.FindAvalibleAMFByCompareSelectedPLMNId(ueSpecifiedPLMNId) {
			availableAMF = amf
			return false
		}
		return true
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

	// Iterate over a fixed range using a helper function
	for i := range randomNumber {
		alter := randomNumber[i] & (subnet.Mask[i] ^ 255)
		ipAddr[i] = subnet.IP[i] + alter
	}

	return net.IPv4(ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3])
}
