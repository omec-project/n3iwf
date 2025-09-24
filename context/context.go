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
	"github.com/wmnsk/go-gtp/gtpv1"
	"golang.org/x/net/ipv4"
)

// Global N3IWF context instance
var n3iwfContext N3IWFContext

// N3IWFContext holds all state and configuration for the N3IWF node
// Pools use sync.Map for concurrent access
// Comments added for clarity
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
	AllocatedUeTeid        sync.Map // map[uint32]*RanUe, TEID as key
	IkeUePool              sync.Map // map[uint64]*N3IWFIkeUe, SPI as key
	RanUePool              sync.Map // map[int64]*RanUe, RanUeNgapID as key
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
	GreConn             *ipv4.PacketConn
	GtpuConn            *gtpv1.UPlaneConn

	Ctx context.Context
	Wg  sync.WaitGroup

	NgapServer *NgapServer
	IkeServer  *IkeServer
}

func init() {
	// Initialize ID generators
	n3iwfContext.RanUuNgapIdGenerator = idgenerator.NewGenerator(0, math.MaxInt64)
	n3iwfContext.TeidGenerator = idgenerator.NewGenerator(1, math.MaxUint32)
}

// N3IWFSelf returns the singleton N3IWF context
func N3IWFSelf() *N3IWFContext {
	return &n3iwfContext
}

// NewN3iwfIkeUe creates and stores a new N3IWFIkeUe for the given SPI
func (n3iwfCtx *N3IWFContext) NewN3iwfIkeUe(spi uint64) *N3IWFIkeUe {
	n3iwfIkeUe := &N3IWFIkeUe{N3iwfCtx: n3iwfCtx}
	n3iwfIkeUe.init()
	n3iwfCtx.IkeUePool.Store(spi, n3iwfIkeUe)
	return n3iwfIkeUe
}

// NewN3iwfRanUe allocates a new RanUeNgapId and creates a N3IWFRanUe
func (n3iwfCtx *N3IWFContext) NewN3iwfRanUe() *N3IWFRanUe {
	ranUeNgapId, err := n3iwfCtx.RanUuNgapIdGenerator.Allocate()
	if err != nil {
		logger.CtxLog.Errorf("new N3IWF UE failed: %+v", err)
		return nil
	}
	n3iwfRanUe := &N3IWFRanUe{
		RanUeSharedCtx: RanUeSharedCtx{N3iwfCtx: n3iwfCtx},
	}
	n3iwfRanUe.init(ranUeNgapId)
	n3iwfCtx.RanUePool.Store(ranUeNgapId, n3iwfRanUe)
	return n3iwfRanUe
}

// DeleteRanUe removes RanUe and its SPI mapping
func (n3iwfCtx *N3IWFContext) DeleteRanUe(ranUeNgapId int64) {
	n3iwfCtx.RanUePool.Delete(ranUeNgapId)
	n3iwfCtx.DeleteIkeSPIFromNgapId(ranUeNgapId)
}

// DeleteIKEUe removes IkeUe and its NgapId mapping
func (n3iwfCtx *N3IWFContext) DeleteIKEUe(spi uint64) {
	n3iwfCtx.IkeUePool.Delete(spi)
	n3iwfCtx.DeleteNgapIdFromIkeSPI(spi)
}

// IkeUePoolLoad returns IkeUe for SPI
func (n3iwfCtx *N3IWFContext) IkeUePoolLoad(spi uint64) (*N3IWFIkeUe, bool) {
	ikeUe, ok := n3iwfCtx.IkeUePool.Load(spi)
	if !ok {
		return nil, false
	}
	return ikeUe.(*N3IWFIkeUe), true
}

// RanUePoolLoad returns RanUe for id (int64 only)
func (n3iwfCtx *N3IWFContext) RanUePoolLoad(id any) (RanUe, bool) {
	idInt, ok := id.(int64)
	if !ok {
		logger.CfgLog.Warnf("RanUePoolLoad unhandled type: %T", id)
		return nil, false
	}
	ranUe, ok := n3iwfCtx.RanUePool.Load(idInt)
	if !ok {
		return nil, false
	}
	return ranUe.(RanUe), true
}

// AllocatedUEIPAddressLoad returns IkeUe for IP address
func (n3iwfCtx *N3IWFContext) AllocatedUEIPAddressLoad(ipAddr string) (*N3IWFIkeUe, bool) {
	ikeUe, ok := n3iwfCtx.AllocatedUeIpAddress.Load(ipAddr)
	if !ok {
		return nil, false
	}
	return ikeUe.(*N3IWFIkeUe), true
}

// AllocatedUETEIDLoad returns RanUe for TEID
func (n3iwfCtx *N3IWFContext) AllocatedUETEIDLoad(teid uint32) (RanUe, bool) {
	ranUe, ok := n3iwfCtx.AllocatedUeTeid.Load(teid)
	if !ok {
		return nil, false
	}
	return ranUe.(RanUe), true
}

// IkeSpiNgapIdMapping stores mapping between SPI and RanUeNgapId
func (n3iwfCtx *N3IWFContext) IkeSpiNgapIdMapping(spi uint64, ranUeNgapId int64) {
	n3iwfCtx.IkeSpiToNgapId.Store(spi, ranUeNgapId)
	n3iwfCtx.NgapIdToIkeSpi.Store(ranUeNgapId, spi)
}

// IkeSpiLoad returns SPI for RanUeNgapId
func (n3iwfCtx *N3IWFContext) IkeSpiLoad(ranUeNgapId int64) (uint64, bool) {
	spi, ok := n3iwfCtx.NgapIdToIkeSpi.Load(ranUeNgapId)
	if !ok {
		return 0, false
	}
	return spi.(uint64), true
}

// NgapIdLoad returns RanUeNgapId for SPI
func (n3iwfCtx *N3IWFContext) NgapIdLoad(spi uint64) (int64, bool) {
	ranNgapId, ok := n3iwfCtx.IkeSpiToNgapId.Load(spi)
	if !ok {
		return 0, false
	}
	return ranNgapId.(int64), true
}

// DeleteNgapIdFromIkeSPI removes NgapId mapping for SPI
func (n3iwfCtx *N3IWFContext) DeleteNgapIdFromIkeSPI(spi uint64) {
	n3iwfCtx.IkeSpiToNgapId.Delete(spi)
}

// DeleteIkeSPIFromNgapId removes SPI mapping for NgapId
func (n3iwfCtx *N3IWFContext) DeleteIkeSPIFromNgapId(ranUeNgapId int64) {
	n3iwfCtx.NgapIdToIkeSpi.Delete(ranUeNgapId)
}

// RanUeLoadFromIkeSPI returns RanUe for SPI
func (n3iwfCtx *N3IWFContext) RanUeLoadFromIkeSPI(spi uint64) (RanUe, error) {
	ranNgapId, ok := n3iwfCtx.IkeSpiToNgapId.Load(spi)
	if !ok {
		return nil, fmt.Errorf("cannot find RanNgapId from IkeUe SPI: %+v", spi)
	}
	ranUe, found := n3iwfCtx.RanUePoolLoad(ranNgapId.(int64))
	if !found {
		return nil, fmt.Errorf("cannot find RanUE from RanNgapId: %+v", ranNgapId)
	}
	return ranUe, nil
}

// IkeUeLoadFromNgapId returns IkeUe for RanUeNgapId
func (n3iwfCtx *N3IWFContext) IkeUeLoadFromNgapId(ranUeNgapId int64) (*N3IWFIkeUe, error) {
	spi, ok := n3iwfCtx.NgapIdToIkeSpi.Load(ranUeNgapId)
	if !ok {
		return nil, fmt.Errorf("cannot find SPI from NgapId: %d", ranUeNgapId)
	}
	ikeUe, found := n3iwfCtx.IkeUePoolLoad(spi.(uint64))
	if !found {
		return nil, fmt.Errorf("cannot find IkeUe from spi: %+v", spi)
	}
	return ikeUe, nil
}

// NewN3iwfAmf creates and stores a new N3IWFAMF for the given SCTP address
func (n3iwfCtx *N3IWFContext) NewN3iwfAmf(sctpAddr string, conn *sctp.SCTPConn) *N3IWFAMF {
	amf := new(N3IWFAMF)
	amf.init(sctpAddr, conn)
	item, loaded := n3iwfCtx.AmfPool.LoadOrStore(sctpAddr, amf)
	if loaded {
		logger.CtxLog.Warnln("AMF entry already exists")
		return item.(*N3IWFAMF)
	}
	return amf
}

// DeleteN3iwfAmf removes AMF for SCTP address
func (n3iwfCtx *N3IWFContext) DeleteN3iwfAmf(sctpAddr string) {
	n3iwfCtx.AmfPool.Delete(sctpAddr)
}

// AMFPoolLoad returns AMF for SCTP address
func (n3iwfCtx *N3IWFContext) AMFPoolLoad(sctpAddr string) (*N3IWFAMF, bool) {
	amf, ok := n3iwfCtx.AmfPool.Load(sctpAddr)
	if !ok {
		return nil, false
	}
	return amf.(*N3IWFAMF), true
}

// DeleteAMFReInitAvailableFlag removes re-init flag for SCTP address
func (n3iwfCtx *N3IWFContext) DeleteAMFReInitAvailableFlag(sctpAddr string) {
	n3iwfCtx.AmfReInitAvailableList.Delete(sctpAddr)
}

// AMFReInitAvailableListLoad returns re-init flag for SCTP address
func (n3iwfCtx *N3IWFContext) AMFReInitAvailableListLoad(sctpAddr string) (bool, bool) {
	flag, ok := n3iwfCtx.AmfReInitAvailableList.Load(sctpAddr)
	if !ok {
		return true, false
	}
	return flag.(bool), true
}

// AMFReInitAvailableListStore sets re-init flag for SCTP address
func (n3iwfCtx *N3IWFContext) AMFReInitAvailableListStore(sctpAddr string, flag bool) {
	n3iwfCtx.AmfReInitAvailableList.Store(sctpAddr, flag)
}

// NewIKESecurityAssociation creates and stores a new IKE Security Association with a unique SPI
func (n3iwfCtx *N3IWFContext) NewIKESecurityAssociation() *IKESecurityAssociation {
	ikeSecurityAssociation := new(IKESecurityAssociation)
	maxSPI := new(big.Int).SetUint64(math.MaxUint64)
	for {
		localSPI, err := rand.Int(rand.Reader, maxSPI)
		if err != nil {
			logger.CtxLog.Errorln("error occurs when generate new IKE SPI")
			return nil
		}
		localSPIuint64 := localSPI.Uint64()
		if _, duplicate := n3iwfCtx.IkeSA.LoadOrStore(localSPIuint64, ikeSecurityAssociation); !duplicate {
			ikeSecurityAssociation.LocalSPI = localSPIuint64
			break
		}
	}
	return ikeSecurityAssociation
}

// DeleteIKESecurityAssociation removes IKE SA for SPI
func (n3iwfCtx *N3IWFContext) DeleteIKESecurityAssociation(spi uint64) {
	n3iwfCtx.IkeSA.Delete(spi)
}

// IKESALoad returns IKE SA for SPI
func (n3iwfCtx *N3IWFContext) IKESALoad(spi uint64) (*IKESecurityAssociation, bool) {
	securityAssociation, ok := n3iwfCtx.IkeSA.Load(spi)
	if !ok {
		return nil, false
	}
	return securityAssociation.(*IKESecurityAssociation), true
}

// DeleteGTPConnection removes GTP connection for UPF address
func (n3iwfCtx *N3IWFContext) DeleteGTPConnection(upfAddr string) {
	n3iwfCtx.GtpConnectionUPF.Delete(upfAddr)
}

// GTPConnectionWithUPFLoad returns GTP connection for UPF address
func (n3iwfCtx *N3IWFContext) GTPConnectionWithUPFLoad(upfAddr string) (*gtpv1.UPlaneConn, bool) {
	conn, ok := n3iwfCtx.GtpConnectionUPF.Load(upfAddr)
	if !ok {
		return nil, false
	}
	return conn.(*gtpv1.UPlaneConn), true
}

// GTPConnectionWithUPFStore stores GTP connection for UPF address
func (n3iwfCtx *N3IWFContext) GTPConnectionWithUPFStore(upfAddr string, conn *gtpv1.UPlaneConn) {
	n3iwfCtx.GtpConnectionUPF.Store(upfAddr, conn)
}

// NewInternalUEIPAddr generates a new unique internal UE IP address within the subnet
func (n3iwfCtx *N3IWFContext) NewInternalUEIPAddr(ikeUe *N3IWFIkeUe) net.IP {
	for {
		ueIPAddr := generateRandomIPinRange(n3iwfCtx.Subnet)
		if ueIPAddr == nil {
			continue
		}
		if ueIPAddr.String() == n3iwfCtx.IpSecGatewayAddress {
			continue
		}
		if _, ok := n3iwfCtx.AllocatedUeIpAddress.LoadOrStore(ueIPAddr.String(), ikeUe); !ok {
			return ueIPAddr
		}
		logger.CtxLog.Warnf("IP(%v) is used by other IkeUE", ueIPAddr.String())
	}
}

// DeleteInternalUEIPAddr removes allocated UE IP address
func (n3iwfCtx *N3IWFContext) DeleteInternalUEIPAddr(ipAddr string) {
	n3iwfCtx.AllocatedUeIpAddress.Delete(ipAddr)
}

// NewTEID allocates a new TEID and stores mapping to RanUe
func (n3iwfCtx *N3IWFContext) NewTEID(ranUe RanUe) uint32 {
	teid64, err := n3iwfCtx.TeidGenerator.Allocate()
	if err != nil {
		logger.CtxLog.Errorf("new TEID failed: %+v", err)
		return 0
	}
	if teid64 < 0 || teid64 > math.MaxUint32 {
		logger.CtxLog.Warnf("new TEID teid64 out of uint32 range: %d, use maxUint32", teid64)
		return 0
	}
	teid32 := uint32(teid64)
	n3iwfCtx.AllocatedUeTeid.Store(teid32, ranUe)
	return teid32
}

// DeleteTEID removes TEID and frees its ID
func (n3iwfCtx *N3IWFContext) DeleteTEID(teid uint32) {
	n3iwfCtx.TeidGenerator.FreeID(int64(teid))
	n3iwfCtx.AllocatedUeTeid.Delete(teid)
}

// AMFSelection selects an available AMF based on GUAMI or PLMNId
func (n3iwfCtx *N3IWFContext) AMFSelection(ueSpecifiedGUAMI *ngapType.GUAMI, ueSpecifiedPLMNId *ngapType.PLMNIdentity) *N3IWFAMF {
	var availableAMF, defaultAMF *N3IWFAMF
	n3iwfCtx.AmfPool.Range(func(_, value any) bool {
		amf := value.(*N3IWFAMF)
		if defaultAMF == nil {
			defaultAMF = amf
		}
		if amf.FindAvailableAMFByCompareGUAMI(ueSpecifiedGUAMI) {
			availableAMF = amf
			return false
		}
		if amf.FindAvailableAMFByCompareSelectedPLMNId(ueSpecifiedPLMNId) {
			availableAMF = amf
			return false
		}
		return true
	})
	if availableAMF == nil && defaultAMF != nil {
		availableAMF = defaultAMF
	}
	return availableAMF
}

// generateRandomIPinRange returns a random IP within the given subnet
func generateRandomIPinRange(subnet *net.IPNet) net.IP {
	ipAddr := make([]byte, 4)
	randomNumber := make([]byte, 4)
	if _, err := rand.Read(randomNumber); err != nil {
		logger.CtxLog.Errorf("generate random number for IP address failed: %+v", err)
		return nil
	}
	for i := range randomNumber {
		ipAddr[i] = subnet.IP[i] + (randomNumber[i] & ^subnet.Mask[i])
	}
	return net.IPv4(ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3])
}
