// SPDX-FileCopyrightText: 2025 Intel Corporation
// Copyright 2021 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"fmt"
	"math"
	"net"

	"github.com/omec-project/n3iwf/ike/message"
	"github.com/omec-project/n3iwf/ike/security"
	"github.com/vishvananda/netlink"
)

const AmfUeNgapIdUnspecified int64 = 0xffffffffff

// N3IWFIkeUe represents a UE context in N3IWF
// Contains IKE and Child SA, identity, and connection info
type N3IWFIkeUe struct {
	N3iwfCtx *N3IWFContext

	// UE identity
	IPSecInnerIP     net.IP
	IPSecInnerIPAddr *net.IPAddr // Used to send UP packets to UE

	// IKE Security Association
	N3IWFIKESecurityAssociation   *IKESecurityAssociation
	N3IWFChildSecurityAssociation map[uint32]*ChildSecurityAssociation // inbound SPI as key

	// Temporary Mapping of two SPIs
	// Exchange Message ID(including a SPI) and ChildSA(including a SPI)
	// Mapping of Message ID of exchange in IKE and Child SA when creating new child SA
	TemporaryExchangeMsgIDChildSAMapping map[uint32]*ChildSecurityAssociation // Message ID as a key

	// Security
	Kn3iwf []uint8 // 32 bytes (256 bits), value is from NGAP IE "Security Key"

	// NAS IKE Connection
	IKEConnection *UDPSocketInfo

	// Length of PDU Session List
	PduSessionListLen int
}

type IkeMsgTemporaryData struct {
	SecurityAssociation      *message.SecurityAssociation
	TrafficSelectorInitiator *message.TrafficSelectorInitiator
	TrafficSelectorResponder *message.TrafficSelectorResponder
}

type IKESecurityAssociation struct {
	*security.IKESAKey
	// SPI
	RemoteSPI uint64
	LocalSPI  uint64

	// Message ID
	InitiatorMessageID uint32
	ResponderMessageID uint32

	// Used for key generating
	ConcatenatedNonce []byte

	// State for IKE_AUTH
	State uint8

	// Temporary data stored for the use in later exchange
	InitiatorID              *message.IdentificationInitiator
	InitiatorCertificate     *message.Certificate
	IKEAuthResponseSA        *message.SecurityAssociation
	TrafficSelectorInitiator *message.TrafficSelectorInitiator
	TrafficSelectorResponder *message.TrafficSelectorResponder
	LastEAPIdentifier        uint8

	// UDP Connection
	IKEConnection *UDPSocketInfo

	// Authentication data
	ResponderSignedOctets []byte
	InitiatorSignedOctets []byte

	// NAT detection
	UeBehindNAT    bool // If true, N3IWF should enable NAT traversal and
	N3iwfBehindNAT bool // TODO: If true, N3IWF should send UDP keepalive periodically

	// IKE UE context
	IkeUE *N3IWFIkeUe

	// Temporary store the receive ike message
	TemporaryIkeMsg *IkeMsgTemporaryData

	DPDReqRetransTimer *Timer // The time from sending the DPD request to receiving the response
	CurrentRetryTimes  int32  // Accumulate the number of times the DPD response wasn't received
	IKESAClosedCh      chan struct{}
	IsUseDPD           bool
}

func (ikeSA *IKESecurityAssociation) String() string {
	return "====== IKE Security Association Info =====" +
		"\nInitiator's SPI: " + fmt.Sprintf("%016x", ikeSA.RemoteSPI) +
		"\nResponder's SPI: " + fmt.Sprintf("%016x", ikeSA.LocalSPI) +
		"\nIKESAKey: " + ikeSA.IKESAKey.String()
}

// Temporary State Data Args
const (
	ArgsUEUDPConn string = "UE UDP Socket Info"
)

type ChildSecurityAssociation struct {
	// SPI
	InboundSPI  uint32 // N3IWF Specify
	OutboundSPI uint32 // Non-3GPP UE Specify

	// Associated XFRM interface
	XfrmIface netlink.Link

	XfrmStateList  []netlink.XfrmState
	XfrmPolicyList []netlink.XfrmPolicy

	// IP address
	PeerPublicIPAddr  net.IP
	LocalPublicIPAddr net.IP

	// Traffic selector
	SelectedIPProtocol    uint8
	TrafficSelectorLocal  net.IPNet
	TrafficSelectorRemote net.IPNet

	// Security
	*security.ChildSAKey

	// Encapsulate
	EnableEncapsulate bool
	N3IWFPort         int
	NATPort           int

	// PDU Session IDs associated with this child SA
	PDUSessionIds []int64

	// IKE UE context
	IkeUE *N3IWFIkeUe

	LocalIsInitiator bool
}

func (childSA *ChildSecurityAssociation) String(xfrmiId uint32) string {
	var inboundEncryptionKey, inboundIntegrityKey, outboundEncryptionKey, outboundIntegrityKey []byte

	if childSA.LocalIsInitiator {
		inboundEncryptionKey = childSA.ResponderToInitiatorEncryptionKey
		inboundIntegrityKey = childSA.ResponderToInitiatorIntegrityKey
		outboundEncryptionKey = childSA.InitiatorToResponderEncryptionKey
		outboundIntegrityKey = childSA.InitiatorToResponderIntegrityKey
	} else {
		inboundEncryptionKey = childSA.InitiatorToResponderEncryptionKey
		inboundIntegrityKey = childSA.InitiatorToResponderIntegrityKey
		outboundEncryptionKey = childSA.ResponderToInitiatorEncryptionKey
		outboundIntegrityKey = childSA.ResponderToInitiatorIntegrityKey
	}

	return fmt.Sprintf("====== IPSec/Child SA Info ======"+
		"\n====== Inbound ======"+
		"\nXFRM interface if_id: %d"+
		"\nIPSec Inbound  SPI: 0x%08x"+
		"\n[UE:%+v] -> [N3IWF:%+v]"+
		"\nIPSec Encryption Algorithm: %d"+
		"\nIPSec Encryption Key: 0x%x"+
		"\nIPSec Integrity  Algorithm: %d"+
		"\nIPSec Integrity  Key: 0x%x"+
		"\n====== IPSec/Child SA Info ======"+
		"\n====== Outbound ======"+
		"\nXFRM interface if_id: %d"+
		"\nIPSec Outbound  SPI: 0x%08x"+
		"\n[N3IWF:%+v] -> [UE:%+v]"+
		"\nIPSec Encryption Algorithm: %d"+
		"\nIPSec Encryption Key: 0x%x"+
		"\nIPSec Integrity  Algorithm: %d"+
		"\nIPSec Integrity  Key: 0x%x",
		xfrmiId,
		childSA.InboundSPI,
		childSA.PeerPublicIPAddr,
		childSA.LocalPublicIPAddr,
		childSA.EncrKInfo.TransformID(),
		inboundEncryptionKey,
		childSA.IntegKInfo.TransformID(),
		inboundIntegrityKey,
		xfrmiId,
		childSA.OutboundSPI,
		childSA.LocalPublicIPAddr,
		childSA.PeerPublicIPAddr,
		childSA.EncrKInfo.TransformID(),
		outboundEncryptionKey,
		childSA.IntegKInfo.TransformID(),
		outboundIntegrityKey,
	)
}

// UDPSocketInfo holds UDP connection info for IKE
type UDPSocketInfo struct {
	Conn      *net.UDPConn
	N3IWFAddr *net.UDPAddr
	UEAddr    *net.UDPAddr
}

// init initializes the N3IWFIkeUe context
func (ikeUe *N3IWFIkeUe) init() {
	ikeUe.N3IWFChildSecurityAssociation = make(map[uint32]*ChildSecurityAssociation)
	ikeUe.TemporaryExchangeMsgIDChildSAMapping = make(map[uint32]*ChildSecurityAssociation)
}

// Remove cleans up the UE context and associated SAs
func (ikeUe *N3IWFIkeUe) Remove() error {
	if ikeUe.N3IWFIKESecurityAssociation.IsUseDPD {
		select {
		case ikeUe.N3IWFIKESecurityAssociation.IKESAClosedCh <- struct{}{}:
		default:
		}
	}

	n3iwfCtx := ikeUe.N3iwfCtx
	n3iwfCtx.DeleteIKESecurityAssociation(ikeUe.N3IWFIKESecurityAssociation.LocalSPI)
	n3iwfCtx.DeleteInternalUEIPAddr(ikeUe.IPSecInnerIP.String())

	for _, childSA := range ikeUe.N3IWFChildSecurityAssociation {
		if err := ikeUe.DeleteChildSA(childSA); err != nil {
			return err
		}
	}
	n3iwfCtx.DeleteIKEUe(ikeUe.N3IWFIKESecurityAssociation.LocalSPI)

	return nil
}

// DeleteChildSAXfrm deletes XFRM state, policy, and interface for a Child SA
func (ikeUe *N3IWFIkeUe) DeleteChildSAXfrm(childSA *ChildSecurityAssociation) error {
	n3iwfCtx := ikeUe.N3iwfCtx
	iface := childSA.XfrmIface

	// Delete child SA xfrmState
	for _, xfrmState := range childSA.XfrmStateList {
		if err := netlink.XfrmStateDel(&xfrmState); err != nil {
			return fmt.Errorf("delete xfrmstate: %w", err)
		}
	}
	// Delete child SA xfrmPolicy
	for _, xfrmPolicy := range childSA.XfrmPolicyList {
		if err := netlink.XfrmPolicyDel(&xfrmPolicy); err != nil {
			return fmt.Errorf("delete xfrmPolicy: %w", err)
		}
	}

	if iface != nil && iface.Attrs().Name != "xfrmi-default" {
		if err := netlink.LinkDel(iface); err != nil {
			return fmt.Errorf("delete interface[%s]: %w", iface.Attrs().Name, err)
		}
		ifId := childSA.XfrmStateList[0].Ifid
		if ifId < 0 || ifId > math.MaxUint32 {
			return fmt.Errorf("ifid is out of uint32 range value: %d", ifId)
		}
		n3iwfCtx.XfrmIfaces.Delete(uint32(ifId))
	}

	childSA.XfrmStateList = nil
	childSA.XfrmPolicyList = nil

	return nil
}

// DeleteChildSA deletes a Child SA and its XFRM resources
func (ikeUe *N3IWFIkeUe) DeleteChildSA(childSA *ChildSecurityAssociation) error {
	if err := ikeUe.DeleteChildSAXfrm(childSA); err != nil {
		return err
	}
	delete(ikeUe.N3IWFChildSecurityAssociation, childSA.InboundSPI)
	return nil
}

// CreateHalfChildSA creates a half Child SA for a CREATE_CHILD_SA request
func (ikeUe *N3IWFIkeUe) CreateHalfChildSA(msgID, inboundSPI uint32, pduSessionID int64) {
	childSA := &ChildSecurityAssociation{
		InboundSPI:    inboundSPI,
		PDUSessionIds: []int64{pduSessionID},
		IkeUE:         ikeUe,
	}
	ikeUe.TemporaryExchangeMsgIDChildSAMapping[msgID] = childSA
}

// CompleteChildSA finalizes a Child SA after receiving a response
func (ikeUe *N3IWFIkeUe) CompleteChildSA(msgID uint32, outboundSPI uint32,
	chosenSecurityAssociation *message.SecurityAssociation,
) (*ChildSecurityAssociation, error) {
	childSA, ok := ikeUe.TemporaryExchangeMsgIDChildSAMapping[msgID]
	if !ok {
		return nil, fmt.Errorf("no half child SA for exchange message ID %d", msgID)
	}
	delete(ikeUe.TemporaryExchangeMsgIDChildSAMapping, msgID)

	if chosenSecurityAssociation == nil {
		return nil, fmt.Errorf("chosenSecurityAssociation is nil")
	}
	if len(chosenSecurityAssociation.Proposals) == 0 {
		return nil, fmt.Errorf("no proposal")
	}

	childSA.OutboundSPI = outboundSPI
	var err error
	childSA.ChildSAKey, err = security.NewChildSAKeyByProposal(chosenSecurityAssociation.Proposals[0])
	if err != nil {
		return nil, fmt.Errorf("CompleteChildSA: %w", err)
	}

	ikeUe.N3IWFChildSecurityAssociation[childSA.InboundSPI] = childSA
	ikeUe.N3iwfCtx.ChildSA.Store(childSA.InboundSPI, childSA)

	return childSA, nil
}
