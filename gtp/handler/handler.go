// SPDX-FileCopyrightText: 2025 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"net"

	n3iwfContext "github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/gre"
	gtpQoSMsg "github.com/omec-project/n3iwf/gtp/message"
	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/n3iwf/util"
	gtp "github.com/wmnsk/go-gtp/gtpv1"
	gtpMsg "github.com/wmnsk/go-gtp/gtpv1/message"
	"golang.org/x/net/ipv4"
)

// Parse the fields not supported by go-gtp and forward data to UE.
func HandleQoSTPDU(c gtp.Conn, senderAddr net.Addr, msg gtpMsg.Message) error {
	pdu := gtpQoSMsg.QoSTPDUPacket{}
	if err := pdu.Unmarshal(msg.(*gtpMsg.TPDU)); err != nil {
		return err
	}

	forward(pdu)
	return nil
}

// Forward user plane packets from N3 to UE with GRE header and new IP header encapsulated
func forward(packet gtpQoSMsg.QoSTPDUPacket) {
	defer util.RecoverWithLog(logger.GTPLog)

	self := n3iwfContext.N3IWFSelf()
	NWuConn := self.NWuIPv4PacketConn
	pktTEID := packet.GetTEID()
	logger.GTPLog.Debugf("pkt teid: %d", pktTEID)

	ranUe, ok := self.AllocatedUETEIDLoad(pktTEID)
	if !ok {
		logger.GTPLog.Errorf("cannot find RanUE context from QosPacket TEID: %+v", pktTEID)
		return
	}

	ikeUe, err := self.IkeUeLoadFromNgapId(ranUe.RanUeNgapId)
	if err != nil {
		logger.GTPLog.Errorf("cannot find IkeUe context from RanUe, NgapID: %+v", ranUe.RanUeNgapId)
		return
	}

	ueInnerIPAddr := ikeUe.IPSecInnerIPAddr
	var cm *ipv4.ControlMessage

	for _, childSA := range ikeUe.N3IWFChildSecurityAssociation {
		if len(childSA.PDUSessionIds) == 0 {
			continue
		}
		pduSession := ranUe.FindPDUSession(childSA.PDUSessionIds[0])
		if pduSession != nil && pduSession.GTPConnection.IncomingTEID == pktTEID {
			logger.GTPLog.Debugf("forwarding IPSec xfrm interfaceid: %d", childSA.XfrmIface.Attrs().Index)
			cm = &ipv4.ControlMessage{IfIndex: childSA.XfrmIface.Attrs().Index}
			break
		}
	}

	var qfi uint8
	var rqi bool
	if packet.HasQoS() {
		qfi, rqi = packet.GetQoSParameters()
		logger.GTPLog.Debugf("QFI: %v, RQI: %v", qfi, rqi)
	}

	grePacket := gre.GREPacket{}
	grePacket.SetPayload(packet.GetPayload(), gre.IPv4)
	grePacket.SetQoS(qfi, rqi)
	forwardData := grePacket.Marshal()

	if n, err := NWuConn.WriteTo(forwardData, cm, ueInnerIPAddr); err != nil {
		logger.GTPLog.Errorf("write to UE failed: %+v", err)
		return
	} else {
		logger.GTPLog.Debugln("forward NWu <- N3")
		logger.GTPLog.Debugf("wrote %d bytes", n)
	}
}
