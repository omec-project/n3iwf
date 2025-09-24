// SPDX-FileCopyrightText: 2025 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"net"

	"github.com/omec-project/n3iwf/context"
	greMsg "github.com/omec-project/n3iwf/gre/message"
	gtpMsg "github.com/omec-project/n3iwf/gtp/message"
	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/n3iwf/util"
	"github.com/wmnsk/go-gtp/gtpv1"
	gtpv1Msg "github.com/wmnsk/go-gtp/gtpv1/message"
	"golang.org/x/net/ipv4"
)

// HandleQoSTPDU parses unsupported fields and forwards data to UE.
func HandleQoSTPDU(n3iwfCtx *context.N3IWFContext, c gtpv1.Conn, senderAddr net.Addr, msg gtpv1Msg.Message) error {
	pdu := gtpMsg.QoSTPDUPacket{}
	if err := pdu.Unmarshal(msg.(*gtpv1Msg.TPDU)); err != nil {
		return err
	}
	forwardDL(n3iwfCtx, pdu)
	return nil
}

// forwardDL forwards user plane packets from N3 to UE with GRE and new IP header encapsulation.
func forwardDL(n3iwfCtx *context.N3IWFContext, packet gtpMsg.QoSTPDUPacket) {
	defer util.RecoverWithLog(logger.GTPLog)

	pktTEID := packet.GetTEID()
	logger.GTPLog.Debugf("pkt teid: %d", pktTEID)

	ranUe, ok := n3iwfCtx.AllocatedUETEIDLoad(pktTEID)
	if !ok {
		logger.GTPLog.Errorf("cannot find RanUE context from QosPacket TEID: %+v", pktTEID)
		return
	}
	ranUeNgapId := ranUe.GetSharedCtx().RanUeNgapId

	ikeUe, err := n3iwfCtx.IkeUeLoadFromNgapId(ranUeNgapId)
	if err != nil {
		logger.GTPLog.Errorf("cannot find IkeUe context from RanUe, NgapId: %+v", ranUeNgapId)
		return
	}

	ueInnerIPAddr := ikeUe.IPSecInnerIPAddr
	var cm *ipv4.ControlMessage

	// Find matching ChildSA for TEID
	for _, childSA := range ikeUe.N3IWFChildSecurityAssociation {
		if len(childSA.PDUSessionIds) == 0 {
			continue
		}
		pduSession := ranUe.FindPDUSession(childSA.PDUSessionIds[0])
		if pduSession != nil && pduSession.GTPConnection.IncomingTEID == pktTEID {
			cm = &ipv4.ControlMessage{IfIndex: childSA.XfrmIface.Attrs().Index}
			logger.GTPLog.Debugf("forwarding IPSec xfrm interfaceid: %d", childSA.XfrmIface.Attrs().Index)
			break
		}
	}
	if cm == nil {
		logger.GTPLog.Warnf("cannot match TEID(%d) to ChildSA", pktTEID)
		return
	}

	var qfi uint8
	var rqi bool
	if packet.HasQoS() {
		qfi, rqi = packet.GetQoSParameters()
		logger.GTPLog.Debugf("QFI: %v, RQI: %v", qfi, rqi)
	}

	grePacket := greMsg.GREPacket{}
	grePacket.SetPayload(packet.GetPayload(), greMsg.IPv4)
	grePacket.SetQoS(qfi, rqi)
	forwardData := grePacket.Marshal()

	n, err := n3iwfCtx.GreConn.WriteTo(forwardData, cm, ueInnerIPAddr)
	if err != nil {
		logger.GTPLog.Errorf("write to UE failed: %+v", err)
		return
	}
	logger.GTPLog.Debugln("forward NWu <- N3")
	logger.GTPLog.Debugf("wrote %d bytes", n)
}

// ForwardUL forwards user plane packets from NWu to UPF with GTP header encapsulation.
func ForwardUL(n3iwfCtx *context.N3IWFContext, ueInnerIP string, ifIndex int, rawData []byte) {
	defer util.RecoverWithLog(logger.NWuUPLog)

	ikeUe, ok := n3iwfCtx.AllocatedUEIPAddressLoad(ueInnerIP)
	if !ok {
		logger.NWuUPLog.Errorln("Ike UE context not found")
		return
	}

	ranUe, err := n3iwfCtx.RanUeLoadFromIkeSPI(ikeUe.N3IWFIKESecurityAssociation.LocalSPI)
	if err != nil {
		logger.NWuUPLog.Errorln("ranUe not found")
		return
	}

	var pduSession *context.PDUSession
	for _, childSA := range ikeUe.N3IWFChildSecurityAssociation {
		if childSA.XfrmIface != nil && childSA.XfrmIface.Attrs().Index == ifIndex && len(childSA.PDUSessionIds) > 0 {
			pduSession = ranUe.GetSharedCtx().PduSessionList[childSA.PDUSessionIds[0]]
			break
		}
	}
	if pduSession == nil {
		logger.NWuUPLog.Errorln("this UE does not have any available PDU session")
		return
	}

	gtpConnection := pduSession.GTPConnection

	// Decapsulate GRE header and extract QoS Parameters if exist
	grePacket := greMsg.GREPacket{}
	if err := grePacket.Unmarshal(rawData); err != nil {
		logger.NWuUPLog.Errorf("gre Unmarshal err: %+v", err)
		return
	}

	payload, _ := grePacket.GetPayload()

	// Encapsulate UL PDU SESSION INFORMATION with extension header if the QoS parameters exist
	if grePacket.GetKeyFlag() {
		gtpPacket, err := gtpMsg.BuildQoSGTPPacket(gtpConnection.OutgoingTEID, grePacket.GetQFI(), payload)
		if err != nil {
			logger.NWuUPLog.Errorf("buildQoSGTPPacket err: %+v", err)
			return
		}
		n, writeErr := n3iwfCtx.GtpuConn.WriteTo(gtpPacket, gtpConnection.UPFUDPAddr)
		if writeErr != nil {
			logGTPWriteError(writeErr)
			return
		}
		logger.NWuUPLog.Debugln("forward NWu -> N3")
		logger.NWuUPLog.Debugf("wrote %d bytes", n)
		return
	}

	logger.NWuUPLog.Warnln("receive GRE header without key field specifying QFI and RQI.")
	n, writeErr := n3iwfCtx.GtpuConn.WriteToGTP(gtpConnection.OutgoingTEID, payload, gtpConnection.UPFUDPAddr)
	if writeErr != nil {
		logGTPWriteError(writeErr)
		return
	}
	logger.NWuUPLog.Debugln("forward NWu -> N3")
	logger.NWuUPLog.Debugf("wrote %d bytes", n)
}

// logGTPWriteError logs GTP write errors and handles closed connection.
func logGTPWriteError(err error) {
	logger.NWuUPLog.Errorf("write to UPF failed: %+v", err)
	if err == gtpv1.ErrConnNotOpened {
		logger.NWuUPLog.Errorln("the connection has been closed")
	}
}
