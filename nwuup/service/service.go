// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"errors"
	"net"
	"runtime/debug"
	"sync"

	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/gre"
	gtpQoSMsg "github.com/omec-project/n3iwf/gtp/message"
	"github.com/omec-project/n3iwf/logger"
	gtpv1 "github.com/wmnsk/go-gtp/gtpv1"
	gtpMsg "github.com/wmnsk/go-gtp/gtpv1/message"
	"golang.org/x/net/ipv4"
)

// Run bind and listen IPv4 packet connection on N3IWF NWu interface with
// UP_IP_ADDRESS, catching GRE encapsulated packets and forward to N3 interface.
func Run(wg *sync.WaitGroup) error {
	// Local IPSec address
	n3iwfSelf := context.N3IWFSelf()
	listenAddr := n3iwfSelf.IpSecGatewayAddress

	// Setup IPv4 packet connection socket
	// This socket will only capture GRE encapsulated packet
	connection, err := net.ListenPacket("ip4:gre", listenAddr)
	if err != nil {
		logger.NWuUPLog.Errorf("error setting listen socket on %s: %+v", listenAddr, err)
		return errors.New("ListenPacket failed")
	}
	ipv4PacketConn := ipv4.NewPacketConn(connection)
	if ipv4PacketConn == nil {
		logger.NWuUPLog.Errorf("error opening IPv4 packet connection socket on %s", listenAddr)
		return errors.New("NewPacketConn failed")
	}

	n3iwfSelf.NWuIPv4PacketConn = ipv4PacketConn

	wg.Add(1)
	go listenAndServe(ipv4PacketConn, wg)

	return nil
}

// listenAndServe reads from socket and calls forward() to forward packets
func listenAndServe(ipv4PacketConn *ipv4.PacketConn, wg *sync.WaitGroup) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.NWuUPLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}

		err := ipv4PacketConn.Close()
		if err != nil {
			logger.NWuUPLog.Errorf("error closing raw socket: %+v", err)
		}
		wg.Done()
	}()

	buffer := make([]byte, 65535)

	if err := ipv4PacketConn.SetControlMessage(ipv4.FlagInterface|ipv4.FlagTTL, true); err != nil {
		logger.NWuUPLog.Errorf("set control message visibility for IPv4 packet connection fail: %+v", err)
		return
	}

	for {
		n, cm, src, err := ipv4PacketConn.ReadFrom(buffer)
		if err != nil {
			logger.NWuUPLog.Errorf("error read from IPv4 packet connection: %+v", err)
			return
		}

		forwardData := buffer[:n]
		wg.Add(1)
		go forward(src.String(), cm.IfIndex, forwardData, wg)
	}
}

// forward forwards user plane packets from NWu to UPF with GTP header
// encapsulated
func forward(ueInnerIP string, ifIndex int, rawData []byte, wg *sync.WaitGroup) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.NWuUPLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		wg.Done()
	}()

	self := context.N3IWFSelf()
	ikeUe, ok := self.AllocatedUEIPAddressLoad(ueInnerIP)
	if !ok {
		logger.NWuUPLog.Errorln("Ike UE context not found")
		return
	}

	ranUe, err := self.RanUeLoadFromIkeSPI(ikeUe.N3IWFIKESecurityAssociation.LocalSPI)
	if err != nil {
		logger.NWuUPLog.Errorln("ranUe not found")
		return
	}

	var pduSession *context.PDUSession

	for _, childSA := range ikeUe.N3IWFChildSecurityAssociation {
		if childSA.XfrmIface != nil && childSA.XfrmIface.Attrs().Index == ifIndex {
			if len(childSA.PDUSessionIds) > 0 {
				pduSession = ranUe.PduSessionList[childSA.PDUSessionIds[0]]
			}
			break
		}
	}
	if pduSession == nil {
		logger.NWuUPLog.Errorln("this UE does not have any available PDU session")
		return
	}

	gtpConnection := pduSession.GTPConnection

	userPlaneConnection := gtpConnection.UserPlaneConnection

	// Decapsulate GRE header and extract QoS Parameters if exist
	grePacket := gre.GREPacket{}
	if err := grePacket.Unmarshal(rawData); err != nil {
		logger.NWuUPLog.Errorf("gre Unmarshal err: %+v", err)
		return
	}

	var (
		n        int
		writeErr error
	)

	payload, _ := grePacket.GetPayload()

	// Encapsulate UL PDU SESSION INFORMATION with extension header if the QoS parameters exist
	if grePacket.GetKeyFlag() {
		qfi := grePacket.GetQFI()
		gtpPacket, err := buildQoSGTPPacket(gtpConnection.OutgoingTEID, qfi, payload)
		if err != nil {
			logger.NWuUPLog.Errorf("buildQoSGTPPacket err: %+v", err)
			return
		}

		n, writeErr = userPlaneConnection.WriteTo(gtpPacket, gtpConnection.UPFUDPAddr)
	} else {
		logger.NWuUPLog.Warnln("receive GRE header without key field specifying QFI and RQI.")
		n, writeErr = userPlaneConnection.WriteToGTP(gtpConnection.OutgoingTEID, payload, gtpConnection.UPFUDPAddr)
	}

	if writeErr != nil {
		logger.NWuUPLog.Errorf("write to UPF failed: %+v", writeErr)
		if writeErr == gtpv1.ErrConnNotOpened {
			logger.NWuUPLog.Errorln("the connection has been closed")
			// TODO: Release the GTP resource
		}
		return
	}

	logger.NWuUPLog.Debugln("forward NWu -> N3")
	logger.NWuUPLog.Debugf("wrote %d bytes", n)
}

func buildQoSGTPPacket(teid uint32, qfi uint8, payload []byte) ([]byte, error) {
	header := gtpMsg.NewHeader(0x34, gtpMsg.MsgTypeTPDU, teid, 0x00, payload).WithExtensionHeaders(
		gtpMsg.NewExtensionHeader(
			gtpMsg.ExtHeaderTypePDUSessionContainer,
			[]byte{gtpQoSMsg.UL_PDU_SESSION_INFORMATION_TYPE, qfi},
			gtpMsg.ExtHeaderTypeNoMoreExtensionHeaders,
		),
	)

	b := make([]byte, header.MarshalLen())

	if err := header.MarshalTo(b); err != nil {
		logger.NWuUPLog.Errorf("go-gtp MarshalTo err: %+v", err)
		return nil, err
	}

	return b, nil
}

func Stop(n3iwfContext *context.N3IWFContext) {
	logger.NWuUPLog.Infoln("close Nwuup server")

	if err := n3iwfContext.NWuIPv4PacketConn.Close(); err != nil {
		logger.NWuUPLog.Errorf("stop nwuup server error: %+v", err)
	}
}
