// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"errors"
	"net"

	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/logger"
	gtpv1 "github.com/wmnsk/go-gtp/v1"
	"golang.org/x/net/ipv4"
)

// Run bind and listen IPv4 packet connection on N3IWF NWu interface
// with UP_IP_ADDRESS, catching GRE encapsulated packets and forward
// to N3 interface.
func Run() error {
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
		logger.NWuUPLog.Errorf("error opening IPv4 packet connection socket on %s: %+v", listenAddr, err)
		return errors.New("NewPacketConn failed")
	}

	n3iwfSelf.NWuIPv4PacketConn = ipv4PacketConn
	go listenAndServe(ipv4PacketConn)

	return nil
}

// listenAndServe read from socket and call forward() to
// forward packet.
func listenAndServe(ipv4PacketConn *ipv4.PacketConn) {
	defer func() {
		err := ipv4PacketConn.Close()
		if err != nil {
			logger.NWuUPLog.Errorf("error closing raw socket: %+v", err)
		}
	}()

	buffer := make([]byte, 65535)

	for {
		n, _, src, err := ipv4PacketConn.ReadFrom(buffer)
		logger.NWuUPLog.Debugf("read %d bytes", n)
		if err != nil {
			logger.NWuUPLog.Errorf("error read from IPv4 Packet connection: %+v", err)
			return
		}

		forwardData := make([]byte, n-4)
		copy(forwardData, buffer[4:n])

		go forward(src.String(), forwardData)
	}
}

// forward forwards user plane packets from NWu to UPF
// with GTP header encapsulated
func forward(ueInnerIP string, packet []byte) {
	// Find UE information
	self := context.N3IWFSelf()
	ue, ok := self.AllocatedUEIPAddressLoad(ueInnerIP)
	if !ok {
		logger.NWuUPLog.Errorln("UE context not found")
		return
	}

	var pduSession *context.PDUSession

	for _, pduSession = range ue.PduSessionList {
		break
	}

	if pduSession == nil {
		logger.NWuUPLog.Errorln("this UE does not have any available PDU session")
		return
	}

	gtpConnection := pduSession.GTPConnection

	userPlaneConnection := gtpConnection.UserPlaneConnection

	n, err := userPlaneConnection.WriteToGTP(gtpConnection.OutgoingTEID, packet, gtpConnection.UPFUDPAddr)
	if err != nil {
		logger.NWuUPLog.Errorf("write to UPF failed: %+v", err)
		if err == gtpv1.ErrConnNotOpened {
			logger.NWuUPLog.Errorln("the connection has been closed")
			// TODO: Release the GTP resource
		}
		return
	} else {
		logger.NWuUPLog.Debugln("forward NWu -> N3")
		logger.NWuUPLog.Debugf("wrote %d bytes", n)
		return
	}
}
