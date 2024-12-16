// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"net"

	n3iwf_context "github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/logger"
	gtpv1 "github.com/wmnsk/go-gtp/v1"
)

// SetupGTPTunnelWithUPF set up GTP connection with UPF
// return *gtpv1.UPlaneConn, net.Addr and error
func SetupGTPTunnelWithUPF(upfIPAddr string) (*gtpv1.UPlaneConn, net.Addr, error) {
	n3iwfSelf := n3iwf_context.N3IWFSelf()

	// Set up GTP connection
	upfUDPAddr := upfIPAddr + ":2152"

	remoteUDPAddr, err := net.ResolveUDPAddr("udp", upfUDPAddr)
	if err != nil {
		logger.GTPLog.Errorf("resolve UDP address %s failed: %+v", upfUDPAddr, err)
		return nil, nil, errors.New("resolve Address Failed")
	}

	n3iwfUDPAddr := n3iwfSelf.GTPBindAddress + ":2152"

	localUDPAddr, err := net.ResolveUDPAddr("udp", n3iwfUDPAddr)
	if err != nil {
		logger.GTPLog.Errorf("resolve UDP address %s failed: %+v", n3iwfUDPAddr, err)
		return nil, nil, errors.New("resolve Address Failed")
	}

	context := context.TODO()

	// Dial to UPF
	userPlaneConnection, err := gtpv1.DialUPlane(context, localUDPAddr, remoteUDPAddr)
	if err != nil {
		logger.GTPLog.Errorf("dial to UPF failed: %+v", err)
		return nil, nil, errors.New("dial failed")
	}

	return userPlaneConnection, remoteUDPAddr, nil
}

// ListenAndServe binds and listens user plane socket on N3IWF N3 interface,
// catching GTP packets and send it to NWu interface
func ListenAndServe(userPlaneConnection *gtpv1.UPlaneConn) error {
	go listenGTP(userPlaneConnection)
	return nil
}

// listenGTP handle the gtpv1 UPlane connection. It reads packets(without
// GTP header) from the connection and call forward() to forward user data
// to NWu interface.
func listenGTP(userPlaneConnection *gtpv1.UPlaneConn) {
	defer func() {
		err := userPlaneConnection.Close()
		if err != nil {
			logger.GTPLog.Errorf("userPlaneConnection Close failed: %+v", err)
		}
	}()

	payload := make([]byte, 65535)

	for {
		n, _, teid, err := userPlaneConnection.ReadFromGTP(payload)
		logger.GTPLog.Debugf("read %d bytes", n)
		if err != nil {
			logger.GTPLog.Errorf("read from GTP failed: %+v", err)
			return
		}

		forwardData := make([]byte, n)
		copy(forwardData, payload[:n])

		go forward(teid, forwardData)
	}
}

// forward forwards user plane packets from N3 to UE,
// with GRE header and new IP header encapsulated
func forward(ueTEID uint32, packet []byte) {
	// N3IWF context
	self := n3iwf_context.N3IWFSelf()
	// IPv4 packet connection
	ipv4PacketConn := self.NWuIPv4PacketConn
	// Find UE information
	ue, ok := self.AllocatedUETEIDLoad(ueTEID)
	if !ok {
		logger.GTPLog.Errorln("UE context not found")
		return
	}
	// UE IP
	ueInnerIPAddr := ue.IPSecInnerIPAddr

	// GRE header
	greHeader := []byte{0, 0, 8, 0}
	// IP payload
	greEncapsulatedPacket := append(greHeader, packet...)

	// Send to UE
	if n, err := ipv4PacketConn.WriteTo(greEncapsulatedPacket, nil, ueInnerIPAddr); err != nil {
		logger.GTPLog.Errorf("write to UE failed: %+v", err)
		return
	} else {
		logger.GTPLog.Debugln("forward NWu <- N3")
		logger.GTPLog.Debugf("wrote %d bytes", n)
	}
}
