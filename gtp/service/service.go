// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"net"

	n3iwfContext "github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/gtp/handler"
	"github.com/omec-project/n3iwf/logger"
	gtpv1 "github.com/wmnsk/go-gtp/gtpv1"
	gtpMessage "github.com/wmnsk/go-gtp/gtpv1/message"
)

// SetupGTPTunnelWithUPF sets up GTP connection with UPF
// returns *gtpv1.UPlaneConn, net.Addr and error
func SetupGTPTunnelWithUPF(upfIPAddr string) (*gtpv1.UPlaneConn, net.Addr, error) {
	n3iwfSelf := n3iwfContext.N3IWFSelf()

	// Set up GTP connection
	upfUDPAddr := upfIPAddr + gtpv1.GTPUPort

	remoteUDPAddr, err := net.ResolveUDPAddr("udp", upfUDPAddr)
	if err != nil {
		logger.GTPLog.Errorf("resolve UDP address %s failed: %+v", upfUDPAddr, err)
		return nil, nil, errors.New("resolve Address Failed")
	}

	n3iwfUDPAddr := n3iwfSelf.GtpBindAddress + gtpv1.GTPUPort

	localUDPAddr, err := net.ResolveUDPAddr("udp", n3iwfUDPAddr)
	if err != nil {
		logger.GTPLog.Errorf("resolve UDP address %s failed: %+v", n3iwfUDPAddr, err)
		return nil, nil, errors.New("resolve Address Failed")
	}

	// Dial to UPF
	userPlaneConnection, err := gtpv1.DialUPlane(context.Background(), localUDPAddr, remoteUDPAddr)
	if err != nil {
		logger.GTPLog.Errorf("dial to UPF failed: %+v", err)
		return nil, nil, errors.New("dial failed")
	}

	// Overwrite T-PDU handler for supporting extension header containing QoS parameters
	userPlaneConnection.AddHandler(gtpMessage.MsgTypeTPDU, handler.HandleQoSTPDU)

	return userPlaneConnection, remoteUDPAddr, nil
}
