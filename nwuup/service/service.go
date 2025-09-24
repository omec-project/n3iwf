// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package service

import (
	ctx "context"
	"fmt"
	"net"
	"sync"

	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/gtp/handler"
	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/n3iwf/util"
	"github.com/wmnsk/go-gtp/gtpv1"
	"github.com/wmnsk/go-gtp/gtpv1/message"
	"golang.org/x/net/ipv4"
)

// Run initializes GRE and GTP-U connections and starts listeners for each.
func Run(n3iwfCtx *context.N3IWFContext, wg *sync.WaitGroup) error {
	if err := newGreConn(n3iwfCtx); err != nil {
		return err
	}
	if err := newGtpuConn(n3iwfCtx); err != nil {
		return err
	}
	wg.Add(2)
	go greListenAndServe(n3iwfCtx, wg)
	go gtpuListenAndServe(n3iwfCtx, wg)
	return nil
}

// newGreConn sets up a GRE IPv4 packet connection socket.
func newGreConn(n3iwfCtx *context.N3IWFContext) error {
	listenAddr := n3iwfCtx.IpSecGatewayAddress
	conn, err := net.ListenPacket("ip4:gre", listenAddr)
	if err != nil {
		logger.NWuUPLog.Errorf("error setting GRE listen socket on %s: %+v", listenAddr, err)
		return fmt.Errorf("error setting GRE listen socket on %s", listenAddr)
	}
	greConn := ipv4.NewPacketConn(conn)
	if greConn == nil {
		logger.NWuUPLog.Errorf("error opening GRE IPv4 packet connection socket on %s", listenAddr)
		return fmt.Errorf("error opening GRE IPv4 packet connection socket on %s", listenAddr)
	}
	n3iwfCtx.GreConn = greConn
	return nil
}

// newGtpuConn sets up a GTP-U connection and handler.
func newGtpuConn(n3iwfCtx *context.N3IWFContext) error {
	gtpuAddr := n3iwfCtx.GtpBindAddress + gtpv1.GTPUPort
	laddr, err := net.ResolveUDPAddr("udp", gtpuAddr)
	if err != nil {
		return fmt.Errorf("resolve GTP-U address %s Failed", gtpuAddr)
	}
	upConn := gtpv1.NewUPlaneConn(laddr)
	upConn.AddHandler(message.MsgTypeTPDU, func(c gtpv1.Conn, senderAddr net.Addr, msg message.Message) error {
		return handler.HandleQoSTPDU(n3iwfCtx, c, senderAddr, msg)
	})
	n3iwfCtx.GtpuConn = upConn
	return nil
}

// greListenAndServe reads GRE packets and forwards them to the N3 interface.
func greListenAndServe(n3iwfCtx *context.N3IWFContext, wg *sync.WaitGroup) {
	defer util.RecoverWithLog(logger.NWuUPLog)
	defer func() {
		if err := n3iwfCtx.GreConn.Close(); err != nil {
			logger.NWuUPLog.Errorf("error closing raw socket: %+v", err)
		}
		wg.Done()
	}()

	buffer := make([]byte, context.MAX_BUF_MSG_LEN)
	if err := n3iwfCtx.GreConn.SetControlMessage(ipv4.FlagInterface|ipv4.FlagTTL, true); err != nil {
		logger.NWuUPLog.Errorf("set control message visibility for IPv4 packet connection fail: %+v", err)
		return
	}

	for {
		n, cm, src, err := n3iwfCtx.GreConn.ReadFrom(buffer)
		if err != nil {
			logger.NWuUPLog.Errorf("error read from IPv4 packet connection: %+v", err)
			return
		}
		logger.NWuUPLog.Debugf("read %d bytes, %s", n, cm)
		// Avoid unnecessary allocation by slicing buffer
		forwardData := buffer[:n]
		go func(data []byte, srcAddr string, ifIndex int) {
			handler.ForwardUL(n3iwfCtx, srcAddr, ifIndex, data)
		}(append([]byte(nil), forwardData...), src.String(), cm.IfIndex)
	}
}

// gtpuListenAndServe starts the GTP-U listener.
func gtpuListenAndServe(n3iwfCtx *context.N3IWFContext, wg *sync.WaitGroup) {
	defer util.RecoverWithLog(logger.NWuUPLog)
	defer wg.Done()
	if err := n3iwfCtx.GtpuConn.ListenAndServe(ctx.Background()); err != nil {
		logger.NWuUPLog.Errorf("GTP-U server err: %v", err)
	}
}

// Stop closes GRE and GTP-U connections.
func Stop(n3iwfCtx *context.N3IWFContext) {
	logger.NWuUPLog.Infoln("close Nwuup server")
	if err := n3iwfCtx.GreConn.Close(); err != nil {
		logger.NWuUPLog.Errorf("stop nwuup greConn error: %v", err)
	}
	if err := n3iwfCtx.GtpuConn.Close(); err != nil {
		logger.NWuUPLog.Errorf("stop nwuup gtpuConn error: %v", err)
	}
}
