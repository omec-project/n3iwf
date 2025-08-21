// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/n3iwf/ngap/message"
	"github.com/omec-project/n3iwf/util"
)

var tcpListener net.Listener

// Run sets up N3IWF NAS for UE to forward NAS message to AMF
func Run(n3iwfCtx *context.N3IWFContext, wg *sync.WaitGroup) error {
	nasTcpAddress := fmt.Sprintf("%s:%d", n3iwfCtx.IpSecGatewayAddress, n3iwfCtx.TcpPort)
	listener, err := net.Listen("tcp", nasTcpAddress)
	if err != nil {
		logger.NWuCPLog.Errorf("failed to listen on TCP address: %+v", err)
		return err
	}
	tcpListener = listener

	logger.NWuCPLog.Debugf("successfully listening on %+v", nasTcpAddress)

	wg.Add(1)
	go listenAndServe(wg)

	return nil
}

// listenAndServe handles TCP listener and accepts incoming requests.
// Stores accepted connection into UE context, and calls serveConn() to handle messages.
func listenAndServe(wg *sync.WaitGroup) {
	defer util.RecoverWithLog(logger.NWuCPLog)
	defer func() {
		if err := tcpListener.Close(); err != nil {
			logger.NWuCPLog.Errorf("error closing tcpListener: %+v", err)
		}
		wg.Done()
	}()

	for {
		conn, err := tcpListener.Accept()
		if err != nil {
			logger.NWuCPLog.Errorf("TCP server accept failed: %+v. Closing the listener", err)
			return
		}

		logger.NWuCPLog.Infof("accepted UE from %+v", conn.RemoteAddr())

		n3iwfCtx := context.N3IWFSelf()
		ueIP := strings.SplitN(conn.RemoteAddr().String(), ":", 2)[0]
		ikeUe, ok := n3iwfCtx.AllocatedUEIPAddressLoad(ueIP)
		if !ok {
			logger.NWuCPLog.Errorf("UE context not found for peer %+v", ueIP)
			_ = conn.Close()
			continue
		}

		ranUe, err := n3iwfCtx.RanUeLoadFromIkeSPI(ikeUe.N3IWFIKESecurityAssociation.LocalSPI)
		if err != nil {
			logger.NWuCPLog.Errorf("RanUe context not found: %+v", err)
			_ = conn.Close()
			continue
		}

		n3iwfUe, ok := ranUe.(*context.N3IWFRanUe)
		if !ok {
			logger.NWuCPLog.Errorf("type assertion: RanUe -> N3iwfUe failed")
			_ = conn.Close()
			continue
		}

		// Store connection
		n3iwfUe.TCPConnection = conn

		n3iwfCtx.NgapServer.RcvEventCh <- context.NewNASTCPConnEstablishedCompleteEvt(n3iwfUe.RanUeNgapId)

		wg.Add(1)
		go serveConn(n3iwfUe, conn, wg)
	}
}

// Stop closes the NWuCP server and all UE connections
func Stop(n3iwfCtx *context.N3IWFContext) {
	logger.NWuCPLog.Infoln("closing NWuCP server")

	if err := tcpListener.Close(); err != nil {
		logger.NWuCPLog.Errorf("error stopping NWuCP server: %+v", err)
	}

	n3iwfCtx.RanUePool.Range(
		func(key, value any) bool {
			ranUe, ok := value.(*context.N3IWFRanUe)
			if ok && ranUe.TCPConnection != nil {
				if err := ranUe.TCPConnection.Close(); err != nil {
					logger.InitLog.Errorf("error closing UE TCP connection: %+v", err)
				}
			}
			return true
		})
}

// serveConn handles accepted TCP connection. Reads NAS packets and forwards to AMF
func serveConn(ranUe *context.N3IWFRanUe, conn net.Conn, wg *sync.WaitGroup) {
	defer util.RecoverWithLog(logger.NWuCPLog)
	defer func() {
		if err := conn.Close(); err != nil {
			logger.NWuCPLog.Errorf("error closing connection: %+v", err)
		}
		wg.Done()
	}()

	reader := bufio.NewReader(conn)
	buf := make([]byte, context.MAX_BUF_MSG_LEN)
	for {
		// Read the length of NAS message
		_, err := io.ReadFull(reader, buf[:2])
		if err != nil {
			logger.NWuCPLog.Errorf("failed to read NAS message length: %+v", err)
			ranUe.TCPConnection = nil
			return
		}
		nasLen := binary.BigEndian.Uint16(buf[:2])
		if int(nasLen) > cap(buf) {
			buf = make([]byte, nasLen)
		}

		// Read the NAS message
		n, err := io.ReadFull(reader, buf[:nasLen])
		if err != nil {
			logger.NWuCPLog.Errorf("failed to read NAS message: %+v", err)
			ranUe.TCPConnection = nil
			return
		}
		forwardData := make([]byte, n)
		copy(forwardData, buf[:n])

		wg.Add(1)
		go forward(ranUe, forwardData, wg)
	}
}

// forward sends NAS messages from UE to the associated AMF
func forward(ranUe *context.N3IWFRanUe, packet []byte, wg *sync.WaitGroup) {
	defer wg.Done()
	defer util.RecoverWithLog(logger.NWuCPLog)

	logger.NWuCPLog.Debugln("forwarding NWu -> N2")
	message.SendUplinkNASTransport(ranUe, packet)
}
