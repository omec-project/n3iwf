// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/n3iwf/ngap/message"
)

// Run setup N3IWF NAS for UE to forward NAS message
// to AMF
func Run() error {
	// N3IWF context
	n3iwfSelf := context.N3IWFSelf()
	tcpAddr := fmt.Sprintf("%s:%d", n3iwfSelf.IpSecGatewayAddress, n3iwfSelf.TcpPort)

	tcpListener, err := net.Listen("tcp", tcpAddr)
	if err != nil {
		logger.NWuCPLog.Errorf("listen TCP address failed: %+v", err)
		return errors.New("listen failed")
	}

	logger.NWuCPLog.Debugf("successfully listen %+v", tcpAddr)

	go listenAndServe(tcpListener)

	return nil
}

// listenAndServe handles TCP listener and accepts incoming
// requests. It also stores accepted connection into UE
// context, and finally, calls serveConn() to serve the messages
// received from the connection.
func listenAndServe(tcpListener net.Listener) {
	defer func() {
		err := tcpListener.Close()
		if err != nil {
			logger.NWuCPLog.Errorf("error closing tcpListener: %+v", err)
		}
	}()

	for {
		connection, err := tcpListener.Accept()
		if err != nil {
			logger.NWuCPLog.Errorln("TCP server accept failed. Close the listener")
			return
		}

		logger.NWuCPLog.Debugf("accepted one UE from %+v", connection.RemoteAddr())

		// Find UE context and store this connection into it, then check if
		// there is any cached NAS message for this UE. If yes, send to it.
		n3iwfSelf := context.N3IWFSelf()

		ueIP := strings.Split(connection.RemoteAddr().String(), ":")[0]
		ue, ok := n3iwfSelf.AllocatedUEIPAddressLoad(ueIP)
		if !ok {
			logger.NWuCPLog.Errorf("UE context not found for peer %+v", ueIP)
			continue
		}

		// Store connection
		ue.TCPConnection = connection

		if ue.TemporaryCachedNASMessage != nil {
			// Send to UE
			if n, err := connection.Write(ue.TemporaryCachedNASMessage); err != nil {
				logger.NWuCPLog.Errorf("writing via IPSec signaling SA failed: %+v", err)
			} else {
				logger.NWuCPLog.Debugln("forward NWu <- N2")
				logger.NWuCPLog.Debugf("wrote %d bytes", n)
			}
			// Clean the cached message
			ue.TemporaryCachedNASMessage = nil
		}

		go serveConn(ue, connection)
	}
}

// serveConn handles accepted TCP connections. It reads NAS packets
// from the connection and calls forward() to forward NAS messages
// to AMF.
func serveConn(ue *context.N3IWFUe, connection net.Conn) {
	defer func() {
		err := connection.Close()
		if err != nil {
			logger.NWuCPLog.Errorf("error closing connection: %+v", err)
		}
	}()

	data := make([]byte, 65535)
	for {
		n, err := connection.Read(data)
		if err != nil {
			if err.Error() == "EOF" {
				logger.NWuCPLog.Warnln("connection close by peer")
				ue.TCPConnection = nil
				return
			} else {
				logger.NWuCPLog.Errorf("read TCP connection failed: %+v", err)
			}
		}
		logger.NWuCPLog.Debugf("get NAS PDU from UE: NAS length: %d, NAS content: %s", n, hex.Dump(data[:n]))

		forwardData := make([]byte, n)
		copy(forwardData, data[:n])

		go forward(ue, forwardData)
	}
}

// forward forwards NAS messages sent from UE to the
// associated AMF
func forward(ue *context.N3IWFUe, packet []byte) {
	logger.NWuCPLog.Debugln("forward NWu -> N2")
	message.SendUplinkNASTransport(ue.AMF, ue, packet)
}
