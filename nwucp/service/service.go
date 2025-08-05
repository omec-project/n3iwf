// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/n3iwf/ngap/message"
	"github.com/omec-project/n3iwf/util"
)

var tcpListener net.Listener

// Run setup N3IWF NAS for UE to forward NAS message
// to AMF
func Run(wg *sync.WaitGroup) error {
	// N3IWF context
	n3iwfSelf := context.N3IWFSelf()
	tcpAddr := fmt.Sprintf("%s:%d", n3iwfSelf.IpSecGatewayAddress, n3iwfSelf.TcpPort)

	listener, err := net.Listen("tcp", tcpAddr)
	if err != nil {
		logger.NWuCPLog.Errorf("listen TCP address failed: %+v", err)
		return errors.New("listen failed")
	}

	tcpListener = listener

	logger.NWuCPLog.Debugf("successfully listen %+v", tcpAddr)

	wg.Add(1)
	go listenAndServe(tcpListener, wg)

	return nil
}

// listenAndServe handles TCP listener and accepts incoming
// requests. It also stores accepted connection into UE
// context, and finally, calls serveConn() to serve the messages
// received from the connection.
func listenAndServe(listener net.Listener, wg *sync.WaitGroup) {
	defer func() {
		err := tcpListener.Close()
		if err != nil {
			logger.NWuCPLog.Errorf("error closing tcpListener: %+v", err)
		}
		wg.Done()
	}()

	defer util.RecoverWithLog(logger.NWuCPLog)

	for {
		connection, err := listener.Accept()
		if err != nil {
			logger.NWuCPLog.Errorf("TCP server accept failed: %+v. Close the listener...", err)
			return
		}

		logger.NWuCPLog.Debugf("accepted one UE from %+v", connection.RemoteAddr())

		// Find UE context and store this connection into it, then check if
		// there is any cached NAS message for this UE. If yes, send to it.
		n3iwfSelf := context.N3IWFSelf()

		ueIP := strings.SplitN(connection.RemoteAddr().String(), ":", 2)[0]
		ikeUe, ok := n3iwfSelf.AllocatedUEIPAddressLoad(ueIP)
		if !ok {
			logger.NWuCPLog.Errorf("UE context not found for peer %+v", ueIP)
			_ = connection.Close()
			continue
		}

		ranUe, err := n3iwfSelf.RanUeLoadFromIkeSPI(ikeUe.N3IWFIKESecurityAssociation.LocalSPI)
		if err != nil {
			logger.NWuCPLog.Errorf("RanUe context not found: %+v", err)
			_ = connection.Close()
			continue
		}
		// Store connection
		ranUe.TCPConnection = connection

		n3iwfSelf.NgapServer.RcvEventCh <- context.NewNASTCPConnEstablishedCompleteEvt(
			ranUe.RanUeNgapId,
		)

		wg.Add(1)
		go serveConn(ranUe, connection, wg)
	}
}

func decapNasMsgFromEnvelope(envelop []byte) []byte {
	// According to TS 24.502 8.2.4,
	// in order to transport a NAS message over the non-3GPP access between the UE and the N3IWF,
	// the NAS message shall be framed in a NAS message envelope as defined in subclause 9.4.
	// According to TS 24.502 9.4,
	// a NAS message envelope = Length | NAS Message

	// Get NAS Message Length
	nasLen := binary.BigEndian.Uint16(envelop[:2])
	nasMsg := make([]byte, nasLen)
	copy(nasMsg, envelop[2:2+nasLen])

	return nasMsg
}

func Stop(n3iwfContext *context.N3IWFContext) {
	logger.NWuCPLog.Infoln("close Nwucp server")

	if err := tcpListener.Close(); err != nil {
		logger.NWuCPLog.Errorf("stop nwuup server error: %+v", err)
	}

	n3iwfContext.RanUePool.Range(
		func(key, value any) bool {
			ranUe := value.(*context.N3IWFRanUe)
			if ranUe.TCPConnection != nil {
				if err := ranUe.TCPConnection.Close(); err != nil {
					logger.InitLog.Errorf("stop nwucp server error: %+v", err)
				}
			}
			return true
		})
}

// serveConn handle accepted TCP connection. It reads NAS packets
// from the connection and call forward() to forward NAS messages
// to AMF
func serveConn(ranUe *context.N3IWFRanUe, connection net.Conn, wg *sync.WaitGroup) {
	defer func() {
		err := connection.Close()
		if err != nil {
			logger.NWuCPLog.Errorf("error closing connection: %+v", err)
		}
		wg.Done()
	}()

	defer util.RecoverWithLog(logger.NWuCPLog)

	data := make([]byte, 65535)
	for {
		n, err := connection.Read(data)
		if err != nil {
			logger.NWuCPLog.Errorf("read TCP connection failed: %+v", err)
			ranUe.TCPConnection = nil
			return
		}
		logger.NWuCPLog.Debugf("get NAS PDU from UE: NAS length: %d, NAS content: %s", n, hex.Dump(data[:n]))

		// Decap Nas envelope
		forwardData := decapNasMsgFromEnvelope(data)

		wg.Add(1)
		go forward(ranUe, forwardData, wg)
	}
}

// forward forwards NAS messages sent from UE to the
// associated AMF
func forward(ranUe *context.N3IWFRanUe, packet []byte, wg *sync.WaitGroup) {
	defer func() {
		wg.Done()
	}()

	defer util.RecoverWithLog(logger.NWuCPLog)

	logger.NWuCPLog.Debugln("forward NWu -> N2")
	message.SendUplinkNASTransport(ranUe, packet)
}
