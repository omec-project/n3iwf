// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"errors"
	"io"
	"math/bits"
	"sync"
	"time"

	"github.com/ishidawataru/sctp"
	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/n3iwf/ngap"
	"github.com/omec-project/n3iwf/ngap/handler"
	"github.com/omec-project/n3iwf/ngap/message"
	"github.com/omec-project/n3iwf/util"
	libNgap "github.com/omec-project/ngap/v2"
)

const (
	RECEIVE_NGAPPACKET_CHANNEL_LEN = 512
	RECEIVE_NGAPEVENT_CHANNEL_LEN  = 512
)

// Run start the N3IWF SCTP process.
func Run(n3iwfCtx *context.N3IWFContext, wg *sync.WaitGroup) error {
	// n3iwf context

	localAddr := n3iwfCtx.LocalSctpAddress

	n3iwfCtx.NgapServer = &context.NgapServer{
		RcvNgapPktCh: make(chan context.NgapReceivePacket, RECEIVE_NGAPPACKET_CHANNEL_LEN),
		RcvEventCh:   make(chan context.NgapEvt, RECEIVE_NGAPEVENT_CHANNEL_LEN),
	}

	for _, remoteAddr := range n3iwfCtx.AmfSctpAddresses {
		errChan := make(chan error, 1) // buffered: Run may stop waiting on shutdown
		wg.Add(1)
		go listenAndServe(localAddr, remoteAddr, errChan, n3iwfCtx, wg)
		// Dialing and the NG Setup write cannot be interrupted, but waiting for them can: on
		// shutdown Run gives up here, and the receiver closes its connection itself once
		// Stop has run (see RegisterConn).
		select {
		case err, ok := <-errChan:
			if ok {
				logger.NgapLog.Errorln(err)
				return errors.New("NGAP service run failed")
			}
		case <-n3iwfCtx.Ctx.Done():
			return errors.New("NGAP service start cancelled")
		}
	}

	wg.Add(1)
	go runNgapEventHandler(n3iwfCtx.NgapServer, wg)

	return nil
}

func runNgapEventHandler(ngapServer *context.NgapServer, wg *sync.WaitGroup) {
	defer util.RecoverWithLog(logger.NgapLog)

	defer func() {
		logger.NgapLog.Infoln("NGAP server stopped")
		close(ngapServer.RcvNgapPktCh)
		// RcvEventCh is deliberately not closed: the IKE event loop and the delivery
		// goroutines behind NgapServer.QueueEvent keep sending to it after this loop has
		// ended (for example when an AMF connection drops), and a send on a closed channel
		// panics. Discard what arrives instead, so those producers neither panic nor block.
		go discardEvents(ngapServer.RcvEventCh)
		wg.Done()
	}()

	for {
		select {
		case rcvPkt := <-ngapServer.RcvNgapPktCh:
			if len(rcvPkt.Buf) == 0 { // receiver closed
				return
			}
			ngap.Dispatch(rcvPkt.Conn, rcvPkt.Buf)
		case rcvEvt := <-ngapServer.RcvEventCh:
			handleNgapEvent(rcvEvt)
		}
	}
}

// discardEvents consumes and drops events until the process exits
func discardEvents(ch <-chan context.NgapEvt) {
	for evt := range ch {
		// Expiring a half-open RAN UE is local cleanup: the IKE side has already dropped the
		// IKE SA, so nothing else will ever release the RAN UE, its AMF list entry or its
		// TEIDs. Everything else needs the AMF connection and is dropped.
		if evt != nil && evt.Type() == context.ExpireHalfOpenRanUe {
			handleNgapEvent(evt)
		}
	}
}

// handleNgapEvent handles one internal event, recovering from panics so that one bad
// event cannot terminate the NGAP event loop.
func handleNgapEvent(rcvEvt context.NgapEvt) {
	defer util.RecoverWithLog(logger.NgapLog)

	handler.HandleEvent(rcvEvt)
}

// handleConnError closes the connection and sends an error to errChan
func handleConnError(conn *sctp.SCTPConn, logMsg string, err error, errChan chan<- error) {
	logger.NgapLog.Errorf(logMsg+": %+v", err)
	if conn != nil {
		errConn := conn.Close()
		if errConn != nil {
			logger.NgapLog.Errorf("conn close error: %+v", errConn)
		}
	}
	errChan <- errors.New(logMsg)
}

func listenAndServe(localAddr, remoteAddr *sctp.SCTPAddr, errChan chan<- error,
	n3iwfCtx *context.N3IWFContext, wg *sync.WaitGroup,
) {
	defer util.RecoverWithLog(logger.NgapLog)
	defer func() {
		logger.NgapLog.Infoln("NGAP receiver stopped")
		wg.Done()
	}()

	var conn *sctp.SCTPConn
	var err error

	// Try to connect up to 3 times
	for i := range 3 {
		conn, err = sctp.DialSCTP("sctp", localAddr, remoteAddr)
		if err == nil {
			break
		}
		logger.NgapLog.Errorf("dial SCTP: %+v", err)
		if i == 2 {
			logger.NgapLog.Debugf("AMF SCTP address: %s", remoteAddr.String())
			handleConnError(nil, "failed to connect to AMF", err, errChan)
			return
		}
		logger.NgapLog.Infoln("retry to connect AMF after 1 second")
		select {
		case <-time.After(1 * time.Second):
		case <-n3iwfCtx.Ctx.Done():
			handleConnError(nil, "shutdown while connecting to AMF", errors.New("cancelled"), errChan)
			return
		}
	}

	// Set default sender SCTP information sinfo_ppid = NGAP_PPID = 60
	info, err := conn.GetDefaultSentParam()
	if err != nil {
		handleConnError(conn, "GetDefaultSentParam()", err, errChan)
		return
	}
	// The previous SCTP library expected PPID in network byte order (big-endian),
	// while the new library expects host byte order. Using bits.ReverseBytes32
	// ensures the PPID is interpreted correctly by the new SCTP implementation.
	info.PPID = bits.ReverseBytes32(libNgap.PPID)
	if err = conn.SetDefaultSentParam(info); err != nil {
		handleConnError(conn, "SetDefaultSentParam()", err, errChan)
		return
	}

	// Subscribe receiver SCTP information
	if err = conn.SubscribeEvents(sctp.SCTP_EVENT_DATA_IO); err != nil {
		handleConnError(conn, "SubscribeEvents()", err, errChan)
		return
	}

	// Register before the NG Setup write and before reporting success: Stop closes registered
	// connections, which is what unblocks a write to a stalled AMF, and a failure later in
	// startup must find this connection. Registration is refused if Stop already ran.
	if !n3iwfCtx.NgapServer.RegisterConn(conn) {
		handleConnError(conn, "NGAP server is stopping", errors.New("stopped"), errChan)
		return
	}

	// Send NG setup request
	message.SendNGSetupRequest(conn, n3iwfCtx)
	close(errChan)

	data := make([]byte, context.MAX_BUF_MSG_LEN)

	for {
		n, info, err := conn.SCTPRead(data)
		if err != nil {
			logger.NgapLog.Debugf("AMF SCTP address: %+v", conn.RemoteAddr().String())
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				logger.NgapLog.Warnln("close connection")
				_ = conn.Close()
				n3iwfCtx.NgapServer.RcvNgapPktCh <- context.NgapReceivePacket{} // signal closed
				return
			}
			logger.NgapLog.Errorf("read from SCTP connection failed: %+v", err)
			return
		}
		logger.NgapLog.Debugf("successfully read %d bytes", n)

		if info == nil || bits.ReverseBytes32(info.PPID) != libNgap.PPID {
			logger.NgapLog.Warn("received SCTP PPID != 60")
			continue
		}

		forwardData := make([]byte, n)
		copy(forwardData, data[:n])

		n3iwfCtx.NgapServer.RcvNgapPktCh <- context.NgapReceivePacket{
			Conn: conn,
			Buf:  forwardData,
		}
	}
}

func Stop(n3iwfContext *context.N3IWFContext) {
	logger.NgapLog.Infoln("close NGAP server")
	if n3iwfContext.NgapServer == nil {
		return // startup ended before the server was created
	}

	for _, ngapServerConn := range n3iwfContext.NgapServer.StopConns() {
		if err := ngapServerConn.Close(); err != nil {
			logger.NgapLog.Errorf("stop ngap server error: %+v", err)
		}
	}
}
