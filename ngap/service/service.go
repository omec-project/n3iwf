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
	libNgap "github.com/omec-project/ngap"
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
		errChan := make(chan error)
		wg.Add(1)
		go listenAndServe(localAddr, remoteAddr, errChan, n3iwfCtx, wg)
		if err, ok := <-errChan; ok {
			logger.NgapLog.Errorln(err)
			return errors.New("NGAP service run failed")
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
		close(ngapServer.RcvEventCh)
		close(ngapServer.RcvNgapPktCh)
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
			handler.HandleEvent(rcvEvt)
		}
	}
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
		time.Sleep(1 * time.Second)
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

	// Send NG setup request
	message.SendNGSetupRequest(conn, n3iwfCtx)
	close(errChan)

	n3iwfCtx.NgapServer.Conn = append(n3iwfCtx.NgapServer.Conn, conn)
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

	for _, ngapServerConn := range n3iwfContext.NgapServer.Conn {
		if err := ngapServerConn.Close(); err != nil {
			logger.NgapLog.Errorf("stop ngap server error: %+v", err)
		}
	}
}
