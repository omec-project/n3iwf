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

var (
	RECEIVE_NGAPPACKET_CHANNEL_LEN = 512
	RECEIVE_NGAPEVENT_CHANNEL_LEN  = 512
)

// Run start the N3IWF SCTP process.
func Run(wg *sync.WaitGroup) error {
	// n3iwf context
	n3iwfSelf := context.N3IWFSelf()
	// load amf SCTP address slice
	amfSCTPAddresses := n3iwfSelf.AmfSctpAddresses

	localAddr := n3iwfSelf.LocalSctpAddress

	n3iwfSelf.NgapServer = NewNgapServer()
	for _, remoteAddr := range amfSCTPAddresses {
		errChan := make(chan error)
		wg.Add(1)
		go receiver(localAddr, remoteAddr, errChan, n3iwfSelf.NgapServer, wg)
		if err, ok := <-errChan; ok {
			logger.NgapLog.Errorln(err)
			return errors.New("NGAP service run failed")
		}
	}

	wg.Add(1)
	go server(n3iwfSelf.NgapServer, wg)

	return nil
}

func NewNgapServer() *context.NgapServer {
	return &context.NgapServer{
		RcvNgapPktCh: make(chan context.ReceiveNGAPPacket, RECEIVE_NGAPPACKET_CHANNEL_LEN),
		RcvEventCh:   make(chan context.NgapEvt, RECEIVE_NGAPEVENT_CHANNEL_LEN),
	}
}

func server(ngapServer *context.NgapServer, wg *sync.WaitGroup) {
	defer func() {
		logger.NgapLog.Infoln("NGAP server stopped")
		close(ngapServer.RcvEventCh)
		close(ngapServer.RcvNgapPktCh)
		wg.Done()
	}()
	defer util.RecoverWithLog(logger.NgapLog)

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

func receiver(localAddr, remoteAddr *sctp.SCTPAddr, errChan chan<- error, ngapServer *context.NgapServer,
	wg *sync.WaitGroup,
) {
	defer func() {
		logger.NgapLog.Infoln("NGAP receiver stopped")
		wg.Done()
	}()

	defer util.RecoverWithLog(logger.NgapLog)

	var conn *sctp.SCTPConn
	var err error

	// Connect the session
	for i := range 3 {
		conn, err = sctp.DialSCTP("sctp", localAddr, remoteAddr)
		if err == nil {
			break
		}
		logger.NgapLog.Errorf("dial SCTP: %+v", err)

		if i == 2 {
			logger.NgapLog.Debugf("AMF SCTP address: %+v", remoteAddr.String())
			errChan <- errors.New("failed to connect to AMF")
			return
		}
		logger.NgapLog.Infoln("retry to connect AMF after 1 second...")
		time.Sleep(1 * time.Second)
	}

	// Set default sender SCTP information sinfo_ppid = NGAP_PPID = 60
	info, err := conn.GetDefaultSentParam()
	if err != nil {
		logger.NgapLog.Errorf("GetDefaultSentParam(): %+v", err)
		errConn := conn.Close()
		if errConn != nil {
			logger.NgapLog.Errorf("conn close error in GetDefaultSentParam(): %+v", errConn)
		}
		errChan <- errors.New("get socket information failed")
		return
	}
	// The previous SCTP library expected PPID in network byte order (big-endian),
	// while the new library expects host byte order. Using bits.ReverseBytes32
	// ensures the PPID is interpreted correctly by the new SCTP implementation.
	info.PPID = bits.ReverseBytes32(libNgap.PPID)
	err = conn.SetDefaultSentParam(info)
	if err != nil {
		logger.NgapLog.Errorf("SetDefaultSentParam(): %+v", err)
		errConn := conn.Close()
		if errConn != nil {
			logger.NgapLog.Errorf("conn close error in SetDefaultSentParam(): %+v", errConn)
		}
		errChan <- errors.New("set socket parameter failed")
		return
	}

	// Subscribe receiver SCTP information
	err = conn.SubscribeEvents(sctp.SCTP_EVENT_DATA_IO)
	if err != nil {
		logger.NgapLog.Errorf("SubscribeEvents(): %+v", err)
		errConn := conn.Close()
		if errConn != nil {
			logger.NgapLog.Errorf("conn close error in SubscribeEvents(): %+v", errConn)
		}
		errChan <- errors.New("subscribe SCTP event failed")
		return
	}

	// Send NG setup request
	message.SendNGSetupRequest(conn)

	close(errChan)

	ngapServer.Conn = append(ngapServer.Conn, conn)

	data := make([]byte, 65535)

	for {
		n, info, err := conn.SCTPRead(data)

		if err != nil {
			logger.NgapLog.Debugf("AMF SCTP address: %+v", conn.RemoteAddr().String())
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				logger.NgapLog.Warnln("close connection")
				errConn := conn.Close()
				if errConn != nil {
					logger.NgapLog.Errorf("conn close error: %+v", errConn)
				}
				ngapServer.RcvNgapPktCh <- context.ReceiveNGAPPacket{}
				return
			}
			logger.NgapLog.Errorf("read from SCTP connection failed: %+v", err)
		} else {
			logger.NgapLog.Debugf("successfully read %d bytes", n)

			if info == nil || bits.ReverseBytes32(info.PPID) != libNgap.PPID {
				logger.NgapLog.Warn("received SCTP PPID != 60")
				continue
			}

			forwardData := make([]byte, n)
			copy(forwardData, data[:n])

			ngapServer.RcvNgapPktCh <- context.ReceiveNGAPPacket{
				Conn: conn,
				Buf:  forwardData[:n],
			}
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
