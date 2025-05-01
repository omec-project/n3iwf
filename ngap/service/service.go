// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"errors"
	"io"
	"time"

	"git.cs.nctu.edu.tw/calee/sctp"
	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/n3iwf/ngap"
	"github.com/omec-project/n3iwf/ngap/message"
	lib_ngap "github.com/omec-project/ngap"
)

// Run start the N3IWF SCTP process.
func Run() error {
	n3iwfSelf := context.N3IWFSelf()
	amfSCTPAddresses := n3iwfSelf.AmfSctpAddresses
	localAddr := n3iwfSelf.LocalSctpAddress

	for _, remoteAddr := range amfSCTPAddresses {
		errChan := make(chan error)
		go listenAndServe(localAddr, remoteAddr, errChan)
		if err, ok := <-errChan; ok {
			logger.NgapLog.Errorln(err)
			return errors.New("NGAP service run failed")
		}
	}

	return nil
}

func listenAndServe(localAddr, remoteAddr *sctp.SCTPAddr, errChan chan<- error) {
	var conn *sctp.SCTPConn
	var err error

	// Connect the session
	for i := 0; i < 3; i++ {
		conn, err = sctp.DialSCTP("sctp", localAddr, remoteAddr)
		if err != nil {
			logger.NgapLog.Errorf("dial SCTP: %+v", err)
		} else {
			break
		}

		if i != 2 {
			logger.NgapLog.Infoln("retry to connect AMF after 1 second...")
			time.Sleep(1 * time.Second)
		} else {
			logger.NgapLog.Debugf("AMF SCTP address: %+v", remoteAddr.String())
			errChan <- errors.New("failed to connect to AMF")
			return
		}
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
	info.PPID = lib_ngap.PPID
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
	go message.SendNGSetupRequest(conn)

	close(errChan)

	data := make([]byte, 65535)

	for {
		n, info, _, err := conn.SCTPRead(data)

		if err != nil {
			logger.NgapLog.Debugf("AMF SCTP address: %+v", conn.RemoteAddr().String())
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				logger.NgapLog.Warnln("close connection")
				errConn := conn.Close()
				if errConn != nil {
					logger.NgapLog.Errorf("conn close error: %+v", errConn)
				}
				return
			}
			logger.NgapLog.Errorf("read from SCTP connection failed: %+v", err)
		} else {
			logger.NgapLog.Debugf("successfully read %d bytes", n)

			if info == nil || info.PPID != lib_ngap.PPID {
				logger.NgapLog.Warn("received SCTP PPID != 60")
				continue
			}

			forwardData := make([]byte, n)
			copy(forwardData, data[:n])

			go ngap.Dispatch(conn, forwardData)
		}
	}
}
