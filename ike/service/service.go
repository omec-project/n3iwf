// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"errors"
	"net"
	"sync"

	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/ike"
	"github.com/omec-project/n3iwf/ike/handler"
	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/n3iwf/util"
)

var (
	RECEIVE_IKEPACKET_CHANNEL_LEN = 512
	RECEIVE_IKEEVENT_CHANNEL_LEN  = 512
)

func Run(wg *sync.WaitGroup) error {
	n3iwfSelf := context.N3IWFSelf()

	// Resolve UDP addresses
	ip := n3iwfSelf.IkeBindAddress
	udpAddrPort500, err := net.ResolveUDPAddr("udp", ip+":500")
	if err != nil {
		logger.IKELog.Errorf("resolve UDP address failed: %+v", err)
		return errors.New("IKE service run failed")
	}
	udpAddrPort4500, err := net.ResolveUDPAddr("udp", ip+":4500")
	if err != nil {
		logger.IKELog.Errorf("resolve UDP address failed: %+v", err)
		return errors.New("IKE service run failed")
	}

	n3iwfSelf.IkeServer = NewIkeServer()

	// Listen and serve
	var errChan chan error

	// Port 500
	wg.Add(1)
	errChan = make(chan error)
	go receiver(udpAddrPort500, n3iwfSelf.IkeServer, errChan, wg)
	if err, ok := <-errChan; ok {
		logger.IKELog.Errorln(err)
		return errors.New("IKE service run failed")
	}

	// Port 4500
	wg.Add(1)
	errChan = make(chan error)
	go receiver(udpAddrPort4500, n3iwfSelf.IkeServer, errChan, wg)
	if err, ok := <-errChan; ok {
		logger.IKELog.Errorln(err)
		return errors.New("IKE service run failed")
	}

	wg.Add(1)
	go server(n3iwfSelf.IkeServer, wg)

	return nil
}

func NewIkeServer() *context.IkeServer {
	return &context.IkeServer{
		Listener:    make(map[int]*net.UDPConn),
		RcvIkePktCh: make(chan context.IkeReceivePacket, RECEIVE_IKEPACKET_CHANNEL_LEN),
		RcvEventCh:  make(chan context.IkeEvt, RECEIVE_IKEEVENT_CHANNEL_LEN),
		StopServer:  make(chan struct{}),
	}
}

func server(ikeServer *context.IkeServer, wg *sync.WaitGroup) {
	defer func() {
		logger.IKELog.Infof("IKE server stopped")
		close(ikeServer.RcvIkePktCh)
		close(ikeServer.StopServer)
		wg.Done()
	}()
	defer util.RecoverWithLog(logger.IKELog)

	for {
		select {
		case rcvPkt := <-ikeServer.RcvIkePktCh:
			logger.IKELog.Debugf("receive IKE packet")
			ike.Dispatch(&rcvPkt.Listener, &rcvPkt.LocalAddr, &rcvPkt.RemoteAddr, rcvPkt.Msg)
		case rcvIkeEvent := <-ikeServer.RcvEventCh:
			handler.HandleEvent(rcvIkeEvent)
		case <-ikeServer.StopServer:
			return
		}
	}
}

func receiver(localAddr *net.UDPAddr, ikeServer *context.IkeServer, errChan chan<- error, wg *sync.WaitGroup) {
	defer func() {
		logger.IKELog.Infof("IKE receiver stopped")
		wg.Done()
	}()
	defer util.RecoverWithLog(logger.IKELog)

	listener, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		logger.IKELog.Errorf("listen UDP failed: %+v", err)
		errChan <- errors.New("listenAndServe failed")
		return
	}

	close(errChan)

	ikeServer.Listener[localAddr.Port] = listener

	data := make([]byte, 65535)

	for {
		n, remoteAddr, err := listener.ReadFromUDP(data)
		if err != nil {
			logger.IKELog.Errorf("readFromUDP failed: %+v", err)
			return
		}

		forwardData := make([]byte, n)
		copy(forwardData, data[:n])
		ikeServer.RcvIkePktCh <- context.IkeReceivePacket{
			RemoteAddr: *remoteAddr,
			Listener:   *listener,
			LocalAddr:  *localAddr,
			Msg:        forwardData,
		}
	}
}

func Stop(n3iwfContext *context.N3IWFContext) {
	logger.IKELog.Infoln("close IKE server")

	for _, ikeServerListener := range n3iwfContext.IkeServer.Listener {
		if err := ikeServerListener.Close(); err != nil {
			logger.IKELog.Errorf("stop IKE server: %s error: %+v", ikeServerListener.LocalAddr().String(), err)
		}
	}

	n3iwfContext.IkeServer.StopServer <- struct{}{}
}
