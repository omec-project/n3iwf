// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"errors"
	"net"

	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/ike"
	"github.com/omec-project/n3iwf/logger"
)

func Run() error {
	// Resolve UDP addresses
	ip := context.N3IWFSelf().IkeBindAddress
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

	// Listen and serve
	var errChan chan error

	// Port 500
	errChan = make(chan error)
	go listenAndServe(udpAddrPort500, errChan)
	if err, ok := <-errChan; ok {
		logger.IKELog.Errorln(err)
		return errors.New("IKE service run failed")
	}

	// Port 4500
	errChan = make(chan error)
	go listenAndServe(udpAddrPort4500, errChan)
	if err, ok := <-errChan; ok {
		logger.IKELog.Errorln(err)
		return errors.New("IKE service run failed")
	}

	return nil
}

func listenAndServe(localAddr *net.UDPAddr, errChan chan<- error) {
	listener, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		logger.IKELog.Errorf("listen UDP failed: %+v", err)
		errChan <- errors.New("listenAndServe failed")
		return
	}

	close(errChan)

	data := make([]byte, 65535)

	for {
		n, remoteAddr, err := listener.ReadFromUDP(data)
		if err != nil {
			logger.IKELog.Errorf("readFromUDP failed: %+v", err)
			continue
		}

		forwardData := make([]byte, n)
		copy(forwardData, data[:n])

		go ike.Dispatch(listener, localAddr, remoteAddr, forwardData)
	}
}
