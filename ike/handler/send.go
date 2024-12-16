// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"net"

	ike_message "github.com/omec-project/n3iwf/ike/message"
	"github.com/omec-project/n3iwf/logger"
)

func SendIKEMessageToUE(udpConn *net.UDPConn, srcAddr, dstAddr *net.UDPAddr, message *ike_message.IKEMessage) {
	logger.IKELog.Debugln("send IKE message to UE")
	logger.IKELog.Debugln("encoding...")
	pkt, err := message.Encode()
	if err != nil {
		logger.IKELog.Errorln(err)
		return
	}
	// As specified in RFC 7296 section 3.1, the IKE message send from/to UDP port 4500
	// should prepend a 4 bytes zero
	if srcAddr.Port == 4500 {
		prependZero := make([]byte, 4)
		pkt = append(prependZero, pkt...)
	}

	logger.IKELog.Debugln("sending...")
	n, err := udpConn.WriteToUDP(pkt, dstAddr)
	if err != nil {
		logger.IKELog.Error(err)
		return
	}
	if n != len(pkt) {
		logger.IKELog.Errorf("not all of the data is sent. Total length: %d. Sent: %d", len(pkt), n)
		return
	}
}
