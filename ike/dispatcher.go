// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package ike

import (
	"net"

	"github.com/omec-project/n3iwf/ike/handler"
	ike_message "github.com/omec-project/n3iwf/ike/message"
	"github.com/omec-project/n3iwf/logger"
)

func Dispatch(udpConn *net.UDPConn, localAddr, remoteAddr *net.UDPAddr, msg []byte) {
	// As specified in RFC 7296 section 3.1, the IKE message send from/to UDP port 4500
	// should prepend a 4 bytes zero
	if localAddr.Port == 4500 {
		for i := 0; i < 4; i++ {
			if msg[i] != 0 {
				logger.IKELog.Warnln(
					"received an IKE packet that does not prepend 4 bytes zero from UDP port 4500," +
						" this packet may be the UDP encapsulated ESP. The packet will not be handled")
				return
			}
		}
		msg = msg[4:]
	}

	ikeMessage := new(ike_message.IKEMessage)

	err := ikeMessage.Decode(msg)
	if err != nil {
		logger.IKELog.Error(err)
		return
	}

	switch ikeMessage.ExchangeType {
	case ike_message.IKE_SA_INIT:
		handler.HandleIKESAINIT(udpConn, localAddr, remoteAddr, ikeMessage)
	case ike_message.IKE_AUTH:
		handler.HandleIKEAUTH(udpConn, localAddr, remoteAddr, ikeMessage)
	case ike_message.CREATE_CHILD_SA:
		handler.HandleCREATECHILDSA(udpConn, localAddr, remoteAddr, ikeMessage)
	default:
		logger.IKELog.Warnf("unimplemented IKE message type, exchange type: %d", ikeMessage.ExchangeType)
	}
}
