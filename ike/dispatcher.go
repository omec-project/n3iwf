// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package ike

import (
	"net"

	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/ike/handler"
	"github.com/omec-project/n3iwf/ike/message"
	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/n3iwf/util"
)

// Dispatch routes incoming IKE messages to the appropriate handler based on ExchangeType.
// It recovers from panics and logs errors.
func Dispatch(udpConn *net.UDPConn, localAddr, remoteAddr *net.UDPAddr,
	ikeMessage *message.IKEMessage, msg []byte,
	ikeSA *context.IKESecurityAssociation,
) {
	defer util.RecoverWithLog(logger.IKELog)

	if ikeMessage == nil {
		logger.IKELog.Warnln("received nil IKEMessage")
		return
	}

	switch ikeMessage.ExchangeType {
	case message.IKE_SA_INIT:
		handler.HandleIKESAINIT(udpConn, localAddr, remoteAddr, ikeMessage, msg)
	case message.IKE_AUTH:
		handler.HandleIKEAUTH(udpConn, localAddr, remoteAddr, ikeMessage, ikeSA)
	case message.CREATE_CHILD_SA:
		handler.HandleCREATECHILDSA(udpConn, localAddr, remoteAddr, ikeMessage, ikeSA)
	case message.INFORMATIONAL:
		handler.HandleInformational(udpConn, localAddr, remoteAddr, ikeMessage, ikeSA)
	default:
		logger.IKELog.Warnf("unimplemented IKE message type, exchange type: %d", ikeMessage.ExchangeType)
		return
	}
}
