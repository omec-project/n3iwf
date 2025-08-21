// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"fmt"
	"math"
	"net"

	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/ike/message"
	"github.com/omec-project/n3iwf/ike/security"
	"github.com/omec-project/n3iwf/logger"
)

func SendIKEMessageToUE(udpConn *net.UDPConn, srcAddr, dstAddr *net.UDPAddr, ikeMsg *message.IKEMessage, ikeSAKey *security.IKESAKey) error {
	logger.IKELog.Debugln("send IKE ikeMsg to UE")
	logger.IKELog.Debugln("encoding")

	pkt, err := EncodeEncrypt(ikeMsg, ikeSAKey, message.Role_Responder)
	if err != nil {
		return fmt.Errorf("SendIKEMessageToUE: %w", err)
	}

	// RFC 7296 section 3.1: prepend 4 zero bytes for UDP port 4500
	if srcAddr.Port == 4500 {
		pkt = append(make([]byte, 4), pkt...)
	}

	logger.IKELog.Debugln("sending")
	n, err := udpConn.WriteToUDP(pkt, dstAddr)
	if err != nil {
		return fmt.Errorf("SendIKEMessageToUE: %w", err)
	}
	if n != len(pkt) {
		return fmt.Errorf("not all of the data is sent. Total length: %d. Sent: %d", len(pkt), n)
	}
	return nil
}

// SendUEInformationExchange builds and sends an IKE informational ikeMsg to UE
func SendUEInformationExchange(
	ikeSA *context.IKESecurityAssociation,
	ikeSAKey *security.IKESAKey,
	payload *message.IKEPayloadContainer,
	initiator, response bool,
	messageID uint32,
	conn *net.UDPConn,
	ueAddr, n3iwfAddr *net.UDPAddr,
) {
	msg := message.NewMessage(
		ikeSA.RemoteSPI, ikeSA.LocalSPI,
		message.INFORMATIONAL, response, initiator, messageID, nil,
	)
	if payload != nil && len(*payload) > 0 {
		msg.Payloads = append(msg.Payloads, *payload...)
	}
	if err := SendIKEMessageToUE(conn, n3iwfAddr, ueAddr, msg, ikeSAKey); err != nil {
		logger.IKELog.Errorf("SendUEInformationExchange err: %+v", err)
	}
}

// SendIKEDeleteRequest sends an IKE SA delete request to UE
func SendIKEDeleteRequest(n3iwfCtx *context.N3IWFContext, localSPI uint64) {
	ikeUe, ok := n3iwfCtx.IkeUePoolLoad(localSPI)
	if !ok {
		logger.IKELog.Errorf("cannot get IkeUE from SPI: %+v", localSPI)
		return
	}
	var deletePayload message.IKEPayloadContainer
	deletePayload.BuildDeletePayload(message.TypeIKE, 0, 0, nil)
	SendUEInformationExchange(
		ikeUe.N3IWFIKESecurityAssociation,
		ikeUe.N3IWFIKESecurityAssociation.IKESAKey,
		&deletePayload,
		false, false,
		ikeUe.N3IWFIKESecurityAssociation.ResponderMessageID,
		ikeUe.IKEConnection.Conn,
		ikeUe.IKEConnection.UEAddr,
		ikeUe.IKEConnection.N3IWFAddr,
	)
}

// SendChildSADeleteRequest deletes Child SAs for given release list and sends delete request
func SendChildSADeleteRequest(ikeUe *context.N3IWFIkeUe, releaseList []int64) {
	var deleteSPIs []uint32
	spiLen := uint16(0)
	for _, releaseID := range releaseList {
		for _, childSA := range ikeUe.N3IWFChildSecurityAssociation {
			if len(childSA.PDUSessionIds) == 0 || childSA.PDUSessionIds[0] != releaseID {
				continue
			}
			spi := childSA.XfrmStateList[0].Spi
			if spi < 0 || spi > math.MaxUint32 {
				logger.IKELog.Errorf("SendChildSADeleteRequest spi out of uint32 range: %d", spi)
				continue
			}
			deleteSPIs = append(deleteSPIs, uint32(spi))
			spiLen++
			if err := ikeUe.DeleteChildSA(childSA); err != nil {
				logger.IKELog.Errorf("delete Child SA error: %+v", err)
			}
		}
	}
	if spiLen == 0 {
		logger.IKELog.Debugln("No Child SAs to delete for given release list")
		return
	}
	var deletePayload message.IKEPayloadContainer
	deletePayload.BuildDeletePayload(message.TypeESP, 4, spiLen, deleteSPIs)
	SendUEInformationExchange(
		ikeUe.N3IWFIKESecurityAssociation,
		ikeUe.N3IWFIKESecurityAssociation.IKESAKey,
		&deletePayload,
		false, false,
		ikeUe.N3IWFIKESecurityAssociation.ResponderMessageID,
		ikeUe.IKEConnection.Conn,
		ikeUe.IKEConnection.UEAddr,
		ikeUe.IKEConnection.N3IWFAddr,
	)
}
