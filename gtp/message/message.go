// SPDX-FileCopyrightText: 2025 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"encoding/hex"
	"errors"

	"github.com/omec-project/n3iwf/logger"
	"github.com/wmnsk/go-gtp/gtpv1/message"
)

// [TS 38.415] 5.5.2 Frame format for the PDU Session user plane protocol
const (
	DL_PDU_SESSION_INFORMATION_TYPE = 0x00
	UL_PDU_SESSION_INFORMATION_TYPE = 0x10
)

// QoSTPDUPacket represents a GTPv1 TPDU packet with QoS parameters.
type QoSTPDUPacket struct {
	tPDU *message.TPDU
	qos  bool
	rqi  bool
	qfi  uint8
}

// GetPayload returns the payload of the TPDU.
func (p *QoSTPDUPacket) GetPayload() []byte {
	if p.tPDU == nil {
		return nil
	}
	return p.tPDU.Payload
}

// GetTEID returns the TEID of the TPDU.
func (p *QoSTPDUPacket) GetTEID() uint32 {
	if p.tPDU == nil {
		return 0
	}
	return p.tPDU.TEID()
}

// GetExtensionHeader returns the extension headers of the TPDU.
func (p *QoSTPDUPacket) GetExtensionHeader() []*message.ExtensionHeader {
	if p.tPDU == nil {
		return nil
	}
	return p.tPDU.ExtensionHeaders
}

// HasQoS returns true if QoS parameters are present.
func (p *QoSTPDUPacket) HasQoS() bool {
	return p.qos
}

// GetQoSParameters returns QFI and RQI values.
func (p *QoSTPDUPacket) GetQoSParameters() (uint8, bool) {
	return p.qfi, p.rqi
}

// Unmarshal parses the TPDU and extracts QoS parameters if present.
func (p *QoSTPDUPacket) Unmarshal(pdu *message.TPDU) error {
	if pdu == nil {
		return errors.New("unmarshal error: nil TPDU")
	}
	p.tPDU = pdu
	if !p.tPDU.HasExtensionHeader() {
		return nil
	}
	return p.unmarshalExtensionHeader()
}

// unmarshalExtensionHeader parses extension headers for QoS parameters.
func (p *QoSTPDUPacket) unmarshalExtensionHeader() error {
	for _, eh := range p.tPDU.ExtensionHeaders {
		if eh.Type == message.ExtHeaderTypePDUSessionContainer {
			if len(eh.Content) < 2 {
				logger.GTPLog.Errorf("extension header too short: got %d bytes", len(eh.Content))
				continue
			}
			p.qos = true
			p.rqi = ((eh.Content[1] >> 6) & 0x1) == 1
			p.qfi = eh.Content[1] & 0x3F
			logger.GTPLog.Debugf("parsed Extension Header: Len=%d, Next Type=%d, Content Dump: %s",
				eh.Length, eh.NextType, hex.Dump(eh.Content))
		} else {
			logger.GTPLog.Warnf("unsupported Extension Header Field Value: %x", eh.Type)
		}
	}
	if !p.qos {
		return errors.New("unmarshalExtensionHeader error: no PDUSessionContainer in ExtensionHeaders")
	}
	return nil
}

// BuildQoSGTPPacket creates a GTP packet with QoS extension header.
func BuildQoSGTPPacket(teid uint32, qfi uint8, payload []byte) ([]byte, error) {
	header := message.NewHeader(0x34, message.MsgTypeTPDU, teid, 0x00, payload).WithExtensionHeaders(
		message.NewExtensionHeader(
			message.ExtHeaderTypePDUSessionContainer,
			[]byte{UL_PDU_SESSION_INFORMATION_TYPE, qfi},
			message.ExtHeaderTypeNoMoreExtensionHeaders,
		),
	)
	b := make([]byte, header.MarshalLen())
	if err := header.MarshalTo(b); err != nil {
		logger.NWuUPLog.Errorf("go-gtp MarshalTo error: %+v", err)
		return nil, err
	}
	return b, nil
}
