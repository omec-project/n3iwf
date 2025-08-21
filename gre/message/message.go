// SPDX-FileCopyrightText: 2025 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"encoding/binary"
	"errors"
)

// [TS 24.502] 9.3.3 GRE encapsulated user data packet
const (
	GREHeaderFieldLength    = 8
	GREHeaderKeyFieldLength = 4
)

// Ethertypes Specified by the IETF
const (
	IPv4 uint16 = 0x0800
	IPv6 uint16 = 0x86DD
)

// GREPacket represents a GRE encapsulated user data packet as per TS 24.502 9.3.3
// Fields are private to enforce encapsulation; use methods to access or modify.
type GREPacket struct {
	flags        uint8
	version      uint8
	protocolType uint16
	key          uint32
	payload      []byte
}

// Marshal serializes the GREPacket into a byte slice.
func (p *GREPacket) Marshal() []byte {
	packet := make([]byte, GREHeaderFieldLength+len(p.payload))

	packet[0] = p.flags
	packet[1] = p.version
	binary.BigEndian.PutUint16(packet[2:4], p.protocolType)
	binary.BigEndian.PutUint32(packet[4:8], p.key)
	copy(packet[GREHeaderFieldLength:], p.payload)
	return packet
}

// Unmarshal parses a byte slice into the GREPacket fields.
// Returns error if input is too short.
func (p *GREPacket) Unmarshal(b []byte) error {
	if len(b) < 4 {
		return ErrInvalidPacketLength
	}
	p.flags = b[0]
	p.version = b[1]
	p.protocolType = binary.BigEndian.Uint16(b[2:4])

	offset := 4

	if p.GetKeyFlag() {
		if len(b) < offset+GREHeaderKeyFieldLength {
			return ErrInvalidPacketLength
		}
		p.key = binary.BigEndian.Uint32(b[offset : offset+GREHeaderKeyFieldLength])
		offset += GREHeaderKeyFieldLength
	} else {
		p.key = 0
	}

	p.payload = b[offset:]
	return nil
}

// SetPayload sets the payload and protocol type for the GREPacket.
func (p *GREPacket) SetPayload(payload []byte, protocolType uint16) {
	p.payload = payload
	p.protocolType = protocolType
}

// GetPayload returns the payload and protocol type.
func (p *GREPacket) GetPayload() ([]byte, uint16) {
	return p.payload, p.protocolType
}

// setKeyFlag sets the Key Present flag in the GRE header.
func (p *GREPacket) setKeyFlag() {
	p.flags |= 0x20
}

// GetKeyFlag returns true if the Key Present flag is set.
func (p *GREPacket) GetKeyFlag() bool {
	return (p.flags & 0x20) != 0
}

// setQFI sets the QFI value in the key field.
func (p *GREPacket) setQFI(qfi uint8) {
	p.key = (p.key &^ (0x3F << 24)) | ((uint32(qfi) & 0x3F) << 24)
}

// setRQI sets the RQI bit in the key field.
func (p *GREPacket) setRQI(rqi bool) {
	if rqi {
		p.key |= 0x80
	} else {
		p.key &^= 0x80
	}
}

// GetQFI returns the QFI value from the key field.
func (p *GREPacket) GetQFI() uint8 {
	return uint8((p.key >> 24) & 0x3F)
}

// GetRQI returns true if the RQI bit is set in the key field.
func (p *GREPacket) GetRQI() bool {
	return (p.key & 0x80) != 0
}

// GetKeyField returns the key field value.
func (p *GREPacket) GetKeyField() uint32 {
	return p.key
}

// SetQoS sets the QFI and RQI values and marks the Key Present flag.
func (p *GREPacket) SetQoS(qfi uint8, rqi bool) {
	p.setQFI(qfi)
	p.setRQI(rqi)
	p.setKeyFlag()
}

// ErrInvalidPacketLength is returned when the input packet is too short.
var ErrInvalidPacketLength = errors.New("invalid GRE packet length")
