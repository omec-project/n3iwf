// Copyright 2020 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"encoding/binary"
	"fmt"
	"math"
)

const IKE_HEADER_LEN int = 28

// IKEHeader represents the header of an IKE message as defined in RFC 7296, Section 3.1
// Fields are ordered as per the wire format for easier marshaling/unmarshaling.
type IKEHeader struct {
	InitiatorSPI uint64
	ResponderSPI uint64
	MajorVersion uint8
	MinorVersion uint8
	ExchangeType uint8
	Flags        uint8
	MessageID    uint32
	NextPayload  IKEPayloadType
	PayloadBytes []byte
}

// NewHeader creates a new IKEHeader with the provided parameters and sets version to 2.0.
func NewHeader(
	iSPI, rSPI uint64, exchgType uint8,
	response, initiator bool, mId uint32,
	nextPayload IKEPayloadType, payloadBytes []byte,
) *IKEHeader {
	h := &IKEHeader{
		InitiatorSPI: iSPI,
		ResponderSPI: rSPI,
		ExchangeType: exchgType,
		MajorVersion: 2,
		MinorVersion: 0,
		MessageID:    mId,
		NextPayload:  nextPayload,
		PayloadBytes: payloadBytes,
	}
	if response {
		h.Flags |= ResponseBitCheck
	}
	if initiator {
		h.Flags |= InitiatorBitCheck
	}
	return h
}

// Marshal serializes the IKEHeader into a byte slice.
func (h *IKEHeader) Marshal() ([]byte, error) {
	b := make([]byte, IKE_HEADER_LEN)

	binary.BigEndian.PutUint64(b[0:8], h.InitiatorSPI)
	binary.BigEndian.PutUint64(b[8:16], h.ResponderSPI)
	b[16] = byte(h.NextPayload)
	b[17] = (h.MajorVersion << 4) | (h.MinorVersion & 0x0F)
	b[18] = h.ExchangeType
	b[19] = h.Flags
	binary.BigEndian.PutUint32(b[20:24], h.MessageID)

	totalLen := IKE_HEADER_LEN + len(h.PayloadBytes)
	if totalLen > math.MaxUint32 {
		return nil, fmt.Errorf("length exceeds uint32 limit: %d", totalLen)
	}
	binary.BigEndian.PutUint32(b[24:IKE_HEADER_LEN], uint32(totalLen))

	if len(h.PayloadBytes) > 0 {
		b = append(b, h.PayloadBytes...)
	}
	return b, nil
}

// IsResponse returns true if the header is marked as a response.
func (h *IKEHeader) IsResponse() bool {
	return (h.Flags & ResponseBitCheck) != 0
}

// IsInitiator returns true if the header is marked as an initiator.
func (h *IKEHeader) IsInitiator() bool {
	return (h.Flags & InitiatorBitCheck) != 0
}

// ParseHeader parses a byte slice into an IKEHeader struct.
func ParseHeader(b []byte) (*IKEHeader, error) {
	if len(b) < IKE_HEADER_LEN {
		return nil, fmt.Errorf("received broken IKE header")
	}

	totalLen := binary.BigEndian.Uint32(b[24:IKE_HEADER_LEN])
	if totalLen < uint32(IKE_HEADER_LEN) {
		return nil, fmt.Errorf("illegal IKE message length %d < header length %d", totalLen, IKE_HEADER_LEN)
	}

	h := &IKEHeader{
		InitiatorSPI: binary.BigEndian.Uint64(b[:8]),
		ResponderSPI: binary.BigEndian.Uint64(b[8:16]),
		NextPayload:  IKEPayloadType(b[16]),
		MajorVersion: b[17] >> 4,
		MinorVersion: b[17] & 0x0F,
		ExchangeType: b[18],
		Flags:        b[19],
		MessageID:    binary.BigEndian.Uint32(b[20:24]),
		PayloadBytes: b[IKE_HEADER_LEN:],
	}
	return h, nil
}
