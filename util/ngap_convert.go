// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/ngap/aper"
	"github.com/omec-project/ngap/ngapType"
)

// PlmnIdToNgap converts a PlmnId to NGAP PLMNIdentity format.
func PlmnIdToNgap(plmnId context.PlmnId) (ngapPlmnId ngapType.PLMNIdentity) {
	mcc := plmnId.Mcc
	mnc := plmnId.Mnc
	var hexString string
	if len(mnc) == 2 {
		// 2-digit MNC: use 'f' as filler
		hexString = string(mcc[1]) + string(mcc[0]) + "f" + string(mcc[2]) + string(mnc[1]) + string(mnc[0])
	} else {
		// 3-digit MNC
		hexString = string(mcc[1]) + string(mcc[0]) + string(mnc[0]) + string(mcc[2]) + string(mnc[2]) + string(mnc[1])
	}
	var err error
	ngapPlmnId.Value, err = hex.DecodeString(hexString)
	if err != nil {
		logger.UtilLog.Errorf("decode string error: %+v", err)
	}
	return
}

// N3iwfIdToNgap converts a uint16 N3IWF ID to NGAP BitString format.
func N3iwfIdToNgap(n3iwfId uint16) (ngapN3iwfId *aper.BitString) {
	ngapN3iwfId = &aper.BitString{
		Bytes:     make([]byte, 2),
		BitLength: 16,
	}
	binary.BigEndian.PutUint16(ngapN3iwfId.Bytes, n3iwfId)
	return
}
