// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

// Maximum buffer message length for N3IWF context
const MAX_BUF_MSG_LEN uint32 = 65535

// N3iwfNfInfo holds information about the N3IWF network function
// including its global ID, node name, and supported TA list
type N3iwfNfInfo struct {
	GlobalN3iwfId   GlobalN3iwfId     `yaml:"globalN3iwfId"`
	RanNodeName     string            `yaml:"name,omitempty"`
	SupportedTaList []SupportedTAItem `yaml:"supportedTaList"`
}

// GlobalN3iwfId represents the global identifier for N3IWF
type GlobalN3iwfId struct {
	PlmnId  PlmnId `yaml:"plmnId"`
	N3iwfId uint16 `yaml:"n3iwfId"` // with length 2 bytes
}

// SupportedTAItem represents a supported Tracking Area and its broadcast PLMN list
type SupportedTAItem struct {
	Tac               string              `yaml:"tac"`
	BroadcastPlmnList []BroadcastPlmnItem `yaml:"broadcastPlmnList"`
}

// BroadcastPlmnItem represents a broadcast PLMN and its supported slice list
type BroadcastPlmnItem struct {
	PlmnId              PlmnId             `yaml:"plmnId"`
	TaiSliceSupportList []SliceSupportItem `yaml:"taiSliceSupportList"`
}

// PlmnId represents a Public Land Mobile Network identifier
type PlmnId struct {
	Mcc string `yaml:"mcc"`
	Mnc string `yaml:"mnc"`
}

// SliceSupportItem represents a supported network slice
type SliceSupportItem struct {
	Snssai SnssaiItem `yaml:"snssai"`
}

// SnssaiItem represents a Single Network Slice Selection Assistance Information item
type SnssaiItem struct {
	Sst int32  `yaml:"sst"`
	Sd  string `yaml:"sd,omitempty"`
}

// AmfSctpAddresses holds SCTP address information for AMF
type AmfSctpAddresses struct {
	IpAddresses []string `yaml:"ipList"`
	Port        int      `yaml:"port,omitempty"`
}
