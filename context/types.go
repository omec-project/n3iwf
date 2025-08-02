// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

type N3iwfNfInfo struct {
	GlobalN3iwfId   GlobalN3iwfId     `yaml:"globalN3iwfId"`
	RanNodeName     string            `yaml:"name,omitempty"`
	SupportedTaList []SupportedTAItem `yaml:"supportedTaList"`
}

type GlobalN3iwfId struct {
	PlmnId  PlmnId `yaml:"plmnId"`
	N3iwfId uint16 `yaml:"n3iwfId"` // with length 2 bytes
}

type SupportedTAItem struct {
	Tac               string              `yaml:"tac"`
	BroadcastPlmnList []BroadcastPlmnItem `yaml:"broadcastPlmnList"`
}

type BroadcastPlmnItem struct {
	PlmnId              PlmnId             `yaml:"plmnId"`
	TaiSliceSupportList []SliceSupportItem `yaml:"taiSliceSupportList"`
}

type PlmnId struct {
	Mcc string `yaml:"mcc"`
	Mnc string `yaml:"mnc"`
}

type SliceSupportItem struct {
	Snssai SnssaiItem `yaml:"snssai"`
}

type SnssaiItem struct {
	Sst string `yaml:"sst"`
	Sd  string `yaml:"sd,omitempty"`
}

type AmfSctpAddresses struct {
	IpAddresses []string `yaml:"ipList"`
	Port        int      `yaml:"port,omitempty"`
}
