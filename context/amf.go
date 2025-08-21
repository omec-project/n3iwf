// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"bytes"
	"fmt"

	"git.cs.nctu.edu.tw/calee/sctp"
	"github.com/omec-project/aper"
	"github.com/omec-project/ngap/ngapConvert"
	"github.com/omec-project/ngap/ngapType"
)

// N3IWFAMF represents an AMF context for N3IWF
// Holds SCTP connection, AMF info, and UE associations
type N3IWFAMF struct {
	SCTPAddr              string
	SCTPConn              *sctp.SCTPConn
	AMFName               *ngapType.AMFName
	ServedGUAMIList       *ngapType.ServedGUAMIList
	RelativeAMFCapacity   *ngapType.RelativeAMFCapacity
	PLMNSupportList       *ngapType.PLMNSupportList
	AMFTNLAssociationList map[string]*AMFTNLAssociationItem // v4+v6 as key
	// Overload related
	AMFOverloadContent *AMFOverloadContent
	// Relative Context
	N3iwfRanUeList map[int64]RanUe // ranUeNgapId as key
}

// AMFTNLAssociationItem holds TNL association info
type AMFTNLAssociationItem struct {
	Ipv4                   string
	Ipv6                   string
	TNLAssociationUsage    *ngapType.TNLAssociationUsage
	TNLAddressWeightFactor *int64
}

// AMFOverloadContent holds overload info for AMF
type AMFOverloadContent struct {
	Action     *ngapType.OverloadAction
	TrafficInd *int64
	NSSAIList  []SliceOverloadItem
}

// SliceOverloadItem holds overload info for a slice
type SliceOverloadItem struct {
	SNssaiList []ngapType.SNSSAI
	Action     *ngapType.OverloadAction
	TrafficInd *int64
}

// init initializes the N3IWFAMF struct
func (amf *N3IWFAMF) init(sctpAddr string, conn *sctp.SCTPConn) {
	amf.SCTPAddr = sctpAddr
	amf.SCTPConn = conn
	amf.AMFTNLAssociationList = make(map[string]*AMFTNLAssociationItem)
	amf.N3iwfRanUeList = make(map[int64]RanUe)
}

// FindUeByAmfUeNgapID returns RanUe by AmfUeNgapId
func (amf *N3IWFAMF) FindUeByAmfUeNgapID(id int64) RanUe {
	for _, ranUe := range amf.N3iwfRanUeList {
		if ranUe.GetSharedCtx().AmfUeNgapId == id {
			return ranUe
		}
	}
	return nil
}

// RemoveAllRelatedUe removes all UEs related to this AMF
func (amf *N3IWFAMF) RemoveAllRelatedUe() error {
	for id, ranUe := range amf.N3iwfRanUeList {
		if err := ranUe.Remove(); err != nil {
			return fmt.Errorf("RemoveAllRelatedUe error: %+v", err)
		}
		delete(amf.N3iwfRanUeList, id)
	}
	return nil
}

// tnlAssocKey generates a unique key for TNL association map
func tnlAssocKey(v4, v6 string) string {
	return v4 + ":" + v6
}

// AddAMFTNLAssociationItem adds a TNL association item
func (amf *N3IWFAMF) AddAMFTNLAssociationItem(info ngapType.CPTransportLayerInformation) *AMFTNLAssociationItem {
	item := &AMFTNLAssociationItem{}
	item.Ipv4, item.Ipv6 = ngapConvert.IPAddressToString(*info.EndpointIPAddress)
	key := tnlAssocKey(item.Ipv4, item.Ipv6)
	amf.AMFTNLAssociationList[key] = item
	return item
}

// FindAMFTNLAssociationItem finds a TNL association item
func (amf *N3IWFAMF) FindAMFTNLAssociationItem(info ngapType.CPTransportLayerInformation) *AMFTNLAssociationItem {
	v4, v6 := ngapConvert.IPAddressToString(*info.EndpointIPAddress)
	key := tnlAssocKey(v4, v6)
	return amf.AMFTNLAssociationList[key]
}

// DeleteAMFTNLAssociationItem deletes a TNL association item
func (amf *N3IWFAMF) DeleteAMFTNLAssociationItem(info ngapType.CPTransportLayerInformation) {
	v4, v6 := ngapConvert.IPAddressToString(*info.EndpointIPAddress)
	key := tnlAssocKey(v4, v6)
	delete(amf.AMFTNLAssociationList, key)
}

// StartOverload sets overload content for AMF
func (amf *N3IWFAMF) StartOverload(
	resp *ngapType.OverloadResponse, trafloadInd *ngapType.TrafficLoadReductionIndication,
	nssai *ngapType.OverloadStartNSSAIList,
) *AMFOverloadContent {
	if resp == nil && trafloadInd == nil && nssai == nil {
		return nil
	}
	content := AMFOverloadContent{}
	if resp != nil {
		content.Action = resp.OverloadAction
	}
	if trafloadInd != nil {
		content.TrafficInd = &trafloadInd.Value
	}
	if nssai != nil {
		for _, item := range nssai.List {
			sliceItem := SliceOverloadItem{}
			for _, item2 := range item.SliceOverloadList.List {
				sliceItem.SNssaiList = append(sliceItem.SNssaiList, item2.SNSSAI)
			}
			if item.SliceOverloadResponse != nil {
				sliceItem.Action = item.SliceOverloadResponse.OverloadAction
			}
			if item.SliceTrafficLoadReductionIndication != nil {
				sliceItem.TrafficInd = &item.SliceTrafficLoadReductionIndication.Value
			}
			content.NSSAIList = append(content.NSSAIList, sliceItem)
		}
	}
	amf.AMFOverloadContent = &content
	return amf.AMFOverloadContent
}

// StopOverload clears overload content
func (amf *N3IWFAMF) StopOverload() {
	amf.AMFOverloadContent = nil
}

// FindAvailableAMFByCompareGUAMI compares incoming GUAMI with AMF served GUAMI
// Returns true if AMF is available for UE
func (amf *N3IWFAMF) FindAvailableAMFByCompareGUAMI(ueSpecifiedGUAMI *ngapType.GUAMI) bool {
	for _, amfServedGUAMI := range amf.ServedGUAMIList.List {
		codedAMFServedGUAMI, err := aper.MarshalWithParams(&amfServedGUAMI.GUAMI, "valueExt")
		if err != nil {
			return false
		}
		codedUESpecifiedGUAMI, err := aper.MarshalWithParams(ueSpecifiedGUAMI, "valueExt")
		if err != nil {
			return false
		}
		if bytes.Equal(codedAMFServedGUAMI, codedUESpecifiedGUAMI) {
			return true
		}
	}
	return false
}

// FindAvailableAMFByCompareSelectedPLMNId compares incoming PLMNId with AMF supported PLMNId
// Returns true if AMF supports the selected PLMNId
func (amf *N3IWFAMF) FindAvailableAMFByCompareSelectedPLMNId(ueSpecifiedSelectedPLMNId *ngapType.PLMNIdentity) bool {
	for _, amfServedPLMNId := range amf.PLMNSupportList.List {
		if bytes.Equal(amfServedPLMNId.PLMNIdentity.Value, ueSpecifiedSelectedPLMNId.Value) {
			return true
		}
	}
	return false
}
