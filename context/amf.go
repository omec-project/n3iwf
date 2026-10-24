// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/ishidawataru/sctp"
	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/ngap/v2/aper"
	"github.com/omec-project/ngap/v2/ngapConvert"
	"github.com/omec-project/ngap/v2/ngapType"
)

// N3IWFAMF represents an AMF context for N3IWF
// Holds SCTP connection, AMF info, and UE associations
type N3IWFAMF struct {
	SCTPConn              *sctp.SCTPConn
	AMFName               *ngapType.AMFName
	ServedGUAMIList       *ngapType.ServedGUAMIList
	RelativeAMFCapacity   *ngapType.RelativeAMFCapacity
	PLMNSupportList       *ngapType.PLMNSupportList
	AMFTNLAssociationList map[string]*AMFTNLAssociationItem
	AMFOverloadContent    *AMFOverloadContent
	ueListMu              sync.RWMutex // guards N3iwfRanUeList
	N3iwfRanUeList        map[int64]RanUe
	SCTPAddr              string
	sendOnce              sync.Once
	sendQ                 chan []byte
}

// amfSendQueueLen bounds the packets waiting for QueueSend's writer
const amfSendQueueLen = 128

// QueueSend writes pkt to the AMF from a writer goroutine of its own, so that a caller in an
// event loop never blocks on a stalled SCTP socket (writes have no deadline). One goroutine
// and at most amfSendQueueLen packets exist per AMF; beyond that pkt is dropped and QueueSend
// returns false. The writer stops at the first write error, for instance once the connection
// is closed, and later packets are dropped. Use it only for best-effort notifications that
// need not be ordered with synchronous sends.
func (amf *N3IWFAMF) QueueSend(pkt []byte) bool {
	amf.sendOnce.Do(func() {
		amf.sendQ = make(chan []byte, amfSendQueueLen)
		go func() {
			for p := range amf.sendQ {
				if _, err := amf.SCTPConn.Write(p); err != nil {
					logger.NgapLog.Errorf("write to SCTP socket failed, stopping AMF[%s] writer: %+v", amf.SCTPAddr, err)
					return
				}
			}
		}()
	})
	select {
	case amf.sendQ <- pkt:
		return true
	default:
		logger.NgapLog.Warnf("AMF[%s] send queue full, dropping packet", amf.SCTPAddr)
		return false
	}
}

// AMFTNLAssociationItem holds TNL association info
type AMFTNLAssociationItem struct {
	TNLAssociationUsage    *ngapType.TNLAssociationUsage
	TNLAddressWeightFactor *int64
	Ipv4                   string
	Ipv6                   string
}

// AMFOverloadContent holds overload info for AMF
type AMFOverloadContent struct {
	Action     *ngapType.OverloadAction
	TrafficInd *int64
	NSSAIList  []SliceOverloadItem
}

// SliceOverloadItem holds overload info for a slice
type SliceOverloadItem struct {
	Action     *ngapType.OverloadAction
	TrafficInd *int64
	SNssaiList []ngapType.SNSSAI
}

// init initializes the N3IWFAMF struct
func (amf *N3IWFAMF) init(sctpAddr string, conn *sctp.SCTPConn) {
	amf.SCTPAddr = sctpAddr
	amf.SCTPConn = conn
	amf.AMFTNLAssociationList = make(map[string]*AMFTNLAssociationItem)
	amf.N3iwfRanUeList = make(map[int64]RanUe)
}

// AttachRanUe registers a RAN UE as served through this AMF
func (amf *N3IWFAMF) AttachRanUe(ranUe RanUe) {
	amf.ueListMu.Lock()
	defer amf.ueListMu.Unlock()
	amf.N3iwfRanUeList[ranUe.GetSharedCtx().RanUeNgapId] = ranUe
}

// DetachRanUe removes a RAN UE from this AMF
func (amf *N3IWFAMF) DetachRanUe(ranUeNgapId int64) {
	amf.ueListMu.Lock()
	defer amf.ueListMu.Unlock()
	delete(amf.N3iwfRanUeList, ranUeNgapId)
}

// RelatedUes returns a snapshot of the UEs served through this AMF
func (amf *N3IWFAMF) RelatedUes() []RanUe {
	amf.ueListMu.RLock()
	defer amf.ueListMu.RUnlock()
	ues := make([]RanUe, 0, len(amf.N3iwfRanUeList))
	for _, ranUe := range amf.N3iwfRanUeList {
		ues = append(ues, ranUe)
	}
	return ues
}

// FindUeByAmfUeNgapID returns RanUe by AmfUeNgapId. UEs that have not been assigned an ID yet
// never match.
func (amf *N3IWFAMF) FindUeByAmfUeNgapID(id int64) RanUe {
	if id == AmfUeNgapIdUnspecified {
		return nil
	}
	// Searched in place under the read lock: a snapshot per lookup would make bulk releases
	// by AMF UE NGAP ID quadratic in allocations.
	amf.ueListMu.RLock()
	defer amf.ueListMu.RUnlock()
	for _, ranUe := range amf.N3iwfRanUeList {
		if ranUe.GetSharedCtx().AmfUeNgapId == id {
			return ranUe
		}
	}
	return nil
}

// RemoveAllRelatedUe removes all UEs related to this AMF
// A failure to remove one UE does not stop the removal of the others.
func (amf *N3IWFAMF) RemoveAllRelatedUe() error {
	var errs []error
	for _, ranUe := range amf.RelatedUes() {
		if err := ranUe.Remove(); err != nil {
			errs = append(errs, fmt.Errorf("remove RAN UE %d: %w", ranUe.GetSharedCtx().RanUeNgapId, err))
		}
		amf.DetachRanUe(ranUe.GetSharedCtx().RanUeNgapId)
	}
	return errors.Join(errs...)
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
