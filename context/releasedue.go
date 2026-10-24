// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package context

import "time"

const (
	// releasedRanUeTTL is how long the identifiers of a locally released RAN UE are kept so
	// that the AMF's UE Context Release Command for it can still be acknowledged
	releasedRanUeTTL = 60 * time.Second
	// maxReleasedRanUe bounds the number of retained entries
	maxReleasedRanUe = 1024
)

// releasedRanUe is the lightweight state kept for a RAN UE that was released locally after
// a UE Context Release Request had been sent to the AMF
type releasedRanUe struct {
	ue      *N3IWFRanUe
	expires time.Time
}

// RememberReleasedRanUe keeps just enough state about ranUe, which is being removed locally,
// to build the UE Context Release Complete for the AMF's UE Context Release Command that
// answers the UE Context Release Request already sent. Resources (TEIDs, IKE mappings, TCP
// connection) are not retained, only the identifiers, the AMF and the location. Entries
// expire after releasedRanUeTTL and at most maxReleasedRanUe are kept. A UE that has no AMF UE
// NGAP ID yet is retained too: the AMF already knows its RAN UE NGAP ID from the Initial UE
// Message, and a Release Command carrying the ID pair supplies the missing AMF UE NGAP ID.
func (n3iwfCtx *N3IWFContext) RememberReleasedRanUe(ranUe RanUe) {
	shared := ranUe.GetSharedCtx()

	stub := &N3IWFRanUe{
		RanUeSharedCtx: RanUeSharedCtx{
			PduSessionList: make(map[int64]*PDUSession),
			N3iwfCtx:       n3iwfCtx,
			AMF:            shared.AMF,
			IPAddrv4:       shared.IPAddrv4,
			IPAddrv6:       shared.IPAddrv6,
			AmfUeNgapId:    shared.AmfUeNgapId,
			RanUeNgapId:    shared.RanUeNgapId,
			PortNumber:     shared.PortNumber,
			UeCtxRelState:  UeCtxRelStateOngoing,
		},
	}

	n3iwfCtx.releasedRanUeMu.Lock()
	defer n3iwfCtx.releasedRanUeMu.Unlock()

	if n3iwfCtx.releasedRanUe == nil {
		n3iwfCtx.releasedRanUe = make(map[int64]releasedRanUe)
	}
	now := time.Now()
	for id, entry := range n3iwfCtx.releasedRanUe {
		if now.After(entry.expires) {
			delete(n3iwfCtx.releasedRanUe, id)
		}
	}
	if len(n3iwfCtx.releasedRanUe) >= maxReleasedRanUe {
		// Evict the entry closest to expiry
		var oldestId int64
		var oldest time.Time
		first := true
		for id, entry := range n3iwfCtx.releasedRanUe {
			if first || entry.expires.Before(oldest) {
				oldestId, oldest, first = id, entry.expires, false
			}
		}
		delete(n3iwfCtx.releasedRanUe, oldestId)
	}
	n3iwfCtx.releasedRanUe[stub.RanUeNgapId] = releasedRanUe{ue: stub, expires: now.Add(releasedRanUeTTL)}
}

// TakeReleasedRanUeByIdPair returns and forgets the retained state for the released RAN UE that
// amf refers to by a RAN UE NGAP ID / AMF UE NGAP ID pair. The entry must belong to amf, and if
// the AMF UE NGAP ID was not known when the UE was released it is filled in from the pair.
func (n3iwfCtx *N3IWFContext) TakeReleasedRanUeByIdPair(
	amf *N3IWFAMF, ranUeNgapId, amfUeNgapId int64,
) *N3IWFRanUe {
	ue := n3iwfCtx.takeReleasedRanUe(func(id int64, ue *N3IWFRanUe) bool {
		return ue.AMF == amf && id == ranUeNgapId &&
			(ue.AmfUeNgapId == AmfUeNgapIdUnspecified || ue.AmfUeNgapId == amfUeNgapId)
	})
	if ue != nil {
		ue.AmfUeNgapId = amfUeNgapId
	}
	return ue
}

// TakeReleasedRanUeByAmfUeNgapId returns and forgets the retained state for the released RAN UE
// that amf refers to by AMF UE NGAP ID. AMF UE NGAP IDs are only unique within one AMF, so the
// entry must belong to amf. Entries whose AMF UE NGAP ID is still unknown never match. Those
// entries are resolved only through the ID pair (TakeReleasedRanUeByIdPair).
func (n3iwfCtx *N3IWFContext) TakeReleasedRanUeByAmfUeNgapId(amf *N3IWFAMF, amfUeNgapId int64) *N3IWFRanUe {
	return n3iwfCtx.takeReleasedRanUe(func(_ int64, ue *N3IWFRanUe) bool {
		return ue.AMF == amf && ue.AmfUeNgapId != AmfUeNgapIdUnspecified && ue.AmfUeNgapId == amfUeNgapId
	})
}

// TakeReleasedRanUeAwaitingAmfUeNgapId returns and forgets the retained state for a RAN UE that
// was released locally before the AMF had assigned it an AMF UE NGAP ID, when amf now sends a
// message naming ranUeNgapId. It returns nil if there is no such entry, so it returns a given
// entry at most once and the caller reports the unknown RAN UE NGAP ID to the AMF exactly once.
// The entry is forgotten because the node that reports an unknown local AP ID and its peer both
// release locally (TS 38.413 clause 10.6), so no Release Command is expected for it afterwards.
// Entries that already carry an AMF UE NGAP ID are left alone: a Release Request was sent for
// them and the AMF's Release Command is still to be acknowledged.
func (n3iwfCtx *N3IWFContext) TakeReleasedRanUeAwaitingAmfUeNgapId(amf *N3IWFAMF, ranUeNgapId int64) *N3IWFRanUe {
	return n3iwfCtx.takeReleasedRanUe(func(id int64, ue *N3IWFRanUe) bool {
		return ue.AMF == amf && id == ranUeNgapId && ue.AmfUeNgapId == AmfUeNgapIdUnspecified
	})
}

func (n3iwfCtx *N3IWFContext) takeReleasedRanUe(match func(int64, *N3IWFRanUe) bool) *N3IWFRanUe {
	n3iwfCtx.releasedRanUeMu.Lock()
	defer n3iwfCtx.releasedRanUeMu.Unlock()

	now := time.Now()
	for id, entry := range n3iwfCtx.releasedRanUe {
		if now.After(entry.expires) {
			delete(n3iwfCtx.releasedRanUe, id)
			continue
		}
		if match(id, entry.ue) {
			delete(n3iwfCtx.releasedRanUe, id)
			return entry.ue
		}
	}
	return nil
}

// PurgeReleasedRanUesOfAmf forgets every retained released RAN UE that belongs to amf. NG Reset
// of the whole NG interface (TS 38.413 clause 8.7.4) removes all UE-associated logical
// NG-connections, so no Release Command can legitimately refer to the retained entries anymore
// and the identifiers may be reused by the AMF.
func (n3iwfCtx *N3IWFContext) PurgeReleasedRanUesOfAmf(amf *N3IWFAMF) {
	n3iwfCtx.purgeReleasedRanUe(func(_ int64, ue *N3IWFRanUe) bool {
		return ue.AMF == amf
	})
}

// PurgeReleasedRanUe forgets the retained released RAN UE of amf that a UE-associated logical
// NG-connection item of a partial NG Reset names. Like the live UE lookup, the RAN UE NGAP ID
// is used when present, otherwise the AMF UE NGAP ID. When both are present, an entry whose AMF UE
// NGAP ID is known must also match the AMF UE NGAP ID.
func (n3iwfCtx *N3IWFContext) PurgeReleasedRanUe(amf *N3IWFAMF, ranUeNgapId, amfUeNgapId *int64) {
	n3iwfCtx.purgeReleasedRanUe(func(id int64, ue *N3IWFRanUe) bool {
		if ue.AMF != amf {
			return false
		}
		if ranUeNgapId != nil {
			return id == *ranUeNgapId &&
				(amfUeNgapId == nil || ue.AmfUeNgapId == AmfUeNgapIdUnspecified || ue.AmfUeNgapId == *amfUeNgapId)
		}
		return amfUeNgapId != nil && ue.AmfUeNgapId != AmfUeNgapIdUnspecified && ue.AmfUeNgapId == *amfUeNgapId
	})
}

func (n3iwfCtx *N3IWFContext) purgeReleasedRanUe(match func(int64, *N3IWFRanUe) bool) {
	n3iwfCtx.releasedRanUeMu.Lock()
	defer n3iwfCtx.releasedRanUeMu.Unlock()

	for id, entry := range n3iwfCtx.releasedRanUe {
		if match(id, entry.ue) {
			delete(n3iwfCtx.releasedRanUe, id)
		}
	}
}
