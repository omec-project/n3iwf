// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package xfrm

import (
	"fmt"
	"net"

	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/ike/message"
	"github.com/omec-project/n3iwf/logger"
	"github.com/vishvananda/netlink"
)

type XFRMEncryptionAlgorithmType uint16

func (xfrmEncryptionAlgorithmType XFRMEncryptionAlgorithmType) String() string {
	switch xfrmEncryptionAlgorithmType {
	case message.ENCR_DES:
		return "cbc(des)"
	case message.ENCR_3DES:
		return "cbc(des3_ede)"
	case message.ENCR_CAST:
		return "cbc(cast5)"
	case message.ENCR_BLOWFISH:
		return "cbc(blowfish)"
	case message.ENCR_NULL:
		return "ecb(cipher_null)"
	case message.ENCR_AES_CBC:
		return "cbc(aes)"
	case message.ENCR_AES_CTR:
		return "rfc3686(ctr(aes))"
	default:
		return ""
	}
}

type XFRMIntegrityAlgorithmType uint16

func (xfrmIntegrityAlgorithmType XFRMIntegrityAlgorithmType) String() string {
	switch xfrmIntegrityAlgorithmType {
	case message.AUTH_HMAC_MD5_96:
		return "hmac(md5)"
	case message.AUTH_HMAC_SHA1_96:
		return "hmac(sha1)"
	case message.AUTH_AES_XCBC_96:
		return "xcbc(aes)"
	case message.AUTH_HMAC_SHA2_256_128:
		return "hmac(sha256)"
	default:
		return ""
	}
}

func buildXfrmState(xfrmiId uint32, childSecurityAssociation *context.ChildSecurityAssociation, spi int, src, dst net.IP, encap *netlink.XfrmStateEncap, encryptionKey, integrityKey []byte) *netlink.XfrmState {
	xfrmEncryptionAlgorithm := &netlink.XfrmStateAlgo{
		Name: XFRMEncryptionAlgorithmType(childSecurityAssociation.EncrKInfo.TransformID()).String(),
		Key:  encryptionKey,
	}
	var xfrmIntegrityAlgorithm *netlink.XfrmStateAlgo
	if childSecurityAssociation.IntegKInfo != nil {
		xfrmIntegrityAlgorithm = &netlink.XfrmStateAlgo{
			Name:        XFRMIntegrityAlgorithmType(childSecurityAssociation.IntegKInfo.TransformID()).String(),
			Key:         integrityKey,
			TruncateLen: getTruncateLength(childSecurityAssociation.IntegKInfo.TransformID()),
		}
	}
	return &netlink.XfrmState{
		Src:   src,
		Dst:   dst,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Spi:   spi,
		Ifid:  int(xfrmiId),
		Auth:  xfrmIntegrityAlgorithm,
		Crypt: xfrmEncryptionAlgorithm,
		ESN:   childSecurityAssociation.EsnInfo.GetNeedESN(),
		Encap: encap,
	}
}

func buildXfrmPolicy(xfrmiId uint32, tmpl netlink.XfrmPolicyTmpl, src, dst *net.IPNet, proto uint8, dir netlink.Dir) *netlink.XfrmPolicy {
	return &netlink.XfrmPolicy{
		Src:   src,
		Dst:   dst,
		Proto: netlink.Proto(proto),
		Dir:   dir,
		Ifid:  int(xfrmiId),
		Tmpls: []netlink.XfrmPolicyTmpl{tmpl},
	}
}

func ApplyXFRMRule(n3iwf_is_initiator bool, xfrmiId uint32,
	childSecurityAssociation *context.ChildSecurityAssociation,
) error {
	var err error
	// Direction: {private_network} -> this_server
	var inEncKey, inIntKey, outEncKey, outIntKey []byte
	if n3iwf_is_initiator {
		inEncKey = childSecurityAssociation.ResponderToInitiatorEncryptionKey
		inIntKey = childSecurityAssociation.ResponderToInitiatorIntegrityKey
		outEncKey = childSecurityAssociation.InitiatorToResponderEncryptionKey
		outIntKey = childSecurityAssociation.InitiatorToResponderIntegrityKey
	} else {
		inEncKey = childSecurityAssociation.InitiatorToResponderEncryptionKey
		inIntKey = childSecurityAssociation.InitiatorToResponderIntegrityKey
		outEncKey = childSecurityAssociation.ResponderToInitiatorEncryptionKey
		outIntKey = childSecurityAssociation.ResponderToInitiatorIntegrityKey
	}

	inState := buildXfrmState(xfrmiId, childSecurityAssociation,
		int(childSecurityAssociation.InboundSPI),
		childSecurityAssociation.PeerPublicIPAddr,
		childSecurityAssociation.LocalPublicIPAddr,
		nil, inEncKey, inIntKey)

	if err = netlink.XfrmStateAdd(inState); err != nil {
		return fmt.Errorf("add XFRM state %+v", err)
	}
	childSecurityAssociation.XfrmStateList = append(childSecurityAssociation.XfrmStateList, *inState)

	inTmpl := netlink.XfrmPolicyTmpl{
		Src:   inState.Src,
		Dst:   inState.Dst,
		Proto: inState.Proto,
		Mode:  inState.Mode,
		Spi:   inState.Spi,
	}
	inPolicy := buildXfrmPolicy(xfrmiId, inTmpl,
		&childSecurityAssociation.TrafficSelectorRemote,
		&childSecurityAssociation.TrafficSelectorLocal,
		childSecurityAssociation.SelectedIPProtocol,
		netlink.XFRM_DIR_IN)

	if err = netlink.XfrmPolicyAdd(inPolicy); err != nil {
		return fmt.Errorf("add XFRM policy %+v", err)
	}
	childSecurityAssociation.XfrmPolicyList = append(childSecurityAssociation.XfrmPolicyList, *inPolicy)

	// Direction: this_server -> {private_network}
	var encap *netlink.XfrmStateEncap
	if childSecurityAssociation.EnableEncapsulate {
		logger.IKELog.Debugf("N3IWFPort: %d, NATPort: %d", childSecurityAssociation.N3IWFPort, childSecurityAssociation.NATPort)
		encap = &netlink.XfrmStateEncap{
			Type:    netlink.XFRM_ENCAP_ESPINUDP,
			SrcPort: childSecurityAssociation.N3IWFPort,
			DstPort: childSecurityAssociation.NATPort,
		}
	}
	outState := buildXfrmState(xfrmiId, childSecurityAssociation,
		int(childSecurityAssociation.OutboundSPI),
		childSecurityAssociation.LocalPublicIPAddr,
		childSecurityAssociation.PeerPublicIPAddr,
		encap, outEncKey, outIntKey)

	if encap != nil {
		outState.Encap.SrcPort, outState.Encap.DstPort = outState.Encap.DstPort, outState.Encap.SrcPort
	}

	if err = netlink.XfrmStateAdd(outState); err != nil {
		return fmt.Errorf("add XFRM state %+v", err)
	}
	childSecurityAssociation.XfrmStateList = append(childSecurityAssociation.XfrmStateList, *outState)

	outTmpl := netlink.XfrmPolicyTmpl{
		Src:   outState.Src,
		Dst:   outState.Dst,
		Proto: outState.Proto,
		Mode:  outState.Mode,
		Spi:   outState.Spi,
	}
	outPolicy := buildXfrmPolicy(xfrmiId, outTmpl,
		&childSecurityAssociation.TrafficSelectorLocal,
		&childSecurityAssociation.TrafficSelectorRemote,
		childSecurityAssociation.SelectedIPProtocol,
		netlink.XFRM_DIR_OUT)

	if err = netlink.XfrmPolicyAdd(outPolicy); err != nil {
		return fmt.Errorf("add XFRM policy %+v", err)
	}
	childSecurityAssociation.XfrmPolicyList = append(childSecurityAssociation.XfrmPolicyList, *outPolicy)
	return nil
}

func SetupIPsecXfrmi(xfrmIfaceName, parentIfaceName string, xfrmIfaceId uint32, xfrmIfaceAddr net.IPNet,
) (netlink.Link, error) {
	var (
		xfrmi, parent netlink.Link
		err           error
	)

	if parent, err = netlink.LinkByName(parentIfaceName); err != nil {
		return nil, fmt.Errorf("cannot find parent interface %s by name: %+v", parentIfaceName, err)
	}

	// ip link add <xfrmIfaceName> type xfrm dev <parent.Attrs().Name> if_id <xfrmIfaceId>
	link := &netlink.Xfrmi{
		LinkAttrs: netlink.LinkAttrs{
			Name:        xfrmIfaceName,
			ParentIndex: parent.Attrs().Index,
		},
		Ifid: xfrmIfaceId,
	}

	if err = netlink.LinkAdd(link); err != nil {
		return nil, err
	}

	if xfrmi, err = netlink.LinkByName(xfrmIfaceName); err != nil {
		return nil, err
	}

	logger.IKELog.Debugf("XFRM interface %s index is %d", xfrmIfaceName, xfrmi.Attrs().Index)

	// ip addr add xfrmIfaceAddr dev <xfrmIfaceName>
	linkIPSecAddr := &netlink.Addr{
		IPNet: &xfrmIfaceAddr,
	}

	if err := netlink.AddrAdd(xfrmi, linkIPSecAddr); err != nil {
		return nil, err
	}

	// ip link set <xfrmIfaceName> up
	if err := netlink.LinkSetUp(xfrmi); err != nil {
		return nil, err
	}

	return xfrmi, nil
}

func getTruncateLength(transformID uint16) int {
	switch transformID {
	case message.AUTH_HMAC_MD5_96:
		return 96
	case message.AUTH_HMAC_SHA1_96:
		return 96
	case message.AUTH_HMAC_SHA2_256_128:
		return 128
	default:
		return 96
	}
}
