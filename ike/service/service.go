// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"syscall"

	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/ike"
	"github.com/omec-project/n3iwf/ike/handler"
	"github.com/omec-project/n3iwf/ike/message"
	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/n3iwf/util"
)

const (
	RECEIVE_IKEPACKET_CHANNEL_LEN = 512
	RECEIVE_IKEEVENT_CHANNEL_LEN  = 512
	DEFAULT_IKE_PORT              = 500
	DEFAULT_NATT_PORT             = 4500
)

// EspHandler defines a function to handle ESP packets
type EspHandler func(srcIP, dstIP *net.UDPAddr, espPkt []byte) error

// Run starts the IKE and NAT-T services and event handler
func Run(n3iwfCtx *context.N3IWFContext, wg *sync.WaitGroup) error {
	ip := n3iwfCtx.IkeBindAddress
	n3iwfCtx.IkeServer = &context.IkeServer{
		Listener:    make(map[int]*net.UDPConn),
		RcvIkePktCh: make(chan context.IkeReceivePacket, RECEIVE_IKEPACKET_CHANNEL_LEN),
		RcvEventCh:  make(chan context.IkeEvt, RECEIVE_IKEEVENT_CHANNEL_LEN),
		StopServer:  make(chan struct{}),
	}

	ikeAddrPort, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, DEFAULT_IKE_PORT))
	if err != nil {
		logger.IKELog.Errorf("resolve UDP address failed: %+v", err)
		return fmt.Errorf("IKE service run failed")
	}
	nattAddrPort, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, DEFAULT_NATT_PORT))
	if err != nil {
		logger.IKELog.Errorf("resolve UDP address failed: %+v", err)
		return fmt.Errorf("NAT-T service run failed")
	}

	// Listen and serve
	for _, addr := range []struct {
		portName string
		udpAddr  *net.UDPAddr
	}{
		{"IKE", ikeAddrPort},
		{"NAT-T", nattAddrPort},
	} {
		wg.Add(1)
		errChan := make(chan error)
		go receiver(addr.udpAddr, errChan, n3iwfCtx, wg)
		if err, ok := <-errChan; ok {
			logger.IKELog.Errorf("listen and serve %s service failed: %+v", addr.portName, err)
			return fmt.Errorf("%s service run failed", addr.portName)
		}
	}

	wg.Add(1)
	go runIkeEventHandler(n3iwfCtx, wg)

	return nil
}

// runIkeEventHandler processes incoming IKE packets and events
func runIkeEventHandler(n3iwfCtx *context.N3IWFContext, wg *sync.WaitGroup) {
	defer util.RecoverWithLog(logger.IKELog)
	defer func() {
		logger.IKELog.Infoln("IKE server stopped")
		close(n3iwfCtx.IkeServer.RcvIkePktCh)
		close(n3iwfCtx.IkeServer.RcvEventCh)
		close(n3iwfCtx.IkeServer.StopServer)
		wg.Done()
	}()

	for {
		select {
		case rcvPkt := <-n3iwfCtx.IkeServer.RcvIkePktCh:
			ikeMsg, ikeSA, err := checkIKEMessage(rcvPkt.Msg, rcvPkt.Listener, rcvPkt.LocalAddr, rcvPkt.RemoteAddr)
			if err != nil {
				logger.IKELog.Warnln(err)
				continue
			}
			ike.Dispatch(rcvPkt.Listener, rcvPkt.LocalAddr, rcvPkt.RemoteAddr, ikeMsg, rcvPkt.Msg, ikeSA)
		case rcvIkeEvent := <-n3iwfCtx.IkeServer.RcvEventCh:
			handler.HandleEvent(rcvIkeEvent)
		case <-n3iwfCtx.IkeServer.StopServer:
			return
		}
	}
}

// receiver listens for UDP packets and forwards valid IKE messages
func receiver(localAddr *net.UDPAddr, errChan chan<- error, n3iwfCtx *context.N3IWFContext, wg *sync.WaitGroup) {
	defer util.RecoverWithLog(logger.IKELog)
	defer func() {
		logger.IKELog.Infoln("IKE receiver stopped")
		wg.Done()
	}()

	listener, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		logger.IKELog.Errorf("listen UDP failed: %+v", err)
		errChan <- fmt.Errorf("listenAndServe failed")
		return
	}
	close(errChan)

	n3iwfCtx.IkeServer.Listener[localAddr.Port] = listener
	data := make([]byte, context.MAX_BUF_MSG_LEN)

	for {
		n, remoteAddr, err := listener.ReadFromUDP(data)
		if err != nil {
			logger.IKELog.Errorf("readFromUDP failed: %+v", err)
			return
		}

		forwardData := make([]byte, n)
		copy(forwardData, data[:n])
		logger.IKELog.Debugf("recv from port(%d): %s", localAddr.Port, hex.Dump(forwardData))

		// As specified in RFC 7296 section 3.1, the IKE message send from/to UDP port 4500
		// should prepend a 4 bytes zero
		if localAddr.Port == DEFAULT_NATT_PORT {
			forwardData, err = handleNattMsg(forwardData, remoteAddr, localAddr, handleESPPacket)
			if err != nil {
				logger.IKELog.Errorf("handle NATT msg: %v", err)
				continue
			}
			if forwardData == nil {
				continue
			}
		}

		if len(forwardData) < message.IKE_HEADER_LEN {
			logger.IKELog.Warnf("received IKE msg is too short from %s", remoteAddr.String())
			continue
		}

		ikePkt := context.IkeReceivePacket{
			RemoteAddr: remoteAddr,
			Listener:   listener,
			LocalAddr:  localAddr,
			Msg:        forwardData,
		}
		n3iwfCtx.IkeServer.RcvIkePktCh <- ikePkt
	}
}

// handleNattMsg processes NAT-T messages and ESP packets
func handleNattMsg(msgBuf []byte, rAddr, lAddr *net.UDPAddr, espHandler EspHandler) ([]byte, error) {
	if len(msgBuf) == 1 && msgBuf[0] == 0xff {
		// skip NAT-T Keepalive
		return nil, nil
	}

	nonEspMarker := []byte{0, 0, 0, 0} // Non-ESP Marker
	nonEspMarkerLen := len(nonEspMarker)
	if len(msgBuf) < nonEspMarkerLen {
		return nil, fmt.Errorf("received msg is too short")
	}
	if !bytes.Equal(msgBuf[:nonEspMarkerLen], nonEspMarker) {
		// ESP packet
		if espHandler != nil {
			if err := espHandler(rAddr, lAddr, msgBuf); err != nil {
				logger.IKELog.Errorf("handle ESP packet error: %v", err)
				return nil, fmt.Errorf("handle ESP: %w", err)
			}
		}
		return nil, nil
	}

	// IKE message: skip Non-ESP Marker
	return msgBuf[nonEspMarkerLen:], nil
}

// Stop closes all listeners and signals the server to stop
func Stop(n3iwfCtx *context.N3IWFContext) {
	logger.IKELog.Infoln("close IKE server")
	for _, ikeServerListener := range n3iwfCtx.IkeServer.Listener {
		if err := ikeServerListener.Close(); err != nil {
			logger.IKELog.Errorf("stop IKE server: %s error: %+v", ikeServerListener.LocalAddr().String(), err)
		}
	}
	n3iwfCtx.IkeServer.StopServer <- struct{}{}
}

// checkIKEMessage validates and parses IKE messages
func checkIKEMessage(msg []byte, udpConn *net.UDPConn, localAddr, remoteAddr *net.UDPAddr) (*message.IKEMessage, *context.IKESecurityAssociation, error) {
	ikeHeader, err := message.ParseHeader(msg)
	if err != nil {
		logger.IKELog.Errorf("IKE msg decode header error: %v", err)
		return nil, nil, fmt.Errorf("IKE msg decode header: %w", err)
	}

	if ikeHeader.MajorVersion > 2 {
		payload := new(message.IKEPayloadContainer)
		payload.BuildNotification(message.TypeNone, message.INVALID_MAJOR_VERSION, nil, nil)
		responseIKEMessage := message.NewMessage(ikeHeader.InitiatorSPI, ikeHeader.ResponderSPI,
			message.INFORMATIONAL, true, false, ikeHeader.MessageID, *payload)
		if err := handler.SendIKEMessageToUE(udpConn, localAddr, remoteAddr, responseIKEMessage, nil); err != nil {
			logger.IKELog.Errorf("check IKE message: %v", err)
			return nil, nil, fmt.Errorf("received an IKE message with higher major version (%d>2): %w", ikeHeader.MajorVersion, err)
		}
		return nil, nil, fmt.Errorf("received an IKE message with higher major version (%d>2)", ikeHeader.MajorVersion)
	}

	var ikeMessage *message.IKEMessage
	var ikeSA *context.IKESecurityAssociation

	if ikeHeader.ExchangeType == message.IKE_SA_INIT {
		ikeMessage, err = handler.DecodeDecrypt(msg, ikeHeader, nil, message.Role_Responder)
		if err != nil {
			logger.IKELog.Errorf("decrypt Ike message error: %v", err)
			return nil, nil, fmt.Errorf("decrypt Ike message error: %w", err)
		}
	} else {
		localSPI := ikeHeader.ResponderSPI
		n3iwfCtx := context.N3IWFSelf()
		var ok bool
		ikeSA, ok = n3iwfCtx.IKESALoad(localSPI)
		if !ok {
			payload := new(message.IKEPayloadContainer)
			payload.BuildNotification(message.TypeNone, message.INVALID_IKE_SPI, nil, nil)
			responseIKEMessage := message.NewMessage(ikeHeader.InitiatorSPI, ikeHeader.ResponderSPI,
				message.INFORMATIONAL, true, false, ikeHeader.MessageID, *payload)
			if err := handler.SendIKEMessageToUE(udpConn, localAddr, remoteAddr, responseIKEMessage, nil); err != nil {
				logger.IKELog.Errorf("check Ike message: %v", err)
				return nil, nil, fmt.Errorf("check Ike message: %w", err)
			}
			return nil, nil, fmt.Errorf("received an unrecognized SPI message: %d", localSPI)
		}
		ikeMessage, err = handler.DecodeDecrypt(msg, ikeHeader, ikeSA.IKESAKey, message.Role_Responder)
		if err != nil {
			logger.IKELog.Errorf("decrypt Ike message error: %v", err)
			return nil, nil, fmt.Errorf("decrypt Ike message error: %w", err)
		}
	}
	return ikeMessage, ikeSA, nil
}

// constructPacketWithESP builds an IPv4 packet with ESP payload
func constructPacketWithESP(srcIP, dstIP *net.UDPAddr, espPacket []byte) ([]byte, error) {
	const (
		ipHeaderLen = 20
		ipVersion   = 4
		ipTTL       = 64
		ipProtoESP  = 50 // ESP protocol number
	)

	// Validate that both addresses are IPv4 and non-nil
	srcIPv4 := srcIP.IP.To4()
	if srcIPv4 == nil {
		return nil, fmt.Errorf("source address %s is not a valid IPv4 address", srcIP.IP)
	}
	dstIPv4 := dstIP.IP.To4()
	if dstIPv4 == nil {
		return nil, fmt.Errorf("destination address %s is not a valid IPv4 address", dstIP.IP)
	}

	totalLen := ipHeaderLen + len(espPacket)
	if totalLen > 65535 {
		return nil, fmt.Errorf("packet too large: %d bytes", totalLen)
	}

	// Build IPv4 header
	packet := make([]byte, totalLen)

	// Version (4 bits) + IHL (4 bits)
	packet[0] = (ipVersion << 4) | (ipHeaderLen / 4)

	// Type of Service
	packet[1] = 0

	// Total Length
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))

	// Identification
	binary.BigEndian.PutUint16(packet[4:6], 0)

	// Flags (3 bits) + Fragment Offset (13 bits)
	binary.BigEndian.PutUint16(packet[6:8], 0)

	// TTL
	packet[8] = ipTTL

	// Protocol (ESP)
	packet[9] = ipProtoESP

	// Header Checksum (will be calculated below)
	packet[10] = 0
	packet[11] = 0

	// Source IP
	copy(packet[12:16], srcIPv4)

	// Destination IP
	copy(packet[16:20], dstIPv4)

	// Calculate and set IP header checksum
	checksum := calculateIPChecksum(packet[:ipHeaderLen])
	binary.BigEndian.PutUint16(packet[10:12], checksum)

	// Copy ESP payload
	copy(packet[ipHeaderLen:], espPacket)

	return packet, nil
}

// calculateIPChecksum computes the IPv4 header checksum
func calculateIPChecksum(header []byte) uint16 {
	var sum uint32

	// Sum all 16-bit words
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}

	// Add carry bits
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	// Return one's complement
	return ^uint16(sum)
}

// handleESPPacket sends ESP packet using raw socket
func handleESPPacket(srcIP, dstIP *net.UDPAddr, espPacket []byte) error {
	logger.IKELog.Debugln("handle ESPPacket")
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("socket error: %v", err)
	}
	defer func() {
		if err := syscall.Close(fd); err != nil {
			logger.IKELog.Errorf("close fd error: %v", err)
		}
	}()
	ipPacket, err := constructPacketWithESP(srcIP, dstIP, espPacket)
	if err != nil {
		return err
	}
	addr := syscall.SockaddrInet4{
		Addr: [4]byte(dstIP.IP),
		Port: dstIP.Port,
	}
	if err := syscall.Sendto(fd, ipPacket, 0, &addr); err != nil {
		return fmt.Errorf("sendto error: %v", err)
	}
	return nil
}
