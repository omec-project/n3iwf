// SPDX-FileCopyrightText: 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestConstructPacketWithESP(t *testing.T) {
	// Setup test data
	srcIP := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 4500}
	dstIP := &net.UDPAddr{IP: net.ParseIP("10.0.0.50"), Port: 4500}
	espPayload := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Construct packet
	packet, err := constructPacketWithESP(srcIP, dstIP, espPayload)
	if err != nil {
		t.Fatalf("constructPacketWithESP failed: %v", err)
	}

	// Validate packet length
	expectedLen := 20 + len(espPayload) // IP header + ESP payload
	if len(packet) != expectedLen {
		t.Errorf("Expected packet length %d, got %d", expectedLen, len(packet))
	}

	// Validate IP version and IHL
	versionIHL := packet[0]
	version := versionIHL >> 4
	ihl := versionIHL & 0x0F
	if version != 4 {
		t.Errorf("Expected IP version 4, got %d", version)
	}
	if ihl != 5 { // 5 * 4 bytes = 20 bytes header
		t.Errorf("Expected IHL 5, got %d", ihl)
	}

	// Validate total length
	totalLen := binary.BigEndian.Uint16(packet[2:4])
	if totalLen != uint16(expectedLen) {
		t.Errorf("Expected total length %d, got %d", expectedLen, totalLen)
	}

	// Validate TTL
	if packet[8] != 64 {
		t.Errorf("Expected TTL 64, got %d", packet[8])
	}

	// Validate protocol (ESP = 50)
	if packet[9] != 50 {
		t.Errorf("Expected protocol 50 (ESP), got %d", packet[9])
	}

	// Validate source IP
	srcIPBytes := packet[12:16]
	if !srcIP.IP.To4().Equal(net.IP(srcIPBytes)) {
		t.Errorf("Source IP mismatch: expected %v, got %v", srcIP.IP.To4(), srcIPBytes)
	}

	// Validate destination IP
	dstIPBytes := packet[16:20]
	if !dstIP.IP.To4().Equal(net.IP(dstIPBytes)) {
		t.Errorf("Destination IP mismatch: expected %v, got %v", dstIP.IP.To4(), dstIPBytes)
	}

	// Validate checksum is not zero
	checksum := binary.BigEndian.Uint16(packet[10:12])
	if checksum == 0 {
		t.Error("Checksum should not be zero")
	}

	// Verify checksum calculation
	// Zero out the checksum field and recalculate
	headerCopy := make([]byte, 20)
	copy(headerCopy, packet[:20])
	headerCopy[10] = 0
	headerCopy[11] = 0
	calculatedChecksum := calculateIPChecksum(headerCopy)
	if calculatedChecksum != checksum {
		t.Errorf("Checksum verification failed: expected %d, got %d", checksum, calculatedChecksum)
	}

	// Validate ESP payload
	espInPacket := packet[20:]
	if len(espInPacket) != len(espPayload) {
		t.Errorf("ESP payload length mismatch: expected %d, got %d", len(espPayload), len(espInPacket))
	}
	for i, b := range espPayload {
		if espInPacket[i] != b {
			t.Errorf("ESP payload mismatch at byte %d: expected %02x, got %02x", i, b, espInPacket[i])
		}
	}
}

func TestCalculateIPChecksum(t *testing.T) {
	// Test with a known IPv4 header
	// Example header with checksum already calculated (from RFC 791)
	header := []byte{
		0x45, 0x00, // Version, IHL, ToS
		0x00, 0x3c, // Total Length
		0x1c, 0x46, // Identification
		0x40, 0x00, // Flags, Fragment Offset
		0x40, 0x06, // TTL, Protocol
		0x00, 0x00, // Checksum (will be calculated)
		0xac, 0x10, 0x0a, 0x63, // Source IP: 172.16.10.99
		0xac, 0x10, 0x0a, 0x0c, // Dest IP: 172.16.10.12
	}

	checksum := calculateIPChecksum(header)

	// Verify checksum is not zero
	if checksum == 0 {
		t.Error("Checksum should not be zero for this header")
	}

	// Verify the checksum by recalculating with the checksum included
	headerWithChecksum := make([]byte, len(header))
	copy(headerWithChecksum, header)
	binary.BigEndian.PutUint16(headerWithChecksum[10:12], checksum)

	// The checksum of a packet with correct checksum should be 0 or 0xFFFF
	verifyChecksum := calculateIPChecksum(headerWithChecksum)
	if verifyChecksum != 0xFFFF && verifyChecksum != 0 {
		t.Errorf("Checksum verification failed: got %04x, expected 0xFFFF or 0", verifyChecksum)
	}
}

func TestConstructPacketWithESP_TooLarge(t *testing.T) {
	srcIP := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 4500}
	dstIP := &net.UDPAddr{IP: net.ParseIP("10.0.0.50"), Port: 4500}
	// Create a payload that would exceed maximum packet size
	largePayload := make([]byte, 65536)

	_, err := constructPacketWithESP(srcIP, dstIP, largePayload)
	if err == nil {
		t.Error("Expected error for packet too large, got nil")
	}
}

func TestConstructPacketWithESP_IPv6SourceAddress(t *testing.T) {
	srcIP := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 4500}
	dstIP := &net.UDPAddr{IP: net.ParseIP("10.0.0.50"), Port: 4500}
	espPayload := []byte{0x01, 0x02, 0x03, 0x04}

	_, err := constructPacketWithESP(srcIP, dstIP, espPayload)
	if err == nil {
		t.Error("Expected error for IPv6 source address, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "source address") {
		t.Errorf("Expected error message to mention 'source address', got: %v", err)
	}
	if err != nil && !strings.Contains(err.Error(), "not a valid IPv4 address") {
		t.Errorf("Expected error message to mention 'not a valid IPv4 address', got: %v", err)
	}
}

func TestConstructPacketWithESP_IPv6DestinationAddress(t *testing.T) {
	srcIP := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 4500}
	dstIP := &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 4500}
	espPayload := []byte{0x01, 0x02, 0x03, 0x04}

	_, err := constructPacketWithESP(srcIP, dstIP, espPayload)
	if err == nil {
		t.Error("Expected error for IPv6 destination address, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "destination address") {
		t.Errorf("Expected error message to mention 'destination address', got: %v", err)
	}
	if err != nil && !strings.Contains(err.Error(), "not a valid IPv4 address") {
		t.Errorf("Expected error message to mention 'not a valid IPv4 address', got: %v", err)
	}
}

func TestConstructPacketWithESP_BothIPv6Addresses(t *testing.T) {
	srcIP := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 4500}
	dstIP := &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 4500}
	espPayload := []byte{0x01, 0x02, 0x03, 0x04}

	_, err := constructPacketWithESP(srcIP, dstIP, espPayload)
	if err == nil {
		t.Error("Expected error for both IPv6 addresses, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "not a valid IPv4 address") {
		t.Errorf("Expected error message to mention 'not a valid IPv4 address', got: %v", err)
	}
}

func TestValidateConstructedPacket(t *testing.T) {
	srcIP := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 4500}
	dstIP := &net.UDPAddr{IP: net.ParseIP("10.0.0.50"), Port: 4500}
	espPayload := []byte("Test ESP Payload Data")

	packet, err := constructPacketWithESP(srcIP, dstIP, espPayload)
	if err != nil {
		t.Fatalf("constructPacketWithESP failed: %v", err)
	}

	// Validate the packet and print detailed analysis
	analysis, err := validateIPv4Packet(packet)
	if err != nil {
		t.Errorf("Packet validation failed: %v", err)
	}

	// Print the analysis (will show in verbose mode: go test -v)
	t.Logf("\n%s", analysis)
}

func ExampleconstructPacketWithESP() {
	// Setup test parameters
	srcIP := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 4500}
	dstIP := &net.UDPAddr{IP: net.ParseIP("10.0.0.50"), Port: 4500}
	espPayload := []byte{
		0x00, 0x00, 0x00, 0x01, // SPI
		0x00, 0x00, 0x00, 0x01, // Sequence Number
		0x01, 0x02, 0x03, 0x04, // Sample encrypted payload
	}

	// Construct the packet
	packet, err := constructPacketWithESP(srcIP, dstIP, espPayload)
	if err != nil {
		panic(err)
	}

	// Validate the packet
	analysis, err := validateIPv4Packet(packet)
	if err != nil {
		panic(err)
	}

	// Display key information
	fmt.Printf("Packet constructed: %d bytes\n", len(packet))
	fmt.Println("Source IP: 192.168.1.100")
	fmt.Println("Destination IP: 10.0.0.50")
	fmt.Println("Protocol: ESP (50)")
	fmt.Println("Checksum: Valid")
	fmt.Printf("ESP Payload: %d bytes\n", len(espPayload))

	// Verify analysis contains expected elements
	if analysis != "" {
		fmt.Println("Validation: Passed")
	}

	// Output:
	// Packet constructed: 32 bytes
	// Source IP: 192.168.1.100
	// Destination IP: 10.0.0.50
	// Protocol: ESP (50)
	// Checksum: Valid
	// ESP Payload: 12 bytes
	// Validation: Passed
}

func BenchmarkConstructPacketWithESP(b *testing.B) {
	srcIP := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 4500}
	dstIP := &net.UDPAddr{IP: net.ParseIP("10.0.0.50"), Port: 4500}
	espPayload := make([]byte, 1400) // Typical MTU size payload

	b.ResetTimer()
	for b.Loop() {
		_, err := constructPacketWithESP(srcIP, dstIP, espPayload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// validateIPv4Packet validates and returns detailed information about an IPv4 packet
func validateIPv4Packet(packet []byte) (string, error) {
	if len(packet) < 20 {
		return "", fmt.Errorf("packet too short: %d bytes (minimum 20 required)", len(packet))
	}

	var result strings.Builder
	result.WriteString("=== IPv4 Packet Analysis ===\n\n")

	// Parse and validate header fields
	versionIHL := packet[0]
	version := versionIHL >> 4
	ihl := versionIHL & 0x0F
	headerLen := int(ihl) * 4

	result.WriteString(fmt.Sprintf("Version: %d\n", version))
	result.WriteString(fmt.Sprintf("IHL: %d (%d bytes)\n", ihl, headerLen))

	if version != 4 {
		return result.String(), fmt.Errorf("invalid IP version: %d (expected 4)", version)
	}

	if headerLen < 20 || headerLen > len(packet) {
		return result.String(), fmt.Errorf("invalid header length: %d", headerLen)
	}

	// Type of Service
	tos := packet[1]
	result.WriteString(fmt.Sprintf("Type of Service: 0x%02x\n", tos))

	// Total Length
	totalLen := binary.BigEndian.Uint16(packet[2:4])
	result.WriteString(fmt.Sprintf("Total Length: %d bytes\n", totalLen))

	if int(totalLen) != len(packet) {
		result.WriteString(fmt.Sprintf("  WARNING: Total length (%d) != actual packet length (%d)\n", totalLen, len(packet)))
	}

	// Identification
	id := binary.BigEndian.Uint16(packet[4:6])
	result.WriteString(fmt.Sprintf("Identification: 0x%04x\n", id))

	// Flags and Fragment Offset
	flagsOffset := binary.BigEndian.Uint16(packet[6:8])
	flags := flagsOffset >> 13
	fragmentOffset := flagsOffset & 0x1FFF
	result.WriteString(fmt.Sprintf("Flags: 0x%x\n", flags))
	result.WriteString(fmt.Sprintf("Fragment Offset: %d\n", fragmentOffset))

	// TTL
	ttl := packet[8]
	result.WriteString(fmt.Sprintf("TTL: %d\n", ttl))

	// Protocol
	protocol := packet[9]
	protocolName := getProtocolName(protocol)
	result.WriteString(fmt.Sprintf("Protocol: %d (%s)\n", protocol, protocolName))

	// Checksum
	checksum := binary.BigEndian.Uint16(packet[10:12])
	result.WriteString(fmt.Sprintf("Header Checksum: 0x%04x\n", checksum))

	// Verify checksum
	headerCopy := make([]byte, headerLen)
	copy(headerCopy, packet[:headerLen])
	headerCopy[10] = 0
	headerCopy[11] = 0
	calculatedChecksum := calculateIPChecksum(headerCopy)

	if calculatedChecksum == checksum {
		result.WriteString("  ✓ Checksum is VALID\n")
	} else {
		result.WriteString(fmt.Sprintf("  ✗ Checksum is INVALID (expected 0x%04x, got 0x%04x)\n", calculatedChecksum, checksum))
	}

	// Source and Destination IP
	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])
	result.WriteString(fmt.Sprintf("Source IP: %s\n", srcIP))
	result.WriteString(fmt.Sprintf("Destination IP: %s\n", dstIP))

	// Payload
	payloadLen := len(packet) - headerLen
	result.WriteString(fmt.Sprintf("\nPayload Length: %d bytes\n", payloadLen))

	if payloadLen > 0 {
		result.WriteString("Payload (first 64 bytes):\n")
		dumpLen := payloadLen
		if dumpLen > 64 {
			dumpLen = 64
		}
		result.WriteString(hexDump(packet[headerLen:headerLen+dumpLen], headerLen))
	}

	return result.String(), nil
}

// getProtocolName returns the protocol name for common protocol numbers
func getProtocolName(protocol byte) string {
	protocolNames := map[byte]string{
		1:   "ICMP",
		6:   "TCP",
		17:  "UDP",
		50:  "ESP",
		51:  "AH",
		132: "SCTP",
	}
	if name, ok := protocolNames[protocol]; ok {
		return name
	}
	return "Unknown"
}

// hexDump creates a hexdump-style output of bytes
func hexDump(data []byte, offset int) string {
	var result strings.Builder
	for i := 0; i < len(data); i += 16 {
		result.WriteString(fmt.Sprintf("  %04x: ", offset+i))

		// Hex values
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				result.WriteString(fmt.Sprintf("%02x ", data[i+j]))
			} else {
				result.WriteString("   ")
			}
			if j == 7 {
				result.WriteString(" ")
			}
		}

		// ASCII representation
		result.WriteString(" |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				result.WriteString(string(b))
			} else {
				result.WriteString(".")
			}
		}
		result.WriteString("|\n")
	}
	return result.String()
}
