package arptools

import (
	"crypto/rand"
	"net"
	"testing"

	"github.com/torbenconto/arp-tools/cmd/ethernet"
)

func GenerateRandomMAC() net.HardwareAddr {
	// Generate a random 6-byte MAC address.
	mac := make([]byte, 6)
	rand.Read(mac)

	// Set the locally administered address bit (first byte should be 02).
	mac[0] = (mac[0] & 0xFE) | 0x02

	return net.HardwareAddr(mac)
}

func GenerateRandomIP() net.IP {
	ip := make([]byte, 4)
	rand.Read(ip)

	return net.IP(ip)
}

func TestPacket_Marshal_Unmarshal(t *testing.T) {
	// Create a packet
	p1 := NewPacket(GenerateRandomMAC(), GenerateRandomMAC(), ethernet.ARPEtherType, ethernet.EthernetHardwareType, ethernet.IPv4ProtocolType, 6, 4, ethernet.SendOpcode, GenerateRandomMAC(), net.IPv4(10, 0, 0, 1), GenerateRandomMAC(), GenerateRandomIP())

	// Marshal the packet
	data, err := p1.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Unmarshal the data into a new packet
	var p2 Packet
	err = p2.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Compare packets
	if !p1.Equals(&p2) {
		t.Fatalf("Packets differ: %+v vs %+v", p1, p2)
	}
}
