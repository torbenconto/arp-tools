package arptools

import (
	"net"

	"github.com/torbenconto/arp-tools/cmd/ethernet"
)

type Packet struct {
	EthernetHeader struct {
		TargetMAC net.HardwareAddr
		SourceMAC net.HardwareAddr
		EtherType ethernet.EtherType_t
	}
	HardwareType ethernet.EtherType_t
	ProtocolType ethernet.ProtocolType_t
	HardwareSize uint8
	ProtocolSize uint8
	Opcode       ethernet.Opcode_t
	TargetMAC    net.HardwareAddr
	TargetIP     net.IP
	SourceMAC    net.HardwareAddr
	SourceIP     net.IP
}
