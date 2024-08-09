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

func NewPacket(
	ethType ethernet.EtherType_t,
	hwType ethernet.EtherType_t,
	protoType ethernet.ProtocolType_t,
	hwSize uint8,
	protoSize uint8,
	opcode ethernet.Opcode_t,
	targetMAC net.HardwareAddr,
	targetIP net.IP,
	sourceMAC net.HardwareAddr,
	sourceIP net.IP,
) *Packet {
	packet := &Packet{
		HardwareType: hwType,
		ProtocolType: protoType,
		HardwareSize: hwSize,
		ProtocolSize: protoSize,
		Opcode:       opcode,
		TargetMAC:    targetMAC,
		TargetIP:     targetIP,
		SourceMAC:    sourceMAC,
		SourceIP:     sourceIP,
	}

	packet.EthernetHeader.TargetMAC = targetMAC
	packet.EthernetHeader.SourceMAC = sourceMAC
	packet.EthernetHeader.EtherType = ethType

	return packet
}
