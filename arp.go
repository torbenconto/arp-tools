package arptools

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"

	"github.com/torbenconto/arp-tools/cmd/ethernet"
	"github.com/torbenconto/arp-tools/internal/socket"
)

type Packet struct {
	EthernetHeader struct {
		TargetMAC net.HardwareAddr
		SourceMAC net.HardwareAddr
		EtherType ethernet.EtherType_t
	}
	HardwareType ethernet.HardwareType_t
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
	hwType ethernet.HardwareType_t,
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

func (a *Packet) ToBytes() []byte {
	buf := new(bytes.Buffer)

	// Ethernet header
	buf.Write(a.EthernetHeader.TargetMAC) // net.HardwareAddr is already a byte slice
	buf.Write(a.EthernetHeader.SourceMAC) // net.HardwareAddr is already a byte slice
	binary.Write(buf, binary.BigEndian, a.EthernetHeader.EtherType)

	// ARP header
	binary.Write(buf, binary.BigEndian, a.HardwareType)
	binary.Write(buf, binary.BigEndian, a.ProtocolType)
	buf.WriteByte(a.HardwareSize)
	buf.WriteByte(a.ProtocolSize)
	binary.Write(buf, binary.BigEndian, a.Opcode)
	buf.Write(a.SourceMAC)      // net.HardwareAddr is already a byte slice
	buf.Write(a.SourceIP.To4()) // Convert to 4-byte slice for IPv4
	buf.Write(a.TargetMAC)      // net.HardwareAddr is already a byte slice
	buf.Write(a.TargetIP.To4()) // Convert to 4-byte slice for IPv4

	fmt.Println(buf.Bytes())

	return buf.Bytes()
}

type Arp struct {
	Socket *socket.Socket
}

func NewArp(intf *net.Interface) *Arp {
	s := socket.NewSocket(intf, syscall.ETH_P_ARP)
	err := s.Listen()
	if err != nil {
		panic(err)
	}

	return &Arp{
		Socket: s,
	}
}

/*
Request sends a single ARP request packet (opcode 0) to broadcast. Does not read response, use Request for that.
*/
func (a *Arp) Request(ip net.IP) error {
	addr, err := ethernet.GetIntfAddr(a.Socket.Intf())
	if err != nil {
		return err
	}

	emptyMac, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	packet := NewPacket(
		ethernet.ARPEtherType,
		ethernet.EthernetHardwareType,
		ethernet.IPv4ProtocolType,
		6,
		4,
		ethernet.SendOpcode,
		emptyMac,
		ip,
		a.Socket.Intf().HardwareAddr,
		addr,
	)

	fmt.Println(packet.ToBytes())

	data := packet.ToBytes()

	a.Socket.Write(data)

	//TODO: convert packet to bytes and send to FF:FF:FF:FF:FF:FF

	return nil
}
