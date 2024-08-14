package arptools

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/torbenconto/arp-tools/cmd/ethernet"
	"github.com/torbenconto/arp-tools/internal/socket"
)

var BroadcastMac, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")

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
	p := Packet{
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
	p.EthernetHeader.EtherType = ethType
	p.EthernetHeader.TargetMAC = targetMAC
	p.EthernetHeader.SourceMAC = sourceMAC

	return &p
}

// Equals compares two Packet structs for equality
func (p1 *Packet) Equals(p2 *Packet) bool {
	if p1 == nil || p2 == nil {
		return p1 == p2
	}

	return p1.EthernetHeader.TargetMAC.String() == p2.EthernetHeader.TargetMAC.String() &&
		p1.EthernetHeader.SourceMAC.String() == p2.EthernetHeader.SourceMAC.String() &&
		p1.EthernetHeader.EtherType == p2.EthernetHeader.EtherType &&
		p1.HardwareType == p2.HardwareType &&
		p1.ProtocolType == p2.ProtocolType &&
		p1.HardwareSize == p2.HardwareSize &&
		p1.ProtocolSize == p2.ProtocolSize &&
		p1.Opcode == p2.Opcode &&
		p1.TargetMAC.String() == p2.TargetMAC.String() &&
		p1.TargetIP.String() == p2.TargetIP.String() &&
		p1.SourceMAC.String() == p2.SourceMAC.String() &&
		p1.SourceIP.String() == p2.SourceIP.String()
}

func (p *Packet) Unmarshal(data []byte) error {
	if len(data) < 42 {
		return errors.New("not enough data")
	}

	offset := 0

	p.EthernetHeader.TargetMAC = net.HardwareAddr(data[offset : offset+6])
	offset += 6
	p.EthernetHeader.SourceMAC = net.HardwareAddr(data[offset : offset+6])
	offset += 6
	p.EthernetHeader.EtherType = ethernet.EtherType_t(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	p.HardwareType = ethernet.HardwareType_t(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	p.ProtocolType = ethernet.ProtocolType_t(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	p.HardwareSize = data[offset]
	offset += 1
	p.ProtocolSize = data[offset]
	offset += 1
	p.Opcode = ethernet.Opcode_t(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	p.SourceMAC = net.HardwareAddr(data[offset : offset+6])
	offset += 6
	p.SourceIP = net.IP(data[offset : offset+4])
	offset += 4
	p.TargetMAC = net.HardwareAddr(data[offset : offset+6])
	offset += 6
	p.TargetIP = net.IP(data[offset : offset+4])

	return nil
}

func (p *Packet) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Ethernet header
	buf.Write(p.EthernetHeader.TargetMAC)
	buf.Write(p.EthernetHeader.SourceMAC)
	if err := binary.Write(buf, binary.BigEndian, p.EthernetHeader.EtherType); err != nil {
		return nil, err
	}

	// ARP header
	if err := binary.Write(buf, binary.BigEndian, p.HardwareType); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, p.ProtocolType); err != nil {
		return nil, err
	}
	buf.WriteByte(p.HardwareSize)
	buf.WriteByte(p.ProtocolSize)
	if err := binary.Write(buf, binary.BigEndian, p.Opcode); err != nil {
		return nil, err
	}
	buf.Write(p.SourceMAC)
	buf.Write(p.SourceIP.To4())
	buf.Write(p.TargetMAC)
	buf.Write(p.TargetIP.To4())

	return buf.Bytes(), nil
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
Request sends a single ARP request packet (opcode 1) to broadcast. Does not read response, use Request for that.
*/
func (a *Arp) Request(ip net.IP) error {
	addr, err := ethernet.GetIntfAddr(a.Socket.Intf())
	if err != nil {
		return err
	}

	packet := NewPacket(
		ethernet.ARPEtherType,
		ethernet.EthernetHardwareType,
		ethernet.IPv4ProtocolType,
		6,
		4,
		ethernet.SendOpcode,
		BroadcastMac,
		ip,
		a.Socket.Intf().HardwareAddr,
		addr,
	)

	data, err := packet.Marshal()
	if err != nil {
		return err
	}

	a.Socket.Write(data)

	return nil
}

/*
Read reads a single ARP frame with a return opcode (2)
*/
func (a *Arp) Read() (*Packet, error) {
	buf := make([]byte, 128)
	for {
		n, err := a.Socket.Read(buf)
		if err != nil {
			return &Packet{}, err
		}

		p := &Packet{}
		p.Unmarshal(buf[:n])

		if p.Opcode == ethernet.RecvOpcode {
			return p, nil
		}

		continue
	}
}

/*
Resolve uses both the Request and Read methods to resolve a given IP to a MAC
*/
func (a *Arp) Resolve(ip net.IP) (*Packet, error) {
	if err := a.Request(ip); err != nil {
		return nil, err
	}

	packet, err := a.Read()
	if err != nil {
		return nil, err
	}

	if packet.Opcode == ethernet.RecvOpcode && bytes.Equal(packet.TargetMAC, a.Socket.Intf().HardwareAddr) {
		return packet, nil
	}

	return nil, fmt.Errorf("invalid ARP response or incorrect MAC address")
}

/*
Reply sends an ARP reply to ip "sendTo" from ip "from" saying that "from" is at your interfaces MAC addr
*/
func (a *Arp) Reply(sendTo, from net.IP) error {
	p, err := a.Resolve(sendTo)
	if err != nil {
		return err
	}

	packet := NewPacket(
		ethernet.ARPEtherType,
		ethernet.EthernetHardwareType,
		ethernet.IPv4ProtocolType,
		6,
		4,
		ethernet.RecvOpcode,
		p.SourceMAC,
		sendTo,
		a.Socket.Intf().HardwareAddr,
		from,
	)

	data, err := packet.Marshal()
	if err != nil {
		return err
	}

	if err := a.Socket.Write(data); err != nil {
		return err
	}

	return nil
}
