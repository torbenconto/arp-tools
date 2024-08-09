package ethernet

import (
	"encoding/binary"
	"errors"
	"math"

	"github.com/josharian/native"
)

type EtherType_t uint16

const (
	ARPEtherType EtherType_t = 0x0806
)

type HardwareType_t uint16

const (
	EthernetHardwareType     HardwareType_t = 1
	FibreChannelHardwareType HardwareType_t = 15
	InfinibandHardwareType   HardwareType_t = 32
)

type ProtocolType_t uint16

const (
	IPv4ProtocolType ProtocolType_t = 0x0800
	IPv6ProtocolType ProtocolType_t = 0x86DD
)

type Opcode_t uint16

const (
	SendOpcode Opcode_t = 0
	RecvOpcode Opcode_t = 1
)

func Htons(i int) (uint16, error) {
	if i < 0 || i > math.MaxUint16 {
		return 0, errors.New("htons: proto value out of range")
	}

	var b []byte
	binary.BigEndian.PutUint16(b[:], uint16(i))

	return native.Endian.Uint16(b[:]), nil
}
