package ethernet

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
