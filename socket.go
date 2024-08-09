package arptools

import (
	"net"
	"sync"
	"syscall"

	"github.com/torbenconto/arp-tools/cmd/ethernet"
)

type Socket struct {
	mu *sync.Mutex

	intf     *net.Interface
	protocol int
	fd       int
}

func NewSocket(intf *net.Interface, protocol int) *Socket {
	return &Socket{
		mu:       &sync.Mutex{},
		intf:     intf,
		protocol: protocol,
		fd:       0,
	}
}

func (s *Socket) Listen() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	proto, err := ethernet.Htons(s.protocol)
	if err != nil {
		return err
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, s.protocol)
	if err != nil {
		return err
	}

	s.fd = fd

	addr := &syscall.SockaddrLinklayer{
		Ifindex:  s.intf.Index,
		Protocol: proto,
	}

	err = syscall.Bind(s.fd, addr)

	return err
}
