package main

import (
	"net"

	arptools "github.com/torbenconto/arp-tools"
)

func main() {
	intf, err := net.InterfaceByName("wlan0")
	if err != nil {
		panic(err)
	}
	a := arptools.NewArp(intf)

	a.Request(net.IPv4(0x0A, 0, 0, 1))
}
