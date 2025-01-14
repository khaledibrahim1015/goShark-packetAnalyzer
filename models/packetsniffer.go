package models

import (
	"time"

	"github.com/google/gopacket/pcap"
)

//	for network interface Device configuration NIC
//
// PacketSniffer represents our main packet capture and analysis tool
type PacketSniffer struct {

	// Interface device  configuration
	//  eth0 or eth1 .. in linux env or en0 or en1 in mac env or in windows like `\Device\NPF_{D2C88C00-9B67-4D86-A424-4A79F2845D43}`
	Iface       string
	Promiscuous bool
	Timeout     time.Duration
	Snaplen     int32
	Filter      string
}

func NewPacketSniffer(ifaceName, filter string) *PacketSniffer {

	return &PacketSniffer{
		Iface:       ifaceName, // Choose a network interface to capture packets from
		Promiscuous: true,
		Timeout:     pcap.BlockForever,
		Snaplen:     65536,  // Capture entire packet
		Filter:      filter, // Filtering Packets by Protocol

	}

}
