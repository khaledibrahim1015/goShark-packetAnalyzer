package internal

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/khaledibrahim1015/goShark-packetAnalyzer/models"
)

// Capture Packets from an Interface
// capturing raw packets from a network interface
func CapturePackets(packetsinf *models.PacketSniffer) {

	// Open the network device for capturing
	handle, err := pcap.OpenLive(packetsinf.Iface, packetsinf.Snaplen, packetsinf.Promiscuous, packetsinf.Timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set a BPF filter if provided  (Filtering Packets by Protocol )
	if packetsinf.Filter != "" {
		err = handle.SetBPFFilter(packetsinf.Filter)
		if err != nil {
			log.Fatal(err)
		}

	}

	// Use the handle as a packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Loop through packets

	for packet := range packetSource.Packets() {

		fmt.Println(packet)

	}

}
