package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
	"github.com/khaledibrahim1015/goShark-packetAnalyzer/internal"
	"github.com/khaledibrahim1015/goShark-packetAnalyzer/models"
)

type CommandFlags struct {
	listDevs  bool
	ifaceName string
	filetr    string
}

func ExecuteCmd() *CommandFlags {

	listInterfaceNetworkDevs := flag.Bool("listIfaceDevs", false, "list all interface network devices on machine ")
	ifaceName := flag.String("interfaceDevice", "", "Choose a network interface to capture packets from")
	filterProtocol := flag.String("filter", "", "Filtering Packets by Protocol")

	flag.Parse()

	return &CommandFlags{
		listDevs:  *listInterfaceNetworkDevs,
		ifaceName: *ifaceName,
		filetr:    *filterProtocol,
	}

}

func main() {
	cmd := ExecuteCmd()
	// List Network Interfaces
	if cmd.listDevs {
		FindAllInterfacesDevices()
	}

	packetSnifInfo := models.NewPacketSniffer(cmd.ifaceName, cmd.filetr)
	internal.CapturePackets(packetSnifInfo)

	// fmt.Println("goshark packet sniffer && analyzer ")

}

func FindAllInterfacesDevices() {

	var ifaces []pcap.Interface
	ifaces, err := pcap.FindAllDevs()
	if err != nil {

		log.Fatalf("error when listing all network interfaces %v", err)

	}

	//  iteration over each nic
	for _, ifaceDevice := range ifaces {
		fmt.Println("\nName: ", ifaceDevice.Name)
		fmt.Println("Description: ", ifaceDevice.Description)
		fmt.Println("Addresses: ")
		for _, address := range ifaceDevice.Addresses {
			fmt.Printf("- IP address: %v\n", address.IP)
			fmt.Printf("  Netmask: %v\n", address.Netmask)
			fmt.Printf("  Broadcast address: %v\n", address.Broadaddr)
		}

	}

}
