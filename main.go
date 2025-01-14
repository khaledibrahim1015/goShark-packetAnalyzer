package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
)

type CommandFlags struct {
	listDevs     bool
	interfaceDev string
}

func ExecuteCmd() *CommandFlags {

	listInterfaceNetworkDevs := flag.Bool("listIfaceDevs", false, "list all interface network devices on machine ")
	interfaceDevice := flag.String("interfaceDevice", "", "Choose a network interface to capture packets from")
	flag.Parse()

	return &CommandFlags{
		listDevs:     *listInterfaceNetworkDevs,
		interfaceDev: *interfaceDevice,
	}

}

func main() {
	cmd := ExecuteCmd()
	// List Network Interfaces
	if cmd.listDevs {
		FindAllInterfacesDevices()
	}

	// 	cmd := ExecuteCmd()
	// 	packetSniffer := models.NewPacketSniffer(cmd.interfaceDev)

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
