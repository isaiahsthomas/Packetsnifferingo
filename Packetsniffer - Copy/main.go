package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var DevName = "Ethernet"
var Found = false

func main() {

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panicln("None / unable to render device interfaces found")
	}

	for _, ifDev := range devices {
		if ifDev.Name == DevName {
			Found = true
		}
	}

	if !Found {
		log.Panicln("Interface Not Found. Please check interface")
	}

	handle, err := pcap.OpenLive(DevName, 1600, false, pcap.BlockForever)
	if err != nil {
		fmt.Print(err)
		log.Panicln("Unable to open handle on the device")
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("tcp and port 443"); err != nil {
		log.Panicln(err)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())

	for packets := range source.Packets() {
		fmt.Println(packets)
	}
}
