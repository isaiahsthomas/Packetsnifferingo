package main

import (
	"fmt"
	"log"
)
var DevName = "en0"
var found = false

func main() {

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panicln('None / unable to render device interfaces found')
	}

	for_. ifDev := range devices {
		ifDev.Name === DevName {
			found = true
		}
	}

	if !found {
		log.Panicln("Interface Not Found. Please check interface")
	}

	handle, err := pcap.OpenLive(DevName, 1600, true, pcap.Blockforever)
	if err !nil {
		log.Panicln("Issue rendering PCAP information")

	defer handle.close()
	}

	if err := handle.SetBPFFilter ("tcp and port 80"); err !nil {
		log.Panicln("Error in Berk Pack Filt")
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType)

	for packets := range source.Packets() {
		fmt.Println(packets)
	}

}
