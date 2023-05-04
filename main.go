package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"os"

	"github.com/fatih/color"
	"github.com/google/gopacket/pcap"
)

type Config struct {
	DeviceName        string   `json:"deviceName"`
	PacketFilter      []string `json:"packetFilter"`
	AutoSavePcapFiles bool     `json:"autoSavePcapFiles"`
}

var config *Config
var listDevice = flag.Bool("l", false, "List the network devices on this machine")
var ip = flag.String("ip", "", "Designate the network devices to capture by IP")

func main() {
	bytes, err := ioutil.ReadFile("./config.json")
	if err != nil {
		log.Fatalln("Could not load ./config.json", err)
	}
	err = json.Unmarshal(bytes, &config)
	if err != nil {
		log.Fatalln("Could not load ./config.json", err)
	}
	for packet := range config.PacketFilter {
		packetFilter[config.PacketFilter[packet]] = true
	}

	flag.Parse()

	if *listDevice {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}

		log.Println(color.RedString("Name"), "\tDescription\t", color.CyanString("IP address"), "\tSubnet mask")
		for _, device := range devices {
			log.Println(color.RedString(device.Name), "\t", device.Description, "\t")
			for _, address := range device.Addresses {
				log.Println("\t\t\t", color.CyanString(address.IP.String()), "\t", address.Netmask)
			}
		}
		os.Exit(0)
	}

	if len(*ip) > 0 {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}

		for _, device := range devices {
			for _, address := range device.Addresses {
				if address.IP.String() == *ip {
					log.Println("Device ", device.Name, " is chose")
					config.DeviceName = device.Name
					break
				}
			}
		}
	}

	go InitProto()
	startServer()
}
