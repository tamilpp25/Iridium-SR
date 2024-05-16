package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/xtaci/kcp-go"
)

type Packet struct {
	Time       int64       `json:"time"`
	FromServer bool        `json:"fromServer"`
	PacketId   uint16      `json:"packetId"`
	PacketName string      `json:"packetName"`
	Object     interface{} `json:"object"`
	Raw        []byte      `json:"raw"`
}

type UniCmdItem struct {
	PacketId   uint16      `json:"packetId"`
	PacketName string      `json:"packetName"`
	Object     interface{} `json:"object"`
	Raw        []byte      `json:"raw"`
}

var playerGetTokenScRspPacketId uint16

var initialKey = make(map[uint32][]byte)
var sessionKey []byte

var captureHandler *pcap.Handle
var kcpMap map[string]*kcp.KCP
var packetFilter = make(map[string]bool)
var pcapFile *os.File

func openPcap(fileName string) {
	readKeys()
	var err error
	captureHandler, err = pcap.OpenOffline(fileName)
	if err != nil {
		log.Println("Could not open pacp file", err)
		return
	}
	startSniffer()
}

func openCapture() {
	readKeys()
	var err error
	captureHandler, err = pcap.OpenLive(config.DeviceName, 1500, true, -1)

	if err != nil {
		log.Println("Could not open capture", err)
		return
	}

	if config.AutoSavePcapFiles {
		pcapFile, err = os.Create(time.Now().Format("06-01-02 15.04.05") + ".pcapng")
		if err != nil {
			log.Println("Could not create pcapng file", err)
		}
		defer pcapFile.Close()
	}

	startSniffer()
}

func closeHandle() {
	if captureHandler != nil {
		captureHandler.Close()
		captureHandler = nil
	}
	if pcapFile != nil {
		pcapFile.Close()
		pcapFile = nil
	}
}

func readKeys() {
	var initialKeyJson map[uint32]string
	file, err := ioutil.ReadFile("./data/Keys.json")
	if err != nil {
		log.Fatal("Could not load initial key @ ./data/Keys.json #1", err)
	}
	err = json.Unmarshal(file, &initialKeyJson)
	if err != nil {
		log.Fatal("Could not load initial key @ ./data/Keys.json #2", err)
	}

	for k, v := range initialKeyJson {
		decode, _ := base64.RawStdEncoding.DecodeString(v)
		initialKey[k] = decode
	}

	playerGetTokenScRspPacketId = packetNameMap["PlayerGetTokenScRsp"]
}

func startSniffer() {
	defer captureHandler.Close()

	err := captureHandler.SetBPFFilter("udp portrange 23301-23302")
	if err != nil {
		log.Println("Could not set the filter of capture")
		return
	}

	packetSource := gopacket.NewPacketSource(captureHandler, captureHandler.LinkType())
	packetSource.NoCopy = true

	kcpMap = make(map[string]*kcp.KCP)

	var pcapWriter *pcapgo.NgWriter
	if pcapFile != nil {
		pcapWriter, err = pcapgo.NewNgWriter(pcapFile, captureHandler.LinkType())
		if err != nil {
			log.Println("Could not create pcapng writer", err)
		}
	}

	for packet := range packetSource.Packets() {
		if pcapWriter != nil {
			err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				log.Println("Could not write packet to pcap file", err)
			}
		}

		capTime := packet.Metadata().Timestamp
		data := packet.ApplicationLayer().Payload()
		udp := packet.TransportLayer().(*layers.UDP)
		fromServer := udp.SrcPort == 23301 || udp.SrcPort == 23302

		if len(data) <= 20 {
			handleSpecialPacket(data, fromServer, capTime)
			continue
		}

		handleKcp(data, fromServer, capTime)
	}
}

func handleKcp(data []byte, fromServer bool, capTime time.Time) {
	data = reformData(data)
	conv := binary.LittleEndian.Uint32(data[:4])
	key := strconv.Itoa(int(conv))
	if fromServer {
		key += "svr"
	} else {
		key += "cli"
	}

	if _, ok := kcpMap[key]; !ok {
		kcpInstance := kcp.NewKCP(conv, func(buf []byte, size int) {})
		kcpInstance.WndSize(1024, 1024)
		kcpMap[key] = kcpInstance
	}
	kcpInstance := kcpMap[key]
	_ = kcpInstance.Input(data, true, true)

	size := kcpInstance.PeekSize()
	for size > 0 {
		kcpBytes := make([]byte, size)
		kcpInstance.Recv(kcpBytes)
		handleProtoPacket(kcpBytes, fromServer, capTime)
		size = kcpInstance.PeekSize()
	}
	kcpInstance.Update()
}

func handleSpecialPacket(data []byte, fromServer bool, timestamp time.Time) {
	sessionKey = nil
	switch binary.BigEndian.Uint32(data[:4]) {
	case 0xFF:
		buildPacketToSend(data, fromServer, timestamp, 0, "Hamdshanke pls.")
		break
	case 404:
		buildPacketToSend(data, fromServer, timestamp, 0, "Disconnected.")
		break
	default:
		buildPacketToSend(data, fromServer, timestamp, 0, "Hamdshanke estamblished.")
		break
	}
}

func handleProtoPacket(data []byte, fromServer bool, timestamp time.Time) {
	key := binary.BigEndian.Uint32(data[:8])
	key = key ^ 0x9D74C714 // Magic Start for SR
	var xorPad []byte

	if sessionKey != nil {
		xorPad = sessionKey
	} else {
		if len(initialKey[key]) == 0 {
			log.Println("Could not found initial key to decrypt", key)
			closeHandle()
		}
		xorPad = initialKey[key]
	}
	if xorPad == nil {
		log.Println("Could not found key to decrypt", key)
		return
	}
	xorDecrypt(data, xorPad)

	packetId := binary.BigEndian.Uint16(data[4:6])
	var objectJson interface{}

	if packetId == playerGetTokenScRspPacketId {
		data, objectJson = handlePlayerGetTokenScRspPacket(data, packetId, objectJson)
	} else {
		data = removeHeaderForParse(data)
		objectJson = parseProtoToInterface(packetId, data)
	}

	buildPacketToSend(data, fromServer, timestamp, packetId, objectJson)
}

func handlePlayerGetTokenScRspPacket(data []byte, packetId uint16, objectJson interface{}) ([]byte, interface{}) {
	data = removeMagic(data)
	dMsg, err := parseProto(packetId, data)
	if err != nil {
		log.Println("Could not parse PlayerGetTokenScRsp proto", err)
		closeHandle()
	}
	oj, err := dMsg.MarshalJSON()
	if err != nil {
		log.Println("Could not parse PlayerGetTokenScRsp proto", err)
		closeHandle()
	}
	err = json.Unmarshal(oj, &objectJson)
	if err != nil {
		log.Println("Could not parse PlayerGetTokenScRsp proto", err)
		closeHandle()
	}
	seed := dMsg.GetFieldByName("secret_key_seed").(uint64)
	sessionKey = createXorPad(seed)

	return data, objectJson
}

func buildPacketToSend(data []byte, fromSever bool, timestamp time.Time, packetId uint16, objectJson interface{}) {
	packet := &Packet{
		Time:       timestamp.UnixMilli(),
		FromServer: fromSever,
		PacketId:   packetId,
		PacketName: GetProtoNameById(packetId),
		Object:     objectJson,
		Raw:        data,
	}

	jsonResult, err := json.Marshal(packet)
	if err != nil {
		log.Println("Json marshal error", err)
	}
	logPacket(packet)

	if packetFilter[GetProtoNameById(packetId)] {
		return
	}
	sendStreamMsg(string(jsonResult))
}

func logPacket(packet *Packet) {
	from := "[Client]"
	if packet.FromServer {
		from = "[Server]"
	}
	forward := ""
	if strings.Contains(packet.PacketName, "ScRsp") {
		forward = "<--"
	} else if strings.Contains(packet.PacketName, "CsReq") {
		forward = "-->"
	} else if strings.Contains(packet.PacketName, "Notify") && packet.FromServer {
		forward = "<-i"
	} else if strings.Contains(packet.PacketName, "Notify") {
		forward = "i->"
	}

	log.Println(color.GreenString(from),
		"\t",
		color.CyanString(forward),
		"\t",
		color.RedString(packet.PacketName),
		color.YellowString("#"+strconv.Itoa(int(packet.PacketId))),
		"\t",
		len(packet.Raw),
	)
}
