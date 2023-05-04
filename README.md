# Iridium-NG

A KCP packet sniffer + visualizer in one, backend rewritten in Go.

![Build](https://github.com/Akka0/Iridium-NG/actions/workflows/build.yml/badge.svg)

[中文说明](/README-zh.md)

# Usage

You can download the binary(win/linux) from Actions, or build from source

0. Bring your `packetIds.json` and `proto/` to the `data/` folder.
1. Make sure you have installed [Npcap driver](https://npcap.com/#download) or wireshark.
2. Use cmd `-l` to list the network devices on your computer and edit `config.json` to set the device by its name, or use cmd `-ip 192.x.x.x` to let it auto find the device by its ip.
3. Open http://localhost:1984/

**Notice: START CAPTURE BEFORE YOU ENTER THE DOOR**

# Config.json

```json
{
  "deviceName" : "", // network device name, such as eth0
  "packetFilter" : [ // the packets listed here will not show in frontend
    ""
  ],
  "autoSavePcapFiles" : true // auto save capture to current folder
}
```

