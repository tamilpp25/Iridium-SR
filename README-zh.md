# Iridium-NG

A KCP packet sniffer + visualizer in one, backend rewritten in Go.

![Build](https://github.com/Akka0/Iridium-NG/actions/workflows/build.yml/badge.svg)

# 用法

你可以从Actions中下载到编译好的，或者自己从源码构建。

0. 往 `data/` 目录放入 `packetIds.json`, `Keys.json` 和 `proto/` 文件.
1. 确保你已安装 [Npcap driver](https://npcap.com/#download) 或 wireshark.
2. 使用命令 `-l` 列出电脑上所有网卡，编辑 `config.json` 设置网卡设备, 或者使用命令 `-ip 192.x.x.x` 自动通过ip寻找设备.
3. 打开 http://localhost:1984/, 

**注意：在进门之前开始抓包**

# Config.json

```json
{
  "deviceName" : "", // 网络设备名称, 例如 eth0
  "packetFilter" : [ // 这里列出的包名将不会在前端显示
    ""
  ],
  "autoSavePcapFiles" : true, // 自动保存抓包记录文件
  "maxKcpPort": "23301", // 最大服务器kcp端口
  "minKcpPort": "23302" // 重小服务器kcp端口
}
```
