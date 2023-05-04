package main

import (
	"bytes"
	"encoding/binary"
)

func removeMagic(data []byte) []byte {
	cut := data[7]
	data = data[10+2:]           // Removes token + four byte magic
	data = data[0 : len(data)-4] // Removes four byte magic at the end
	data = data[cut:]
	return data
}

func removeHeaderForParse(data []byte) []byte {
	cut := data[8]
	data = removeMagic(data)
	return data[cut:]
}

func xorDecrypt(data []byte, key []byte) {
	for i := 0; i < len(data); i++ {
		data[i] = data[i] ^ key[i%len(key)]
	}
}

func reformData(data []byte) []byte {
	i := 0
	tokenSizeTotal := 0
	var messages [][]byte
	for i < len(data) {
		convId := data[i : i+4]
		remainingHeader := data[i+8 : i+28]
		contentLen := int(binary.LittleEndian.Uint32(data[i+24 : i+28]))
		content := data[i+28 : (i + 28 + contentLen)]

		formattedMessage := make([]byte, 24+contentLen)
		copy(formattedMessage, convId)
		copy(formattedMessage[4:], remainingHeader)
		copy(formattedMessage[24:], content)
		i += 28 + contentLen
		tokenSizeTotal += 4
		messages = append(messages, formattedMessage)
	}

	return bytes.Join(messages, []byte{})
}

func createXorPad(seed uint64) []byte {
	first := New()
	first.Seed(int64(seed))
	// generator := New()
	// generator.Seed(first.Generate())
	// generator.Generate()
	xorPad := make([]byte, 4096)

	for i := 0; i < 4096; i += 8 {
		value := first.Generate()
		binary.BigEndian.PutUint64(xorPad[i:i+8], uint64(value))
	}
	return xorPad
}
