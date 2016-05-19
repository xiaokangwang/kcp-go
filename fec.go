package kcp

import "encoding/binary"

// FEC defines forward error correction for a KCP connection
type FEC struct {
	kcp     *KCP
	packets []fecPacket
	size    int // fec group size
}

type fecPacket struct {
	seqid  uint32
	length uint16
	hasFec uint16
	date   []byte
}

func newFEC(kcp *KCP, size int) *FEC {
	if size < 2 {
		return nil
	}

	fec := new(FEC)
	fec.kcp = kcp
	fec.size = size
	return fec
}

func (fec *FEC) decode(data []byte) fecPacket {
	var packet fecPacket
	packet.seqid = binary.LittleEndian.Uint32(data)
	packet.length = binary.LittleEndian.Uint16(data[4:])
	packet.hasFec = binary.LittleEndian.Uint16(data[6:])
	return packet
}

func (fec *FEC) input(data []byte) []byte {
	return nil
}

func (fec *FEC) generate(data ...[]byte) []byte {
	if len(data) != fec.size {
		return nil
	}

	code := make([]byte, fec.maxlength(data...)+fecHeaderSize)
	xorBytes(code, data[0], data[1])
	for i := 2; i < len(data); i++ {
		xorBytes(code, code, data[i])
	}

	return code
}

func (fec *FEC) maxlength(data ...[]byte) int {
	max := len(data[0])
	for i := 1; i < len(data); i++ {
		if len(data[i]) > max {
			max = len(data[i])
		}
	}
	return max
}
