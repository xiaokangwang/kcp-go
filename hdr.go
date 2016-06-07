package kcp

import "encoding/binary"

const (
	HEADER_NONCE_LEN      = 16
	HEADER_CRC32_LEN      = 4
	HEADER_FRAME_TYPE_LEN = 2
	HEADER_LENGTH_LEN     = 2
)

const (
	HEADER_CRC32_OFFSET      = HEADER_NONCE_LEN
	HEADER_FRAME_TYPE_OFFSET = HEADER_CRC32_OFFSET + HEADER_CRC32_LEN
	HEADER_LENGTH_OFFSET     = HEADER_FRAME_TYPE_OFFSET + HEADER_FRAME_TYPE_LEN
	HEADER_SEQID_OFFSET      = HEADER_LENGTH_OFFSET + HEADER_LENGTH_LEN
)

type FrameType int

const (
	FRAME_TYPE_DATA = FrameType(iota)
	FRAME_TYPE_FEC
	FRAME_TYPE_PING
	FRAME_TYPE_SNMP
)

func hdrSetNonce(header []byte, nonce []byte) {
	copy(header[:HEADER_NONCE_LEN], nonce)
}

func hdrSetCrc32(header []byte, crc32 uint32) {
	binary.LittleEndian.PutUint32(header[HEADER_NONCE_LEN:], crc32)
}

func hdrSetFrameType(header []byte, typ FrameType) {
	switch typ {
	case FRAME_TYPE_DATA:
		header[HEADER_FRAME_TYPE_OFFSET] |= 128
	case FRAME_TYPE_FEC:
		header[HEADER_FRAME_TYPE_OFFSET] |= 64
	case FRAME_TYPE_PING:
		header[HEADER_FRAME_TYPE_OFFSET] |= 32
	case FRAME_TYPE_SNMP:
		header[HEADER_FRAME_TYPE_OFFSET] |= 16
	}
}

func hdrSetDataLength(header []byte, length uint16) {
	binary.LittleEndian.PutUint16(header[HEADER_LENGTH_OFFSET:], length)
}

func hdrSetSeqId(header []byte, seqid uint32) {
	binary.LittleEndian.PutUint32(header[HEADER_LENGTH_OFFSET:], seqid)
}
