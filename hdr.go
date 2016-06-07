package kcp

import "encoding/binary"

// lengths
const (
	HLEN_NONCE      = 16
	HLEN_CRC32      = 4
	HLEN_FRAME_TYPE = 2
	HLEN_DATASIZE   = 2
)

// offsets
const (
	HOFF_CRC32      = HLEN_NONCE
	HOFF_FRAME_TYPE = HOFF_CRC32 + HLEN_CRC32
	HOFF_DATASIZE   = HOFF_FRAME_TYPE + HLEN_FRAME_TYPE
	HOFF_SEQID      = HOFF_DATASIZE + HLEN_DATASIZE
)

type FrameType int

const (
	FRAME_TYPE_UNKNOWN = FrameType(iota)
	FRAME_TYPE_DATA
	FRAME_TYPE_FEC
	FRAME_TYPE_PING
	FRAME_TYPE_SNMP
)

func hdrSetNonce(header []byte, nonce []byte) {
	copy(header[:HLEN_NONCE], nonce)
}

func hdrSetCRC(header []byte, crc32 uint32) {
	binary.LittleEndian.PutUint32(header[HOFF_CRC32:], crc32)
}

func hdrGetCRC(header []byte) uint32 {
	return binary.LittleEndian.Uint32(header[HOFF_CRC32:])
}

func hdrSetFrameType(header []byte, typ FrameType) {
	switch typ {
	case FRAME_TYPE_DATA:
		header[HOFF_FRAME_TYPE] |= 128
	case FRAME_TYPE_FEC:
		header[HOFF_FRAME_TYPE] |= 64
	case FRAME_TYPE_PING:
		header[HOFF_FRAME_TYPE] |= 32
	case FRAME_TYPE_SNMP:
		header[HOFF_FRAME_TYPE] |= 16
	}
}

func hdrGetFrameType(header []byte) FrameType {
	if header[HOFF_FRAME_TYPE]&128 != 0 {
		return FRAME_TYPE_DATA
	}

	if header[HOFF_FRAME_TYPE]&64 != 0 {
		return FRAME_TYPE_FEC
	}

	if header[HOFF_FRAME_TYPE]&32 != 0 {
		return FRAME_TYPE_PING
	}

	if header[HOFF_FRAME_TYPE]&16 != 0 {
		return FRAME_TYPE_SNMP
	}

	return FRAME_TYPE_UNKNOWN
}

func hdrSetSize(header []byte, size uint16) {
	binary.LittleEndian.PutUint16(header[HOFF_DATASIZE:], size)
}

func hdrGetSize(header []byte) uint16 {
	return binary.LittleEndian.Uint16(header[HOFF_DATASIZE:])
}

func hdrSetSeqId(header []byte, seqid uint32) {
	binary.LittleEndian.PutUint32(header[HOFF_SEQID:], seqid)
}

func hdrGetSeqId(header []byte) uint32 {
	return binary.LittleEndian.Uint32(header[HOFF_SEQID:])
}
