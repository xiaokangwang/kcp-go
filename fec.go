package kcp

import "encoding/binary"

const (
	fecHeaderSize = 6
	typeData      = 0
	typeFEC       = 1
)

// FEC defines forward error correction for a KCP connection
type FEC struct {
	rx    []fecPacket
	rxlen int
	group int // fec group size
	seqid uint32
}

type fecPacket struct {
	seqid uint32
	isfec uint16
	data  []byte
}

func newFEC(group, rxlen int) *FEC {
	if group < 2 || rxlen < group {
		return nil
	}

	fec := new(FEC)
	fec.group = group
	fec.rxlen = rxlen
	return fec
}

// decode a fec packet
func fecDecode(data []byte) fecPacket {
	var pkt fecPacket
	pkt.seqid = binary.LittleEndian.Uint32(data)
	pkt.isfec = binary.LittleEndian.Uint16(data[4:])
	pkt.data = make([]byte, len(data[fecHeaderSize:]))
	copy(pkt.data, data[fecHeaderSize:])
	return pkt
}

// add header data of FEC, invoker must keep data[:fecHeaderSize] free
// no allocations will be made by fec module
func (fec *FEC) markData(data []byte) {
	binary.LittleEndian.PutUint32(data, fec.seqid)
	binary.LittleEndian.PutUint16(data[4:], typeData)
	fec.seqid++
}

func (fec *FEC) markFEC(data []byte) {
	binary.LittleEndian.PutUint32(data, fec.seqid)
	binary.LittleEndian.PutUint16(data[4:], typeFEC)
	fec.seqid++
}

// input a fec packet
func (fec *FEC) input(pkt fecPacket) []byte {
	n := len(fec.rx) - 1
	insert_idx := 0
	for i := n; i >= 0; i-- {
		if pkt.seqid == fec.rx[i].seqid { // de-duplicate
			return nil
		} else if pkt.seqid > fec.rx[i].seqid { // insertion
			insert_idx = i + 1
			break
		}
	}

	// insert into ordered rx queue
	if insert_idx == n+1 {
		fec.rx = append(fec.rx, pkt)
	} else if insert_idx == 0 {
		rx := make([]fecPacket, n+1)
		rx[0] = pkt
		copy(rx[1:], fec.rx)
		fec.rx = rx
	} else {
		rx := make([]fecPacket, n+1)
		copy(rx, fec.rx[:insert_idx])
		rx[insert_idx] = pkt
		copy(rx[insert_idx+1:], fec.rx[insert_idx:])
		fec.rx = rx
	}

	var recovered []byte
	for i := insert_idx; i < len(fec.rx); i++ {
		if fec.rx[i].isfec == typeFEC {
			ecc := &fec.rx[i]
			first := i - fec.group
			if first >= 0 && fec.rx[first].seqid == ecc.seqid-uint32(fec.group) {
				// normal flow, eg: [1,2,3,[4]]
				copy(fec.rx[first:], fec.rx[i+1:])
				fec.rx = fec.rx[:len(fec.rx)-fec.group-1]
				break
			} else if first+1 >= 0 && (fec.rx[first+1].seqid == ecc.seqid-uint32(fec.group) ||
				fec.rx[first+1].seqid == ecc.seqid-uint32(fec.group)+1) {
				// recoverable data, eg: [2,3,[4]], [1,3,[4]], [1,2,[4]]
				recovered = make([]byte, len(ecc.data))
				copy(recovered, fec.rx[first+1].data)
				for j := first + 2; j <= i; j++ {
					buf := make([]byte, len(ecc.data))
					copy(buf, fec.rx[j].data)
					xorBytes(recovered, recovered, buf)
				}
				copy(fec.rx[first+1:], fec.rx[i+1:])
				fec.rx = fec.rx[:len(fec.rx)-fec.group]
				break
			} else {
				break
			}
		}
	}

	// keep rxlen
	if len(fec.rx) > fec.rxlen {
		fec.rx = fec.rx[1:]
	}

	return recovered
}

func (fec *FEC) calcECC(data [][]byte) []byte {
	if len(data) != fec.group {
		return nil
	}

	maxlen := 0
	for k := range data {
		if maxlen < len(data[k]) {
			maxlen = len(data[k])
		}
	}

	ecc := make([]byte, maxlen)
	copy(ecc, data[0])
	for i := 1; i < len(data); i++ {
		buf := make([]byte, maxlen)
		copy(buf, data[i])
		xorBytes(ecc, ecc, buf)
	}

	return ecc
}
