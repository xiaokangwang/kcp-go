package kcp

import "encoding/binary"

const (
	fecHeaderSize = 6
	typeData      = 0
	typeFEC       = 1<<16 - 1
)

// FEC defines forward error correction for packets
type FEC struct {
	rx      []fecPacket // orderedr rx queue
	rxlimit int
	cluster int // fec cluster size
	seqid   uint32
}

type fecPacket struct {
	seqid uint32
	isfec uint16
	data  []byte
}

func newFEC(cluster, rxlimit int) *FEC {
	if cluster < 2 || rxlimit < cluster {
		return nil
	}

	fec := new(FEC)
	fec.cluster = cluster
	fec.rxlimit = rxlimit
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
			first := i - fec.cluster
			if first >= 0 && fec.rx[first].seqid == ecc.seqid-uint32(fec.cluster) {
				// normal flow, eg: [1,2,3,[4]]
				copy(fec.rx[first:], fec.rx[i+1:])
				fec.rx = fec.rx[:len(fec.rx)-fec.cluster-1]
				break
			} else if first+1 >= 0 && (fec.rx[first+1].seqid == ecc.seqid-uint32(fec.cluster) ||
				fec.rx[first+1].seqid == ecc.seqid-uint32(fec.cluster)+1) {
				// recoverable data, eg: [2,3,[4]], [1,3,[4]], [1,2,[4]]
				recovered = make([]byte, len(ecc.data))
				xorBytes(recovered, fec.rx[first+1].data, fec.rx[first+2].data)
				for j := first + 3; j <= i; j++ {
					xorBytes(recovered, recovered, fec.rx[j].data)
				}
				copy(fec.rx[first+1:], fec.rx[i+1:])
				fec.rx = fec.rx[:len(fec.rx)-fec.cluster]
				break
			} else {
				break
			}
		}
	}

	// keep rxlen
	if len(fec.rx) > fec.rxlimit {
		fec.rx = fec.rx[1:]
	}

	return recovered
}

func (fec *FEC) calcECC(data [][]byte) []byte {
	if len(data) != fec.cluster {
		return nil
	}

	maxlen := len(data[0])
	for i := 1; i < len(data); i++ {
		if maxlen < len(data[i]) {
			maxlen = len(data[i])
		}
	}

	ecc := make([]byte, maxlen)
	xorBytes(ecc, data[0], data[1])
	for i := 2; i < len(data); i++ {
		xorBytes(ecc, ecc, data[i])
	}
	return ecc
}
