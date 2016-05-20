package kcp

import "encoding/binary"

const (
	fecHeaderSize = 6
	typeData      = 0
	typeFEC       = 1
)

// FEC defines forward error correction for a KCP connection
type FEC struct {
	kcp   *KCP
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

func newFEC(kcp *KCP, group, rxlen int) *FEC {
	if group < 2 || rxlen < group {
		return nil
	}

	fec := new(FEC)
	fec.kcp = kcp
	fec.group = group
	fec.rxlen = rxlen
	return fec
}

// decode a fec packet
func (fec *FEC) decode(data []byte) fecPacket {
	var pkt fecPacket
	pkt.seqid = binary.LittleEndian.Uint32(data)
	pkt.isfec = binary.LittleEndian.Uint16(data[4:])
	pkt.data = data[fecHeaderSize:]
	return pkt
}

// add header data of FEC, invoker must keep data[:fecHeaderSize] free
// no allocations will be made by fec module
func (fec *FEC) addheader(data []byte) {
	binary.LittleEndian.PutUint32(data, fec.seqid)
	binary.LittleEndian.PutUint16(data[4:], typeData)
	fec.seqid++
}

// input a fec packet
func (fec *FEC) input(data []byte) []byte {
	if len(data) < fecHeaderSize {
		return nil
	}

	pkt := fec.decode(data)
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
			if first < -1 {
				break
			}

			if fec.rx[first].seqid == ecc.seqid-uint32(fec.group) {
				// normal flow, eg: [1,2,3,[4]]
				copy(fec.rx[first:], fec.rx[i+1:])
				fec.rx = fec.rx[:len(fec.rx)-fec.group]
				break
			} else if fec.rx[first+1].seqid == ecc.seqid-uint32(fec.group) ||
				fec.rx[first+1].seqid == ecc.seqid-uint32(fec.group)+1 {
				// recoverable data, eg: [2,3,[4]], [1,3,[4]], [1,2,[4]]
				recovered = make([]byte, len(ecc.data))
				xorBytes(recovered, fec.rx[first].data, fec.rx[first+1].data)
				for j := first + 2; j < i; j++ {
					xorBytes(recovered, recovered, fec.rx[j].data)
				}
				copy(fec.rx[first:], fec.rx[i+1:])
				fec.rx = fec.rx[:len(fec.rx)-fec.group+1]
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

// genfec must be called after addheader
func (fec *FEC) genfec(seqid uint32, data ...[]byte) []byte {
	if len(data) != fec.group {
		return nil
	}

	maxlen := 0
	for k := range data {
		if maxlen < len(data[k]) {
			maxlen = len(data[k])
		}
	}

	if maxlen < 0 {
		return nil
	}

	ecc := make([]byte, maxlen+2)
	xorBytes(ecc, data[0], data[1])
	for i := 2; i < len(data); i++ {
		xorBytes(ecc, ecc, data[i])
	}

	// overwrite header content
	binary.LittleEndian.PutUint32(ecc, seqid)
	binary.LittleEndian.PutUint16(ecc[4:], typeFEC)
	return ecc
}
