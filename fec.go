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
}

type fecPacket struct {
	seqid uint32
	isfec uint16
	data  []byte
}

func newFEC(kcp *KCP, group, rxlen int) *FEC {
	if group < 1 || rxlen < group {
		return nil
	}

	fec := new(FEC)
	fec.kcp = kcp
	fec.group = group
	fec.rxlen = rxlen
	return fec
}

func (fec *FEC) decode(data []byte) *fecPacket {
	packet := new(fecPacket)
	packet.seqid = binary.LittleEndian.Uint32(data)
	packet.isfec = binary.LittleEndian.Uint16(data[4:])
	return packet
}

func (fec *FEC) input(data []byte) []byte {
	if len(data) < fecHeaderSize {
		return nil
	}

	pkt := fec.decode(data)
	if pkt == nil {
		return nil
	}

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

	if insert_idx == n+1 {
		fec.rx = append(fec.rx, *pkt)
	} else if insert_idx == 0 {
		rx := make([]fecPacket, n+1)
		rx[0] = *pkt
		copy(rx[1:], fec.rx)
		fec.rx = rx
	} else {
		rx := make([]fecPacket, n+1)
		copy(rx, fec.rx[:insert_idx])
		rx[insert_idx] = *pkt
		copy(rx[insert_idx+1:], fec.rx[insert_idx:])
		fec.rx = rx
	}

	if insert_idx < fec.group {
		return nil
	}

	var recover []byte
	for i := insert_idx; i < len(fec.rx); i++ {
		if fec.rx[i].isfec == typeFEC {
			first := i - fec.group
			if fec.rx[first].seqid == fec.rx[i].seqid-uint32(fec.group) { // no lost
				copy(fec.rx[first:], fec.rx[i+1:])
				fec.rx = fec.rx[:len(fec.rx)-fec.group-1]
				break
			} else if fec.rx[first+1].seqid == fec.rx[i].seqid-uint32(fec.group) ||
				fec.rx[first+1].seqid == fec.rx[i].seqid-uint32(fec.group)+1 { // recoverable
				recover = make([]byte, 2048)
				xorBytes(recover, fec.rx[first].data, fec.rx[first+1].data)
				for j := first + 2; j < i; j++ {
					xorBytes(recover, recover, fec.rx[j].data)
				}
				copy(fec.rx[first:], fec.rx[i+1:])
				fec.rx = fec.rx[:len(fec.rx)-fec.group]
			} else {
				break
			}
		}
	}

	if len(fec.rx) > fec.rxlen {
		fec.rx = fec.rx[1:]
	}

	return recover
}

func (fec *FEC) genfec(seqid uint32, data ...[]byte) []byte {
	if len(data) != fec.group {
		return nil
	}

	recover := make([]byte, fec.maxlength(data...))
	xorBytes(recover, data[0], data[1])
	for i := 2; i < len(data); i++ {
		xorBytes(recover, recover, data[i])
	}
	// overwrite header content
	binary.LittleEndian.PutUint32(recover, seqid)
	binary.LittleEndian.PutUint16(recover[4:], typeFEC)
	return recover
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
