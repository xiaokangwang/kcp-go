package kcp

// FEC defines forward error correction for a KCP connection
type FEC struct {
	kcp       *KCP
	rcv_queue [][]byte
	snd_queue [][]byte
	size      int // fec group size
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

func (fec *FEC) correct(data []byte) []byte {
	return nil
}

func (fec *FEC) calc(data ...[]byte) []byte {
	if len(data) != fec.size {
		return nil
	}
	code := make([]byte, fec.maxlength(data...))
	xorBytes(data[0], data[0], data[1])
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
