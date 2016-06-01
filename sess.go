package kcp

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/net/ipv4"
)

var (
	errTimeout    = errors.New("i/o timeout")
	errBrokenPipe = errors.New("broken pipe")
	initialVector = []byte{167, 115, 79, 156, 18, 172, 27, 1, 164, 21, 242, 193, 252, 120, 230, 107}
	salt          = "kcp-go"
)

const (
	basePort        = 20000         // minimum port for listening
	maxPort         = 65535         // maximum port for listening
	defaultWndSize  = 128           // default window size, in packet
	otpSize         = aes.BlockSize // magic number
	crcSize         = 4             // 4bytes packet checksum
	cryptHeaderSize = otpSize + crcSize
	connTimeout     = 60 * time.Second
	mtuLimit        = 4096
)

type (
	// UDPSession defines a KCP session implemented by UDP
	UDPSession struct {
		kcp           *KCP         // the core ARQ
		fec           *FEC         // forward error correction
		conn          *net.UDPConn // the underlying UDP socket
		block         cipher.Block
		needUpdate    bool
		l             *Listener // point to server listener if it's a server socket
		local, remote net.Addr
		rd            time.Time // read deadline
		wd            time.Time // write deadline
		sockbuff      []byte    // kcp receiving is based on packet, I turn it into stream
		die           chan struct{}
		isClosed      bool
		mu            sync.Mutex
		chReadEvent   chan struct{}
		chWriteEvent  chan struct{}
		chTicker      chan time.Time
		chUDPOutput   chan []byte
		headerSize    int
		lastInputTs   time.Time
		ackNoDelay    bool
	}
)

// newUDPSession create a new udp session for client or server
func newUDPSession(conv uint32, fec int, l *Listener, conn *net.UDPConn, remote *net.UDPAddr, block cipher.Block) *UDPSession {
	sess := new(UDPSession)
	sess.chTicker = make(chan time.Time, 1)
	sess.chUDPOutput = make(chan []byte, defaultWndSize)
	sess.die = make(chan struct{})
	sess.local = conn.LocalAddr()
	sess.chReadEvent = make(chan struct{}, 1)
	sess.chWriteEvent = make(chan struct{}, 1)
	sess.remote = remote
	sess.conn = conn
	sess.l = l
	sess.block = block
	sess.lastInputTs = time.Now()
	if fec > 0 {
		sess.fec = newFEC(fec, 128)
	}

	// caculate header size
	if sess.block != nil {
		sess.headerSize += cryptHeaderSize
	}
	if sess.fec != nil {
		sess.headerSize += fecHeaderSizePlus2
	}

	sess.kcp = NewKCP(conv, func(buf []byte, size int) {
		if size >= IKCP_OVERHEAD {
			ext := make([]byte, sess.headerSize+size)
			copy(ext[sess.headerSize:], buf)
			sess.chUDPOutput <- ext
		}
	})
	sess.kcp.WndSize(defaultWndSize, defaultWndSize)
	sess.kcp.SetMtu(IKCP_MTU_DEF - sess.headerSize)

	go sess.updateTask()
	go sess.outputTask()
	if l == nil { // it's a client connection
		go sess.readLoop()
	}

	if l == nil {
		atomic.AddUint64(&DefaultSnmp.ActiveOpens, 1)
	} else {
		atomic.AddUint64(&DefaultSnmp.PassiveOpens, 1)
	}
	atomic.AddUint64(&DefaultSnmp.CurrEstab, 1)

	return sess
}

// Read implements the Conn Read method.
func (s *UDPSession) Read(b []byte) (n int, err error) {
	for {
		s.mu.Lock()
		if len(s.sockbuff) > 0 { // copy from buffer
			n = copy(b, s.sockbuff)
			s.sockbuff = s.sockbuff[n:]
			s.mu.Unlock()
			return n, nil
		}

		if s.isClosed {
			s.mu.Unlock()
			return 0, errBrokenPipe
		}

		if !s.rd.IsZero() {
			if time.Now().After(s.rd) { // timeout
				s.mu.Unlock()
				return 0, errTimeout
			}
		}

		if n := s.kcp.PeekSize(); n > 0 { // data arrived
			if len(b) >= n {
				s.kcp.Recv(b)
			} else {
				buf := make([]byte, n)
				s.kcp.Recv(buf)
				n = copy(b, buf)
				s.sockbuff = buf[n:] // store remaining bytes into sockbuff for next read
			}
			s.mu.Unlock()
			atomic.AddUint64(&DefaultSnmp.BytesReceived, uint64(n))
			return n, nil
		}

		var timeout <-chan time.Time
		if !s.rd.IsZero() {
			delay := s.rd.Sub(time.Now())
			timeout = time.After(delay)
		}
		s.mu.Unlock()

		// wait for read event or timeout
		select {
		case <-s.chReadEvent:
		case <-timeout:
		}
	}
}

// Write implements the Conn Write method.
func (s *UDPSession) Write(b []byte) (n int, err error) {
	for {
		s.mu.Lock()
		if s.isClosed {
			s.mu.Unlock()
			return 0, errBrokenPipe
		}

		if !s.wd.IsZero() {
			if time.Now().After(s.wd) { // timeout
				s.mu.Unlock()
				return 0, errTimeout
			}
		}

		if s.kcp.WaitSnd() < int(s.kcp.snd_wnd) {
			n = len(b)
			max := s.kcp.mss << 8
			for {
				if len(b) <= int(max) { // in most cases
					s.kcp.Send(b)
					break
				} else {
					s.kcp.Send(b[:max])
					b = b[max:]
				}
			}
			s.kcp.current = currentMs()
			s.kcp.flush()
			s.mu.Unlock()
			atomic.AddUint64(&DefaultSnmp.BytesSent, uint64(n))
			return n, nil
		}

		var timeout <-chan time.Time
		if !s.wd.IsZero() {
			delay := s.wd.Sub(time.Now())
			timeout = time.After(delay)
		}
		s.mu.Unlock()

		// wait for write event or timeout
		select {
		case <-s.chWriteEvent:
		case <-timeout:
		}
	}
}

// Close closes the connection.
func (s *UDPSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed {
		return errBrokenPipe
	}
	close(s.die)
	s.isClosed = true
	if s.l == nil { // client socket close
		s.conn.Close()
	}

	atomic.AddUint64(&DefaultSnmp.CurrEstab, ^uint64(0))
	return nil
}

// LocalAddr returns the local network address. The Addr returned is shared by all invocations of LocalAddr, so do not modify it.
func (s *UDPSession) LocalAddr() net.Addr {
	return s.local
}

// RemoteAddr returns the remote network address. The Addr returned is shared by all invocations of RemoteAddr, so do not modify it.
func (s *UDPSession) RemoteAddr() net.Addr { return s.remote }

// SetDeadline sets the deadline associated with the listener. A zero time value disables the deadline.
func (s *UDPSession) SetDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rd = t
	s.wd = t
	return nil
}

// SetReadDeadline implements the Conn SetReadDeadline method.
func (s *UDPSession) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rd = t
	return nil
}

// SetWriteDeadline implements the Conn SetWriteDeadline method.
func (s *UDPSession) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wd = t
	return nil
}

// SetWindowSize set maximum window size
func (s *UDPSession) SetWindowSize(sndwnd, rcvwnd int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kcp.WndSize(sndwnd, rcvwnd)
}

// SetMtu sets the maximum transmission unit
func (s *UDPSession) SetMtu(mtu int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kcp.SetMtu(mtu - s.headerSize)
}

// SetACKNoDelay changes ack flush option, set true to flush ack immediately,
func (s *UDPSession) SetACKNoDelay(nodelay bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ackNoDelay = nodelay
}

// SetNoDelay calls nodelay() of kcp
func (s *UDPSession) SetNoDelay(nodelay, interval, resend, nc int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kcp.NoDelay(nodelay, interval, resend, nc)
}

// SetDSCP sets the DSCP field of IP header
func (s *UDPSession) SetDSCP(tos int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ipv4.NewConn(s.conn).SetTOS(tos << 2); err != nil {
		log.Println("set tos:", err)
	}
}

func (s *UDPSession) outputTask() {
	encbuf := make([]byte, aes.BlockSize)
	fecOffset := 0
	if s.block != nil {
		fecOffset = cryptHeaderSize
	}
	var fec_group [][]byte
	var fec_cnt int
	if s.fec != nil {
		// fec group buffer
		fec_group = make([][]byte, s.fec.cluster)
		for i := 0; i < len(fec_group); i++ {
			fec_group[i] = make([]byte, mtuLimit)
		}
	}

	// ping
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case ext := <-s.chUDPOutput:
			var ecc []byte
			if s.fec != nil {
				s.fec.markData(ext[fecOffset:])
				// add 2B size
				binary.LittleEndian.PutUint16(ext[fecOffset+fecHeaderSize:], uint16(len(ext[fecOffset+fecHeaderSize:])))

				// copy data to fec group
				copy(fec_group[fec_cnt][:mtuLimit], ext)
				fec_group[fec_cnt] = fec_group[fec_cnt][:len(ext)]
				fec_cnt++

				// cacluation of ecc
				if fec_cnt == s.fec.cluster {
					ecc = s.fec.calcECC(fec_group)
					s.fec.markFEC(ecc[fecOffset:])
					fec_cnt = 0
				}
			}

			if s.block != nil {
				io.ReadFull(crand.Reader, ext[:otpSize]) // OTP
				checksum := crc32.ChecksumIEEE(ext[cryptHeaderSize:])
				binary.LittleEndian.PutUint32(ext[otpSize:], checksum)
				encrypt(s.block, ext, encbuf)

				if ecc != nil {
					io.ReadFull(crand.Reader, ecc[:otpSize])
					checksum := crc32.ChecksumIEEE(ecc[cryptHeaderSize:])
					binary.LittleEndian.PutUint32(ecc[otpSize:], checksum)
					encrypt(s.block, ecc, encbuf)
				}
			}

			//if rand.Intn(100) < 80 {
			n, err := s.conn.WriteTo(ext, s.remote)
			if err != nil {
				log.Println(err, n)
			}
			atomic.AddUint64(&DefaultSnmp.OutSegs, 1)
			atomic.AddUint64(&DefaultSnmp.OutBytes, uint64(n))
			//}

			if ecc != nil {
				n, err := s.conn.WriteTo(ecc, s.remote)
				if err != nil {
					log.Println(err, n)
				}
				atomic.AddUint64(&DefaultSnmp.OutSegs, 1)
				atomic.AddUint64(&DefaultSnmp.OutBytes, uint64(n))
			}
		case <-ticker.C:
			ping := make([]byte, s.headerSize+IKCP_OVERHEAD)
			if s.block != nil {
				io.ReadFull(crand.Reader, ping[:otpSize]) // OTP
				checksum := crc32.ChecksumIEEE(ping[cryptHeaderSize:])
				binary.LittleEndian.PutUint32(ping[otpSize:], checksum)
				encrypt(s.block, ping, encbuf)
			}

			n, err := s.conn.WriteTo(ping, s.remote)
			if err != nil {
				log.Println(err, n)
			}
		case <-s.die:
			return
		}
	}
}

// kcp update, input loop
func (s *UDPSession) updateTask() {
	var tc <-chan time.Time
	if s.l == nil { // client
		ticker := time.NewTicker(10 * time.Millisecond)
		tc = ticker.C
		defer ticker.Stop()
	} else {
		tc = s.chTicker
	}

	var nextupdate uint32
	for {
		select {
		case <-tc:
			s.mu.Lock()
			current := currentMs()
			if current >= nextupdate || s.needUpdate {
				s.kcp.Update(current)
				nextupdate = s.kcp.Check(current)
			}
			s.needUpdate = false
			s.mu.Unlock()
			s.notifyWriteEvent()
		case <-s.die:
			if s.l != nil { // has listener
				s.l.chDeadlinks <- s.remote
			}
			return
		}
	}
}

// GetConv gets conversation id of a session
func (s *UDPSession) GetConv() uint32 {
	return s.kcp.conv
}

func (s *UDPSession) notifyReadEvent() {
	select {
	case s.chReadEvent <- struct{}{}:
	default:
	}
}

func (s *UDPSession) notifyWriteEvent() {
	select {
	case s.chWriteEvent <- struct{}{}:
	default:
	}
}

func (s *UDPSession) kcpInput(data []byte) {
	atomic.AddUint64(&DefaultSnmp.InSegs, 1)
	now := time.Now()
	if now.Sub(s.lastInputTs) > connTimeout {
		s.Close()
		return
	}
	s.lastInputTs = now

	s.mu.Lock()
	if s.fec != nil {
		f := fecDecode(data)
		if f.flag == typeData {
			s.kcp.Input(f.data[2:]) // skip 2B size
		}

		if f.flag == typeData || f.flag == typeFEC {
			if ecc := s.fec.input(f); ecc != nil {
				sz := binary.LittleEndian.Uint16(ecc)
				if int(sz) <= len(ecc) && sz >= 2 {
					s.kcp.Input(ecc[2:sz])
				}
			}
		}
	} else {
		s.kcp.Input(data)
	}

	if s.ackNoDelay {
		s.kcp.current = currentMs()
		s.kcp.flush()
	} else {
		s.needUpdate = true
	}
	s.mu.Unlock()
	s.notifyReadEvent()
}

// read loop for client session
func (s *UDPSession) readLoop() {
	conn := s.conn
	buffer := make([]byte, mtuLimit)
	decbuf := make([]byte, 2*aes.BlockSize)
	for {
		if n, err := conn.Read(buffer); err == nil && n >= s.headerSize+IKCP_OVERHEAD {
			dataValid := false
			data := buffer[:n]
			if s.block != nil {
				decrypt(s.block, data, decbuf)
				data = data[otpSize:]
				checksum := crc32.ChecksumIEEE(data[crcSize:])
				if checksum == binary.LittleEndian.Uint32(data) {
					data = data[crcSize:]
					dataValid = true
				} else {
					atomic.AddUint64(&DefaultSnmp.InCsumErrors, 1)
				}
			} else if s.block == nil {
				dataValid = true
			}

			if dataValid {
				s.kcpInput(data)
			}
		} else if err != nil {
			return
		} else {
			atomic.AddUint64(&DefaultSnmp.InErrs, 1)
		}
	}
}

type (
	// Listener defines a server listening for connections
	Listener struct {
		block       cipher.Block
		fec         int
		conn        *net.UDPConn
		sessions    map[string]*UDPSession
		chAccepts   chan *UDPSession
		chDeadlinks chan net.Addr
		headerSize  int
		die         chan struct{}
	}

	packet struct {
		from *net.UDPAddr
		data []byte
	}
)

// monitor incoming data for all connections of server
func (l *Listener) monitor() {
	chPacket := make(chan packet, 1024)
	decbuf := make([]byte, 2*aes.BlockSize)
	go l.receiver(chPacket)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case p := <-chPacket:
			data := p.data
			from := p.from
			dataValid := false
			if l.block != nil {
				decrypt(l.block, data, decbuf)
				data = data[otpSize:]
				checksum := crc32.ChecksumIEEE(data[crcSize:])
				if checksum == binary.LittleEndian.Uint32(data) {
					data = data[crcSize:]
					dataValid = true
				} else {
					atomic.AddUint64(&DefaultSnmp.InCsumErrors, 1)
				}
			} else if l.block == nil {
				dataValid = true
			}

			if dataValid {
				addr := from.String()
				s, ok := l.sessions[addr]
				if !ok { // new session
					var conv uint32
					convValid := false
					if l.fec > 0 { // has fec header
						isfec := binary.LittleEndian.Uint16(data[4:])
						if isfec == typeData {
							conv = binary.LittleEndian.Uint32(data[fecHeaderSizePlus2:])
							convValid = true
						}
					} else { // direct read
						conv = binary.LittleEndian.Uint32(data)
						convValid = true
					}

					if convValid {
						s := newUDPSession(conv, l.fec, l, l.conn, from, l.block)
						s.kcpInput(data)
						l.sessions[addr] = s
						l.chAccepts <- s
					}
				} else {
					s.kcpInput(data)
				}
			}
		case deadlink := <-l.chDeadlinks:
			delete(l.sessions, deadlink.String())
		case <-l.die:
			return
		case <-ticker.C:
			now := time.Now()
			for _, s := range l.sessions {
				select {
				case s.chTicker <- now:
				default:
				}
			}
		}
	}
}

func (l *Listener) receiver(ch chan packet) {
	for {
		data := make([]byte, mtuLimit)
		if n, from, err := l.conn.ReadFromUDP(data); err == nil && n >= l.headerSize+IKCP_OVERHEAD {
			ch <- packet{from, data[:n]}
		} else if err != nil {
			return
		} else {
			atomic.AddUint64(&DefaultSnmp.InErrs, 1)
		}
	}
}

// Accept implements the Accept method in the Listener interface; it waits for the next call and returns a generic Conn.
func (l *Listener) Accept() (*UDPSession, error) {
	select {
	case c := <-l.chAccepts:
		return c, nil
	case <-l.die:
		return nil, errors.New("listener stopped")
	}
}

// Close stops listening on the UDP address. Already Accepted connections are not closed.
func (l *Listener) Close() error {
	if err := l.conn.Close(); err == nil {
		close(l.die)
		return nil
	} else {
		return err
	}
}

// Addr returns the listener's network address, The Addr returned is shared by all invocations of Addr, so do not modify it.
func (l *Listener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// Listen listens for incoming KCP packets addressed to the local address laddr on the network "udp",
func Listen(laddr string) (*Listener, error) {
	return ListenWithOptions(0, laddr, nil)
}

// ListenWithOptions listens for incoming KCP packets addressed to the local address laddr on the network "udp" with packet encryption,
// FEC = 0 means no FEC, FEC > 0 means num(FEC) as a FEC cluster
func ListenWithOptions(fec int, laddr string, key []byte) (*Listener, error) {
	udpaddr, err := net.ResolveUDPAddr("udp", laddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpaddr)
	if err != nil {
		return nil, err
	}

	l := new(Listener)
	l.conn = conn
	l.sessions = make(map[string]*UDPSession)
	l.chAccepts = make(chan *UDPSession, 1024)
	l.chDeadlinks = make(chan net.Addr, 1024)
	l.die = make(chan struct{})
	l.fec = fec
	if key != nil && len(key) > 0 {
		pass := pbkdf2.Key(key, []byte(salt), 4096, 32, sha1.New)
		if block, err := aes.NewCipher(pass[:]); err == nil {
			l.block = block
		} else {
			log.Println(err)
		}
	}

	// caculate header size
	if l.block != nil {
		l.headerSize += cryptHeaderSize
	}
	if l.fec > 0 {
		l.headerSize += fecHeaderSizePlus2
	}

	go l.monitor()
	return l, nil
}

// Dial connects to the remote address raddr on the network "udp"
func Dial(raddr string) (*UDPSession, error) {
	return DialWithOptions(0, raddr, nil)
}

// DialWithOptions connects to the remote address raddr on the network "udp" with packet encryption
func DialWithOptions(fec int, raddr string, key []byte) (*UDPSession, error) {
	udpaddr, err := net.ResolveUDPAddr("udp", raddr)
	if err != nil {
		return nil, err
	}

	for {
		port := basePort + rand.Int()%(maxPort-basePort)
		if udpconn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port}); err == nil {
			if key != nil && len(key) > 0 {
				pass := pbkdf2.Key(key, []byte(salt), 4096, 32, sha1.New)
				if block, err := aes.NewCipher(pass[:]); err == nil {
					return newUDPSession(rand.Uint32(), fec, nil, udpconn, udpaddr, block), nil
				} else {
					log.Println(err)
				}
			}
			return newUDPSession(rand.Uint32(), fec, nil, udpconn, udpaddr, nil), nil
		}
	}
}

// packet encryption with local CFB mode
func encrypt(block cipher.Block, data []byte, buf []byte) {
	tbl := buf[:aes.BlockSize]
	block.Encrypt(tbl, initialVector)
	n := len(data) / aes.BlockSize
	base := 0
	for i := 0; i < n; i++ {
		xorWords(data[base:], data[base:], tbl)
		block.Encrypt(tbl, data[base:])
		base += aes.BlockSize
	}
	xorBytes(data[base:], data[base:], tbl)
}

func decrypt(block cipher.Block, data []byte, buf []byte) {
	tbl := buf[:aes.BlockSize]
	next := buf[aes.BlockSize:]
	block.Encrypt(tbl, initialVector)
	n := len(data) / aes.BlockSize
	base := 0
	for i := 0; i < n; i++ {
		block.Encrypt(next, data[base:])
		xorWords(data[base:], data[base:], tbl)
		tbl, next = next, tbl
		base += aes.BlockSize
	}
	xorBytes(data[base:], data[base:], tbl)
}

func currentMs() uint32 {
	return uint32(time.Now().UnixNano() / int64(time.Millisecond))
}
