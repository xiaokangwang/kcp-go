package kcp

import "sync/atomic"

// Snmp defines network statistics indicator
type Snmp struct {
	BytesSent     uint64
	BytesReceived uint64
	MaxConn       uint64
	ActiveOpens   uint64
	PassiveOpens  uint64
	CurrEstab     uint64
	InErrs        uint64
	InCsumErrors  uint64
	InSegs        uint64
	OutSegs       uint64
	OutBytes      uint64
	RetransSegs   uint64
	LostSegs      uint64
	RepeatSegs    uint64
}

func newSnmp() *Snmp {
	return new(Snmp)
}

func (s *Snmp) Copy() *Snmp {
	d := newSnmp()
	d.BytesSent = atomic.LoadUint64(&s.BytesSent)
	d.BytesReceived = atomic.LoadUint64(&s.BytesReceived)
	d.MaxConn = atomic.LoadUint64(&s.MaxConn)
	d.ActiveOpens = atomic.LoadUint64(&s.ActiveOpens)
	d.PassiveOpens = atomic.LoadUint64(&s.PassiveOpens)
	d.CurrEstab = atomic.LoadUint64(&s.CurrEstab)
	d.InErrs = atomic.LoadUint64(&s.InErrs)
	d.InCsumErrors = atomic.LoadUint64(&s.InCsumErrors)
	d.InSegs = atomic.LoadUint64(&s.InSegs)
	d.OutSegs = atomic.LoadUint64(&s.OutSegs)
	d.OutBytes = atomic.LoadUint64(&s.OutBytes)
	d.RetransSegs = atomic.LoadUint64(&s.RetransSegs)
	d.LostSegs = atomic.LoadUint64(&s.LostSegs)
	d.RepeatSegs = atomic.LoadUint64(&s.RepeatSegs)
	return d
}

var DefaultSnmp *Snmp

func init() {
	DefaultSnmp = newSnmp()
}
