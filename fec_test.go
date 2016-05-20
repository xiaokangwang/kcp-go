package kcp

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

func TestFECNoLost(t *testing.T) {
	fec := newFEC(3, 128)
	for i := 0; i < 100; i += 3 {
		data := makefecgroup(i, 3)
		for k := range data {
			fec.addheader(data[k])
			t.Log("input:", data[k])
		}
		ecc := fec.genfec(data)
		t.Log("  ecc:", ecc)
		data = append(data, ecc)
		for k := range data {
			if recovered := fec.input(data[k]); recovered != nil {
				t.Log("recovered:", binary.LittleEndian.Uint32(ecc))
			}
		}
	}
}

func TestFECLost1(t *testing.T) {
	fec := newFEC(4, 128)
	for i := 0; i < 100; i += 4 {
		data := makefecgroup(i, 4)
		for k := range data {
			fec.addheader(data[k])
			t.Log("input:", data[k])
		}
		ecc := fec.genfec(data)
		t.Log("  ecc:", ecc)
		data = append(data, ecc)
		lost := rand.Intn(5)
		t.Log(" lost:", data[lost])
		data = append(data[:lost], data[lost+1:]...)
		for k := range data {
			if recovered := fec.input(data[k]); recovered != nil {
				t.Log("recovered:", recovered)
			}
		}
	}
}

func TestFECLost2(t *testing.T) {
	fec := newFEC(5, 128)
	for i := 0; i < 100; i += 5 {
		data := makefecgroup(i, 5)
		for k := range data {
			fec.addheader(data[k])
			t.Log("input:", data[k])
		}
		ecc := fec.genfec(data)
		t.Log("  ecc:", ecc)
		data = append(data, ecc)
		lost := rand.Intn(6)
		t.Log(" lost:", data[lost])
		data = append(data[:lost], data[lost+1:]...)
		lost = rand.Intn(5)
		t.Log(" lost:", data[lost])
		data = append(data[:lost], data[lost+1:]...)

		for k := range data {
			if recovered := fec.input(data[k]); recovered != nil {
				t.Log("recovered:", recovered)
			}
		}
	}
}

func makefecgroup(start, size int) (group [][]byte) {
	for i := 0; i < size; i++ {
		data := make([]byte, fecHeaderSize+4)
		binary.LittleEndian.PutUint32(data[fecHeaderSize:], uint32(start+i))
		group = append(group, data)
	}
	return
}
