package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"
)

func main() {
	err := rawTCP()
	if err != nil {
		log.Fatal(err)
	}
}

func rawTCP() error {
	if len(os.Args) < 4 {
		return errors.New("synack <src-ip> <dst-ip> <dst-port>")
	}
	src, err := net.ResolveIPAddr("ip4", os.Args[1])
	if err != nil {
		return err
	}
	dst, err := net.ResolveIPAddr("ip4", os.Args[2])
	if err != nil {
		return err
	}
	port, err := strconv.ParseUint(os.Args[3], 10, 16)
	if err != nil {
		return err
	}
	//start receiving ipv4, protocol:tcp
	recieved := make(chan time.Time)
	listening := make(chan bool)
	go func() {
		l, err := net.ListenIP("ip4:tcp", src)
		if err != nil {
			log.Printf("Listen %s", err)
			return
		}
		listening <- true
		b := make([]byte, 1024)
		n, addr, err := l.ReadFromIP(b)
		if err != nil {
			log.Printf("Read %s", err)
			return
		}
		t1 := time.Now()
		h := NewTCPHeader(b[:n])
		if h.Ctrl&ACK > 0 {
			log.Printf("ACK[NKOWLEDGED] %d bytes", n)
		} else {
			log.Printf("??? %d bytes", n)
		}
		log.Printf("%s: %#v", addr, h)
		recieved <- t1
	}()
	<-listening
	//prepare tcp SYN frame
	packet := TCPHeader{
		Source:      45222,
		Destination: uint16(port),
		SeqNum:      rand.Uint32(),
		AckNum:      0,
		DataOffset:  5,      // 4 bits (5*4=20)
		Reserved:    0,      // 3 bits
		ECN:         0,      // 3 bits
		Ctrl:        SYN,    // 6 bits (000010, SYN bit set)
		Window:      0xaaaa, // The amount of data that it is able to accept in bytes
		Checksum:    0,      // Kernel will set this if it's 0
		Urgent:      0,
		Options:     []TCPOption{},
	}
	data := packet.Marshal()
	packet.Checksum = Csum(data, to4byte(src), to4byte(dst))
	data = packet.Marshal()
	//send
	d, err := net.DialIP("ip4:tcp", src, dst)
	if err != nil {
		return err
	}
	t0 := time.Now()
	n, err := d.Write(data)
	if err != nil {
		return err
	}
	log.Printf("SYN[CHRONIZE] %d bytes", n)
	t1 := <-recieved
	log.Printf("rtt %s", t1.Sub(t0))
	return nil
}

/*
Borrowed from:
https://github.com/grahamking/latency/blob/master/tcp.go

Copyright 2013-2014 Graham King

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

For full license details see <http://www.gnu.org/licenses/>.
*/

const (
	FIN = 1  // 00 0001
	SYN = 2  // 00 0010
	RST = 4  // 00 0100
	PSH = 8  // 00 1000
	ACK = 16 // 01 0000
	URG = 32 // 10 0000
)

type TCPHeader struct {
	Source      uint16
	Destination uint16
	SeqNum      uint32
	AckNum      uint32
	DataOffset  uint8 // 4 bits
	Reserved    uint8 // 3 bits
	ECN         uint8 // 3 bits
	Ctrl        uint8 // 6 bits
	Window      uint16
	Checksum    uint16 // Kernel will set this if it's 0
	Urgent      uint16
	Options     []TCPOption
}

type TCPOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}

// Parse packet into TCPHeader structure
func NewTCPHeader(data []byte) *TCPHeader {
	var tcp TCPHeader
	r := bytes.NewReader(data)
	binary.Read(r, binary.BigEndian, &tcp.Source)
	binary.Read(r, binary.BigEndian, &tcp.Destination)
	binary.Read(r, binary.BigEndian, &tcp.SeqNum)
	binary.Read(r, binary.BigEndian, &tcp.AckNum)

	var mix uint16
	binary.Read(r, binary.BigEndian, &mix)
	tcp.DataOffset = byte(mix >> 12)  // top 4 bits
	tcp.Reserved = byte(mix >> 9 & 7) // 3 bits
	tcp.ECN = byte(mix >> 6 & 7)      // 3 bits
	tcp.Ctrl = byte(mix & 0x3f)       // bottom 6 bits

	binary.Read(r, binary.BigEndian, &tcp.Window)
	binary.Read(r, binary.BigEndian, &tcp.Checksum)
	binary.Read(r, binary.BigEndian, &tcp.Urgent)

	return &tcp
}

func (tcp *TCPHeader) HasFlag(flagBit byte) bool {
	return tcp.Ctrl&flagBit != 0
}

func (tcp *TCPHeader) Marshal() []byte {

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, tcp.Source)
	binary.Write(buf, binary.BigEndian, tcp.Destination)
	binary.Write(buf, binary.BigEndian, tcp.SeqNum)
	binary.Write(buf, binary.BigEndian, tcp.AckNum)

	var mix uint16
	mix = uint16(tcp.DataOffset)<<12 | // top 4 bits
		uint16(tcp.Reserved)<<9 | // 3 bits
		uint16(tcp.ECN)<<6 | // 3 bits
		uint16(tcp.Ctrl) // bottom 6 bits
	binary.Write(buf, binary.BigEndian, mix)

	binary.Write(buf, binary.BigEndian, tcp.Window)
	binary.Write(buf, binary.BigEndian, tcp.Checksum)
	binary.Write(buf, binary.BigEndian, tcp.Urgent)

	for _, option := range tcp.Options {
		binary.Write(buf, binary.BigEndian, option.Kind)
		if option.Length > 1 {
			binary.Write(buf, binary.BigEndian, option.Length)
			binary.Write(buf, binary.BigEndian, option.Data)
		}
	}

	out := buf.Bytes()

	// Pad to min tcp header size, which is 20 bytes (5 32-bit words)
	pad := 20 - len(out)
	for i := 0; i < pad; i++ {
		out = append(out, 0)
	}

	return out
}

// TCP Checksum
func Csum(data []byte, srcip, dstip [4]byte) uint16 {

	pseudoHeader := []byte{
		srcip[0], srcip[1], srcip[2], srcip[3],
		dstip[0], dstip[1], dstip[2], dstip[3],
		0,                  // zero
		6,                  // protocol number (6 == TCP)
		0, byte(len(data)), // TCP length (16 bits), not inc pseudo header
	}

	sumThis := make([]byte, 0, len(pseudoHeader)+len(data))
	sumThis = append(sumThis, pseudoHeader...)
	sumThis = append(sumThis, data...)
	//fmt.Printf("% x\n", sumThis)

	lenSumThis := len(sumThis)
	var nextWord uint16
	var sum uint32
	for i := 0; i+1 < lenSumThis; i += 2 {
		nextWord = uint16(sumThis[i])<<8 | uint16(sumThis[i+1])
		sum += uint32(nextWord)
	}
	if lenSumThis%2 != 0 {
		//fmt.Println("Odd byte")
		sum += uint32(sumThis[len(sumThis)-1])
	}

	// Add back any carry, and any carry from adding the carry
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)

	// Bitwise complement
	return uint16(^sum)
}

func to4byte(ip *net.IPAddr) [4]byte {
	b := [4]byte{}
	copy(b[:], ip.IP.To4())
	return b
}
