package main

import (
	"syscall"
)

type DnsSession struct {
	transID []byte
	srcIP []byte
	srcPort []byte
	dstIP []byte
}


// push the packet session and modify the packet
func push(fd int, sessions *[]DnsSession, buf []byte, n int) {
	session := &DnsSession{}
	session.transID = buf[DNS_OFFSET:DNS_OFFSET+2]
	session.srcIP = buf[IPV4_SRC_OFFSET:IPV4_DST_OFFSET]
	session.srcPort = buf[UDP_SRC_PORT:UDP_SRC_PORT+2]
	session.dstIP = buf[IPV4_DST_OFFSET:IPV4_DST_OFFSET+4]
	
	*sessions = append(*sessions, *session)
	// payload := buf[DNS_OFFSET:n]

	// mock headers
	var addr syscall.SockaddrInet4
	addr.Addr = [4]byte{192,168,56,103}// DEMO only
	addr.Port = 53
	syscall.Sendto(fd, buf[UDP_SRC_PORT:n], 0, &addr)
}

// // // pop the packet session and modify the packet session
// func pop(sessions []DnsSession, buf []byte, n int) {

// }
