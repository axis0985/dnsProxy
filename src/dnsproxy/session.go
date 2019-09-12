package main

import (
	"fmt"
	"net"
	"syscall"
)

// push the packet session and modify the packet
func push(fd int, sessions map[string][]byte, buf []byte, n int) {
	// only query should be pushed
	if buf[DNS_OFFSET+2]&0x80 != 0 {
		return
	}

	sessionKey := string(buf[IPV4_SRC_OFFSET:IPV4_DST_OFFSET]) + string(buf[DNS_OFFSET:DNS_OFFSET+2])
	sessionValue := make([]byte, 4)
	copy(sessionValue, buf[IPV4_DST_OFFSET:IPV4_DST_OFFSET+4])
	sessions[sessionKey] = sessionValue
	
	// Choose the interface to send packet
	ifi, _ := net.InterfaceByName("enp0s8")
	var addr syscall.SockaddrLinklayer
	addr.Ifindex = ifi.Index

	// mock IP
	copy(buf[IPV4_DST_OFFSET:IPV4_DST_OFFSET+4], []byte{192,168,56,103})
	// CheckSum
	check := ipCheckSum(buf[IPV4_OFFSET:IPV4_OFFSET+20])
	buf[IPV4_CHECKSUM_OFFSET], buf[IPV4_CHECKSUM_OFFSET+1] = byte(check>>8&255), byte(check&255)
	udpCheck := udpCheckSum(buf, n)
	buf[UDP_SRC_PORT+6], buf[UDP_SRC_PORT+7] = byte(udpCheck>>8&255), byte(udpCheck&255)


	err := syscall.Sendto(fd, buf[:n], 0, &addr)
	if err!=nil {
		fmt.Println(err)
	}
}

// pop the packet session and modify the packet session
func pop(fd int, sessions map[string][]byte, buf []byte, n int) {
	// only reponse should be pushed
	if buf[DNS_OFFSET+2]&0x80 == 0 {
		return
	}
	sessionKey := string(buf[IPV4_DST_OFFSET:IPV4_DST_OFFSET+4]) + string(buf[DNS_OFFSET:DNS_OFFSET+2])
	if sessionValue, ok := sessions[sessionKey]; ok {
		// Choose the interface to send packet
		ifi, _ := net.InterfaceByName("enp0s8")
		var addr syscall.SockaddrLinklayer
		addr.Ifindex = ifi.Index

		// mock ip
		copy(buf[IPV4_SRC_OFFSET:IPV4_SRC_OFFSET+4], sessionValue)
		// CheckSum
		check := ipCheckSum(buf[IPV4_OFFSET:IPV4_OFFSET+20])
		buf[IPV4_CHECKSUM_OFFSET], buf[IPV4_CHECKSUM_OFFSET+1] = byte(check>>8&255), byte(check&255)
		udpCheck := udpCheckSum(buf, n)
		buf[UDP_SRC_PORT+6], buf[UDP_SRC_PORT+7] = byte(udpCheck>>8&255), byte(udpCheck&255)

		err := syscall.Sendto(fd, buf[:n], 0, &addr)
		if err!=nil {
			fmt.Println(err)
		}
		delete(sessions, sessionKey)
	}
}
