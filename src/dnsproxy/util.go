package main
import (
	"fmt"
)
const (
	// IPV4 OFFSET
	IPV4_OFFSET = 14
	// IPv4 Source IP Offset
	IPV4_SRC_OFFSET = 26
	// IPv4 Destination IP Offset
	IPV4_DST_OFFSET = 30
	// IPv4 Checksum offset
	IPV4_CHECKSUM_OFFSET = 24
	// UDP Source Port Offset
	UDP_SRC_PORT = 34
	// UDP Destination Port Offset
	UDP_DST_PORT = 36
	// DNS Headers Offset, also UDP Payload offset
	DNS_OFFSET = 42
)

// from https://stackoverflow.com/questions/7565300/identifying-dns-packets
// 								   1  1  1  1  1  1
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      ID                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QDCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ANCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    NSCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ARCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// simply validate if the packet is DNS packet
func validate(buf []byte, n int) bool {
	// Technically, QDCOUNT can be other number
	// In practice, QDCOUNT is always 0x0001
	if buf[DNS_OFFSET+4] != 0x00 || buf[DNS_OFFSET+5] != 0x01 {
		return false
	}
	// Roughly check the port is 53
	if byteToNum(buf[UDP_SRC_PORT:UDP_DST_PORT]) != 53 && byteToNum(buf[UDP_DST_PORT:UDP_DST_PORT+2]) != 53 {
		return false
	}
	return true
}

func byteToNum(data []byte) int {
	var ret int
	for _, b := range data {
		ret <<= 8
		ret |= int(b)
	}
	return ret
}

// for ip checksum
func checkSum(msg []byte) uint16 {
    sum := 0
    for n := 0; n < len(msg)-1; n += 2 {
        sum += int(msg[n])*256 + int(msg[n+1])
    }
    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)
    var ans = uint16(^sum)
    return ans
}

func ipCheckSum(msg []byte) uint16 {
	iph := make([]byte,20)
	copy(iph, msg)
	iph[10], iph[11] = 0,0
	return checkSum(iph)
}

func udpCheckSum (msg []byte, n int) uint16 {
	payloadLen := n-DNS_OFFSET
	bufSize := 20 + payloadLen
	if payloadLen%2 == 1{
		bufSize = 20 + payloadLen + 1
	}
	buf := make([]byte, bufSize)
	copy(buf[0:4], msg[IPV4_SRC_OFFSET:IPV4_DST_OFFSET])
	copy(buf[4:8], msg[IPV4_DST_OFFSET:IPV4_DST_OFFSET+4])
	buf[9] = msg[IPV4_OFFSET+9]
	copy(buf[10:12], msg[UDP_SRC_PORT+4:UDP_SRC_PORT+6])
	copy(buf[12:18], msg[UDP_SRC_PORT:UDP_SRC_PORT+6])
	copy(buf[20:], msg[DNS_OFFSET:n])
	return checkSum(buf)
}

func Htons (i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}
