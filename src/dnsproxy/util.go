package main

const (
	// IPv4 Source IP Offset
	IPV4_SRC_OFFSET = 12
	// IPv4 Destination IP Offset
	IPV4_DST_OFFSET = 16
	// UDP Source Port Offset
	UDP_SRC_PORT = 20
	// UDP Destination Port Offset
	UDP_DST_PORT = 22
	// DNS Headers Offset
	DNS_OFFSET = 28
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
    for n := 1; n < len(msg)-1; n += 2 {
        sum += int(msg[n])*256 + int(msg[n+1])
    }
    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)
    var ans = uint16(^sum)
    return ans
}