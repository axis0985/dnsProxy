package main
import (
	"fmt"
	"syscall"
)

func main() {
	fd, err:= syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(Htons(syscall.ETH_P_ALL)))
	if err != nil {
		fmt.Println("Error: " + err.Error())
		return;
	}
	defer syscall.Close(fd)

	// DNS sessions
	// map string(srcIP+transaction ID) to dstIP
	sessions := make(map[string][]byte, 512)

	for {
		buf := make([]byte, 1504)
		n, _ ,err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			fmt.Println(err)
		}
		if validate(buf, n) {
			push(fd, sessions, buf, n)
			pop(fd, sessions, buf, n)
		}
	}
}

