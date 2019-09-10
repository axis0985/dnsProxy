package main
import (
	"fmt"
	"syscall"
	"os"
)

func main() {
	fd, err:= syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil {
		fmt.Println("Error: " + err.Error())
		return;
	}
	f := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))

	sessions := make([]DnsSession, 128)

	for {
		buf := make([]byte, 1024)
		n, err := f.Read(buf)
		if err != nil {
			fmt.Println(err)
		}
		if validate(buf, n) {
			push(fd, &sessions,buf,n)
			fmt.Println(buf[IPV4_SRC_OFFSET:IPV4_DST_OFFSET])
			fmt.Println(buf[IPV4_DST_OFFSET:IPV4_DST_OFFSET+4])
			fmt.Printf("%s\n",buf[DNS_OFFSET:n])
			fmt.Println("------")
		}
		//copy(buf[IPV4_DST_OFFSET:IPV4_DST_OFFSET+4], []byte{127,5,5,1})
		
	}
	defer syscall.Close(fd)
}

