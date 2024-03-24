package test

import (
	"fmt"
	"net"
	"time"
)

func Client(port string) {
	// Connect to the server
	conn, err := net.Dial("tcp", "localhost:"+port)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Send some data to the server
	_, err = conn.Write([]byte("Hello, server!"))
	if err != nil {
		fmt.Println(err)
		return
	}
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Client %s success\n", port)
	time.Sleep(time.Minute)
	// Close the connection
	conn.Close()
}
