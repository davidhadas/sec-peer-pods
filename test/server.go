package test

import (
	"fmt"
	"net"
	"strconv"
)

func Server(port int) {
	// Listen for incoming connections on port 8080
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		fmt.Println(err)
		return
	}

	// Accept incoming connections and handle them
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}

		// Handle the connection in a new goroutine
		go handleConnection(conn, port)
	}
}

func handleConnection(conn net.Conn, port int) {
	// Close the connection when we're done
	defer conn.Close()

	// Read incoming data
	buf := make([]byte, 1024)
	_, err := conn.Read(buf)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Print the incoming data
	fmt.Printf("Received: %s port %d\n", buf, port)
	_, err = conn.Write(buf)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Written: %s port %d\n", buf, port)
}
