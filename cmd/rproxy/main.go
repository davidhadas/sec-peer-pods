package main

import (
	"time"

	"github.com/davidhadas/sec-peer-pods/pkg/sshproxy"
	"github.com/davidhadas/sec-peer-pods/test"
)

func main() {
	go test.HttpServer("7777")
	go test.HttpClient("http://127.0.0.1:7070/")
	sshproxy.StartProxy("http://127.0.0.1:7777/", "7070")
	time.Sleep(10 * time.Minute)
}
