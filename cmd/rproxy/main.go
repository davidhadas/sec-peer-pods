package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/davidhadas/sec-peer-pods/pkg/ppssh"
	"github.com/davidhadas/sec-peer-pods/test"
)

type SID string

func (sid SID) urlModifier(path string) string {
	if strings.HasSuffix(path, ppssh.PP_PRIVATE_KEY) {
		return strings.Replace(path, ppssh.PP_SID, fmt.Sprintf("pp-%s/", sid), 1)
	}
	return path
}

func main() {
	go test.HttpServer("7777")
	go test.HttpClient("http://127.0.0.1:7070/")
	go test.HttpClient("http://127.0.0.1:7070/aaa/bbb/" + ppssh.PP_SID + "privateKey")
	time.Sleep(10 * time.Minute)
}
