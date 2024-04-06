package main

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"runtime"
	"time"

	"github.com/davidhadas/sec-peer-pods/pkg/kubemgr"
	"github.com/davidhadas/sec-peer-pods/pkg/wnssh"
	"github.com/davidhadas/sec-peer-pods/test"
)

func main() {
	kubemgr.SkipVerify = true

	// This sid should come from create container request
	sid := "fake"                             // SID
	ipAddr, _ := netip.ParseAddr("127.0.0.1") // ipAddr of the VM
	ipAddrs := []netip.Addr{ipAddr}

	go test.HttpServer("7777")
	//go test.HttpServer("7070")
	go test.HttpServer("8888")

	///////// Adaptor Initialization when SSH is enabled
	//kc := InitKbsClient("http://kbs-service.kbs-operator-system:8080/kbs/v0")
	//kc := InitKbsClient("http://192.168.122.43:30507/kbs/v0")
	//"http://127.0.0.1:8888/kbs/v0"

	go func() {
		for {
			fmt.Printf("Goroutines: %d\n", runtime.NumGoroutine())
			time.Sleep(time.Second)
		}
	}()

	sshClient, err := wnssh.InitSshClient([]string{"K:KATAAPI:0"}, []string{"B:KBS:9999", "K:KUBEAPI:16443", "K:DNS:9053"}, "http://127.0.0.1:9999/kbs/v0")
	if err != nil {
		log.Printf("InitSshClient %v", err)
		return
	}

	// Per peer pod (Resume):
	// 		Get sid, ipAddrs in peerpods crd
	//		ci := sshClient.InitPP(ctx, sid, ipAddrs)
	//		if ci == nil {
	//			log.Print("failed InitiatePeerPodTunnel")
	//			// How do we handle errors here?
	//			return
	//		}
	//		if err := ci.Start(); err != nil {
	//			log.Printf("failed InitiatePeerPodTunnel: %s", err)
	//			// How do we handle errors here?
	//			return
	//		}
	// 		Set ci in sandbox

	////////// CreateVM
	// add sandbox
	for {
		////////// StartVM
		ctx := context.Background()

		// Set sid, ipAddrs in peerpods crd
		// Then do:
		ci := sshClient.InitPP(ctx, sid, ipAddrs)
		if ci == nil {
			log.Print("failed InitiatePeerPodTunnel")
			// fail StartVM
			return
		}

		inPort := ci.GetPort("KATAAPI")
		if inPort == "" {
			log.Print("failed find port")
			// fail StartVM
			return
		}
		go test.HttpClient(fmt.Sprintf("http://127.0.0.1:%s", inPort))

		if err := ci.Start(); err != nil {
			log.Printf("failed ci.Start: %s", err)
			// fail StartVM
			return
		}
		// Set ci in sandbox
		time.Sleep(time.Second * 30)

		////////// StopVM
		// get ci from sandbox based on sid
		ci.DisconnectPP(sid)
		time.Sleep(time.Second * 30)

	}
}
