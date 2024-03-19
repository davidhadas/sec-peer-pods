package main

import (
	"context"
	"log"
	"net/netip"
	"time"

	"github.com/davidhadas/sec-peer-pods/pkg/wnssh"
	"github.com/davidhadas/sec-peer-pods/test"
)

func main() {
	sid := "myppid"                           // SID
	ipAddr, _ := netip.ParseAddr("127.0.0.1") // ipAddr of the VM
	ipAddrs := []netip.Addr{ipAddr}

	///////// Adaptor Initialization when SSH is enabled

	sshClient, err := wnssh.InitSshClient([]int{}, []int{7000}, []int{7100}, []int{6443, 9053})
	if err != nil {
		log.Printf("InitSshClient faield %v", err)
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

	inPort := ci.GetPort(7100)
	if inPort == 0 {
		log.Print("failed find port")
		// fail StartVM
		return
	}
	go test.Client(inPort)

	if err := ci.Start(); err != nil {
		log.Printf("failed InitiatePeerPodTunnel: %s", err)
		// fail StartVM
		return
	}

	// Set ci in sandbox
	time.Sleep(time.Minute * 10)

	////////// StopVM
	// get ci from sandbox based on sid
	ci.DisconnectPP(sid)
	time.Sleep(time.Minute * 10)
}
