package main

import (
	"log"

	"github.com/davidhadas/sec-peer-pods/pkg/tessh"
)

func main() {
	ppId = "myPp"
	tessh.CreateSecret(ppId)
	unprovenTePrivateKey := initClientKeys("unproven")
	provenTePrivateKey := initClientKeys("proven")

	peer, ctx := tessh.StartSshClient(unprovenTePrivateKey, nil)
	err := peer.AddOutbound("7000", "7777", "127.0.0.1")
	if err != nil {
		log.Printf("failed initiate peer: %s", err)
		return
	}
	<-ctx.Done()

	ppPublicKey := []byte{}
	peer, ctx = tessh.StartSshClient(provenTePrivateKey, ppPublicKey)
	err = peer.AddInbound("7100") // adaptor-forwarder
	if err != nil {
		log.Printf("failed initiate peer: %s", err)
		return
	}
	err = peer.AddOutbound("6443", "10.1.1.1", "6443") // Kubernetes API
	if err != nil {
		log.Printf("failed initiate peer: %s", err)
		return
	}
	err = peer.AddOutbound("53", "10.1.1.1", "53") // DNS
	if err != nil {
		log.Printf("failed initiate peer: %s", err)
		return
	}
	<-ctx.Done()
}
