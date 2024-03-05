package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/davidhadas/sec-peer-pods/pkg/kubemgr"
	"github.com/davidhadas/sec-peer-pods/pkg/tessh"
)

func main() {
	ppId := "myppid"
	ppAddr := "localhost:2022"

	kubemgr.InitKubeMgr()
	ppPublicKey, tePrivateKey := tessh.GetPeerPodKeys(ppId)
	if len(ppPublicKey) == 0 || len(tePrivateKey) == 0 {
		log.Print("Missing keys for PeerPod")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Attestation Phase
	log.Println("Starting Attstation Phase")
	peer, attestationDone := tessh.StartSshClient(ctx, ppAddr, tePrivateKey, nil)
	if peer == nil {
		log.Print("failed StartSshClient during attestation phase")
		return
	}
	err := peer.AddOutbound("7000", "7777", "127.0.0.1")
	if err != nil {
		log.Printf("failed initiate peer: %s", err)
		peer.Close(fmt.Sprintf("AddOutbound %v", err))
		cancel()
		return
	}

	<-attestationDone
	cancel()
	log.Println("Attstation Phase Done")

	// Kubernetes Phase

	go func() {
		for {
			ctx, cancel := context.WithCancel(context.Background())
			log.Println("Starting Kubernetes Phase")
			peer, kubernetesDone := tessh.StartSshClient(ctx, ppAddr, tePrivateKey, ppPublicKey)
			if peer == nil {
				log.Print("failed StartSshClient")
				time.Sleep(time.Second)
				continue
			}
			err = peer.AddInbound("7100") // adaptor-forwarder
			if err != nil {
				log.Printf("failed initiate peer: %s", err)
				peer.Close(fmt.Sprintf("AddOutbound %v", err))
				cancel()
			}
			err = peer.AddOutbound("6443", "10.1.1.1", "6443") // Kubernetes API
			if err != nil {
				log.Printf("failed initiate peer: %s", err)
				peer.Close(fmt.Sprintf("AddOutbound %v", err))
				cancel()
			}
			/*
				err = peer.AddOutbound("53", "10.1.1.1", "53") // DNS
				if err != nil {
					log.Printf("failed initiate peer: %s", err)
					peer.Close()
					cancel()
				}
			*/

			<-kubernetesDone
			cancel()
		}
	}()
	time.Sleep(time.Minute)
	tessh.TerminatePeerPodTunnel(ppId)
}
