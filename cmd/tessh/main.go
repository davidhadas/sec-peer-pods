package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/davidhadas/sec-peer-pods/pkg/kubemgr"
	"github.com/davidhadas/sec-peer-pods/pkg/sshproxy"
	"github.com/davidhadas/sec-peer-pods/pkg/tessh"
)

func main() {
	ppId := "myppid"
	ppAddr := "localhost:2022"
	attestationPhaseOutbounds := sshproxy.Outbounds{}
	attestationPhaseOutbounds.Add("7000", "127.0.0.1", "7777")

	kubernetesPhaseInbounds := sshproxy.Inbounds{}
	kubernetesPhaseInbounds.Add("7100")
	kubernetesPhaseOutbounds := sshproxy.Outbounds{}
	kubernetesPhaseOutbounds.Add("6443", "127.0.0.1", "6443")
	kubernetesPhaseOutbounds.Add("9053", "127.0.0.1", "9053")

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
	peer.AddOutbounds(attestationPhaseOutbounds)
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
			peer.AddOutbounds(kubernetesPhaseOutbounds)      // Kubernetes API
			err := peer.AddInbounds(kubernetesPhaseInbounds) // adaptor-forwarder
			if err != nil {
				log.Printf("failed initiate peer: %s", err)
				peer.Close(fmt.Sprintf("AddOutbound %v", err))
				cancel()
			}

			<-kubernetesDone
			cancel()
		}
	}()
	time.Sleep(time.Minute)
	tessh.TerminatePeerPodTunnel(ppId)
}
