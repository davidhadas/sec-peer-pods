package main

import (
	"context"
	"log"
	"net"
	"os"

	"github.com/davidhadas/sec-peer-pods/pkg/kubemgr"
	"github.com/davidhadas/sec-peer-pods/pkg/ppssh"
	"github.com/davidhadas/sec-peer-pods/pkg/sshproxy"
	"github.com/davidhadas/sec-peer-pods/pkg/sshutil"
	"github.com/davidhadas/sec-peer-pods/pkg/wnssh"
)

func kubernetesPhase(nConn net.Conn, inbounds sshproxy.Inbounds, outbounds sshproxy.Outbounds) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Printf("Kubernetes client connected\n")
	peer, kubernetesDone, err := ppssh.KubernetesSShService(ctx, nConn)
	if err != nil {
		log.Printf("Failed to KubernetesSShService: %s", err)
		return
	}
	peer.AddOutbounds(outbounds)
	err = peer.AddInbounds(inbounds)
	if err != nil {
		log.Printf("Failed to KubernetesSShService: %s", err)
		return
	}
	<-kubernetesDone
	log.Printf("KubernetesSShService exiting")
}

func main() {
	ppId := "myppid"

	attestationPhaseInbounds := sshproxy.Inbounds{}
	attestationPhaseInbounds.Add("7000")

	kubernetesPhaseInbounds := sshproxy.Inbounds{}
	kubernetesPhaseInbounds.Add("6443")
	kubernetesPhaseInbounds.Add("9053")
	kubernetesPhaseOutbounds := sshproxy.Outbounds{}
	kubernetesPhaseOutbounds.Add("7100", "127.0.0.1", "7100")

	kubemgr.InitKubeMgr()
	os.Remove(ppssh.PROVEN_PP_PRIVATE_KEY_PATH)
	os.Remove(ppssh.PROVEN_TE_PUBLIC_KEY_PATH)
	os.Remove(ppssh.UNPROVEN_TE_PUBLIC_KEY_PATH)
	os.Remove(ppssh.SIGNELTON_PATH)

	ctx, cancel := context.WithCancel(context.Background())

	ppssh.Singleton()
	log.Printf("SSH Service starting\n")

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:"+sshutil.SSHPORT)
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}
	defer listener.Close()

	var attestationDone chan bool
	var peer *sshproxy.SshPeer
	for {

		// Singleton - accept an unproven connection for attestation
		log.Printf("waiting for Attestation client to connect\n")
		nConn, err := listener.Accept()
		if err != nil {
			log.Fatal("failed to accept incoming connection (Attestation Phase): ", err)
		}

		log.Printf("Attestation client connected\n")
		peer, attestationDone, err = ppssh.AttestationSShService(ctx, nConn)
		if err == nil {
			err = peer.AddInbounds(attestationPhaseInbounds)
			if err != nil {
				log.Printf("failed to initiate peer: %s", err)
				continue
			}
			// wait for a provenPpPrivateKey
			ppssh.WaitForProvenKeys(ctx, peer)

			break
		}
		log.Print(err.Error())
	}
	_, tePublicKey, _ := kubemgr.KubeMgr.ReadSecret(wnssh.CLIENT_SSH_SECRET)
	ppPrivateKey, _, _ := kubemgr.KubeMgr.ReadSecret(ppId)

	err = os.WriteFile(ppssh.PROVEN_TE_PUBLIC_KEY_PATH, tePublicKey, 0600)
	if err != nil {
		return
	}
	err = os.WriteFile(ppssh.PROVEN_PP_PRIVATE_KEY_PATH, ppPrivateKey, 0600)
	if err != nil {
		return
	}

	<-attestationDone
	cancel()

	log.Printf("AttestationSShService exiting")

	for {

		log.Printf("waiting for Kubernetes client to connect\n")
		nConn, err := listener.Accept()
		if err != nil {
			log.Fatal("failed to accept incoming connection (Kubernetes Phase): ", err)
		}

		kubernetesPhase(nConn, kubernetesPhaseInbounds, kubernetesPhaseOutbounds)
	}
}
