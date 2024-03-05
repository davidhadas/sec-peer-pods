package main

import (
	"context"
	"log"
	"net"
	"os"

	"github.com/davidhadas/sec-peer-pods/pkg/kubemgr"
	"github.com/davidhadas/sec-peer-pods/pkg/ppssh"
	"github.com/davidhadas/sec-peer-pods/pkg/sshutil"
	"github.com/davidhadas/sec-peer-pods/pkg/tessh"
)

func main() {
	ppId := "myppid"

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
	for {
		// Singleton - accept an unproven connection for attestation
		log.Printf("waiting for Attestation client to connect\n")
		nConn, err := listener.Accept()
		if err != nil {
			log.Fatal("failed to accept incoming connection (Attestation Phase): ", err)
		}

		log.Printf("Attestation client connected\n")
		attestationDone, err = ppssh.AttestationSShService(ctx, nConn)
		if err == nil {
			break
		}
		log.Print(err.Error())
	}
	_, tePublicKey, _ := kubemgr.KubeMgr.ReadSecret(tessh.TE_SECRET)
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
		var kubernetesDone chan bool
		ctx, cancel = context.WithCancel(context.Background())

		log.Printf("waiting for Kubernetes client to connect\n")
		nConn, err := listener.Accept()
		if err != nil {
			log.Fatal("failed to accept incoming connection (Kubernetes Phase): ", err)
		}
		log.Printf("Kubernetes client connected\n")
		kubernetesDone, err = ppssh.KubernetesSShService(ctx, nConn)
		if err != nil {
			cancel()
			continue
		}
		<-kubernetesDone
		cancel()
		log.Printf("KubernetesSShService exiting")
	}
}
