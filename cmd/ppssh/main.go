package main

import (
	"log"
	"net"

	"github.com/davidhadas/sec-peer-pods/pkg/ppssh"
	"github.com/davidhadas/sec-peer-pods/pkg/sshutil"
)

func main() {
	ppssh.Singleton()
	log.Printf("SSH Service starting")

	unprovenConfig := ppssh.InitSshConfig(true)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:"+sshutil.SSHPORT)
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}
	// Singleton - accept an unproven connection for attestation
	nConn, err := listener.Accept()
	if err != nil {
		log.Fatal("failed to accept incoming connection (Attestation Phase): ", err)
	}

	if ppssh.AttestationSShService(nConn, unprovenConfig) {
		// Once attestation is succesful, allow proven connections forever
		provenConfig := ppssh.InitSshConfig(false)
		for {
			nConn, err := listener.Accept()
			if err != nil {
				log.Fatal("failed to accept incoming connection (Kubernetes Phase): ", err)
			}
			ppssh.KubernetesSShService(nConn, provenConfig)
		}
	}
	listener.Close()
}
