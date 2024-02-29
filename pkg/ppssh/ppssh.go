package ppssh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/davidhadas/sec-peer-pods/pkg/sshproxy"
	"github.com/davidhadas/sec-peer-pods/pkg/sshutil"
	"golang.org/x/crypto/ssh"
)

const (
	PROVEN_PP_PRIVATRE_KEY_PATH = "/tmp/provenPpPrivateKey"
	PROVEN_TE_PUBLIC_KEY_PATH   = "/tmp/provenTePublicKey"
	UNPROVEN_TE_PUBLIC_KEY_PATH = "/tmp/unprovenTePublicKey"
	SIGNELTON_PATH              = "/tmp/sshSingleton"
)

func Singleton() {
	// Signleton- make sure we run the ssh service once per boot.
	if _, err := os.Stat(SIGNELTON_PATH); !errors.Is(err, os.ErrNotExist) {
		log.Fatal("SSH Service run in signleton mode - cant be executed twice")
	}
	singleton, err := os.Create(SIGNELTON_PATH)
	if err != nil {
		log.Fatal(err)
	}
	singleton.Close()
}

func getKeys() (attestationPhase bool, ppPrivateKeyBytes []byte, tePublicKeyBytes []byte) {
	var err error

	if ppPrivateKeyBytes, err = os.ReadFile(PROVEN_PP_PRIVATRE_KEY_PATH); err == nil {
		// Kubernetes Phase  - must have TE proven tePublicKeyBytes and ppPrivateKeyBytes
		tePublicKeyBytes, err = os.ReadFile(PROVEN_TE_PUBLIC_KEY_PATH)
		if err != nil {
			log.Fatalf("Missing a proven TE Public Key, err: %v", err)
		}
		log.Printf("SSH Server initialized in Kubernetes Phase")
		return
	}

	// Attestation Phase - may have unproven tePublicKeyBytes
	attestationPhase = true

	tePublicKeyBytes, err = os.ReadFile(UNPROVEN_TE_PUBLIC_KEY_PATH)
	if err != nil {
		tePublicKeyBytes = nil
	}

	// Private Key generation - unproven to the clinet, key is generated on the fly
	ppPrivateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		log.Fatalf("Failed to generate host key, err: %v", err)
	}

	// Validate Private Key
	err = ppPrivateKey.Validate()
	if err != nil {
		log.Fatalf("Failed to validate host key, err: %v", err)
	}

	ppPrivateKeyBytes = sshutil.RsaPrivateKeyPEM(ppPrivateKey)
	log.Printf("SSH Server initialized in Attastation Phase")
	return
}

func InitSshConfig(expectedAttestationPhase bool) *ssh.ServerConfig {
	config := &ssh.ServerConfig{}

	attestationPhase, ppPrivateKeyBytes, tePublicKeyBytes := getKeys()
	if expectedAttestationPhase != attestationPhase {
		log.Fatalf("Unexpected phase. Expected Attestation Phase %t, Actual Attetsation Phase %t ", expectedAttestationPhase, attestationPhase)
	}

	// Public key authentication is done by comparing
	// the public key of a received connection
	// with the entries in the authorized_keys file.

	if tePublicKeyBytes != nil { // connect with an client public key

		teSshPublicKey, _, _, _, err := ssh.ParseAuthorizedKey(tePublicKeyBytes)
		if err != nil {
			log.Fatal(err)
		}

		tePublicKey := string(teSshPublicKey.Marshal())

		// An SSH server is represented by a ServerConfig, which holds
		// certificate details and handles authentication of ServerConns.
		config.PublicKeyCallback = func(c ssh.ConnMetadata, clientPublicKey ssh.PublicKey) (*ssh.Permissions, error) {
			if tePublicKey == string(clientPublicKey.Marshal()) {
				return &ssh.Permissions{
					// Record the public key used for authentication.
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(clientPublicKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", c.User())
		}
	} else {
		// Given that tePublicKeyBytes is missing, asset that we are at attestationPhase
		if !attestationPhase {
			log.Fatalf("Missing SSH Server key") // should never happen
		}
		config.NoClientAuth = true
		log.Printf("SSH Server initialized without client public key")
	}

	serverSigner, err := ssh.ParsePrivateKey(ppPrivateKeyBytes)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}
	config.AddHostKey(serverSigner)
	return config
}

func KubernetesSShService(nConn net.Conn, config *ssh.ServerConfig) {
	log.Printf("Kubernetes Phase connected")

	// Handshake on the incoming net.Conn.
	conn, chans, sshReqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Printf("Failed to handshake: %s", err)
		return
	}

	if conn.Permissions != nil {
		log.Printf("Logged in with key %s", conn.Permissions.Extensions["pubkey-fp"])
	} else {
		log.Printf("Logged in without key")
	}

	// Starting ssh tunnel services for attestation phase
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	peer := sshproxy.NewSshPeer(ctx, cancel, conn, chans, sshReqs)
	err = peer.AddOutbound("7100", "127.0.0.1", "7100") // adaptor-forwarder
	if err != nil {
		log.Printf("Failed to initiate peer: %s", err)
		return
	}
	err = peer.AddInbound("6443") // Kubernetes API
	if err != nil {
		log.Printf("Failed to initiate peer: %s", err)
		return
	}
	err = peer.AddInbound("53") // DNS
	if err != nil {
		log.Printf("Failed to initiate peer: %s", err)
		return
	}
	<-ctx.Done()
}

func AttestationSShService(nConn net.Conn, config *ssh.ServerConfig) bool {
	log.Printf("Attestation Phase connected")

	// Handshake on the incoming net.Conn.
	conn, chans, sshReqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Printf("Failed to handshake: %s", err)
		return false
	}

	if conn.Permissions != nil {
		log.Printf("Logged in with key %s", conn.Permissions.Extensions["pubkey-fp"])
	} else {
		log.Printf("Logged in without key")
	}

	// Starting ssh tunnel services for attestation phase
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	peer := sshproxy.NewSshPeer(ctx, cancel, conn, chans, sshReqs)
	err = peer.AddInbound("7000")
	if err != nil {
		log.Printf("Failed to initiate peer: %s", err)
		return false
	}
	<-ctx.Done()
	log.Printf("AttestationSShService exiting")
	return true
}
