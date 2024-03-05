package ppssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/davidhadas/sec-peer-pods/pkg/sshproxy"
	"github.com/davidhadas/sec-peer-pods/pkg/sshutil"
	"golang.org/x/crypto/ssh"
)

const (
	PROVEN_PP_PRIVATE_KEY_PATH  = "/tmp/provenPpPrivateKey"
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

func WaitForProvenKeys(ctx context.Context, peer *sshproxy.SshPeer) {
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
	OUT:
		for {
			select {
			case <-ticker.C:
				if key, err := os.ReadFile(PROVEN_PP_PRIVATE_KEY_PATH); err != nil || len(key) == 0 {
					continue
				}
				if key, err := os.ReadFile(PROVEN_TE_PUBLIC_KEY_PATH); err != nil || len(key) == 0 {
					continue
				}

				log.Printf("Found files %s, %s", PROVEN_PP_PRIVATE_KEY_PATH, PROVEN_TE_PUBLIC_KEY_PATH)

				peer.Close("Found proven files")
				break OUT
			case <-ctx.Done():
				break OUT
			}
		}
		ticker.Stop()
	}()
}

func getKubernetesPhaseKeys() (ppPrivateKeyBytes []byte, tePublicKeyBytes []byte) {
	var err error

	ppPrivateKeyBytes, err = os.ReadFile(PROVEN_PP_PRIVATE_KEY_PATH)
	if err != nil {
		log.Fatalf("SSH Server failed to get PP Private Key from %s, err: %v", PROVEN_PP_PRIVATE_KEY_PATH, err)
	}

	// Kubernetes Phase  - must have TE proven tePublicKeyBytes and ppPrivateKeyBytes
	tePublicKeyBytes, err = os.ReadFile(PROVEN_TE_PUBLIC_KEY_PATH)
	if err != nil {
		log.Fatalf("SSH Server failed to get TE Public Key from %s, err: %v", PROVEN_TE_PUBLIC_KEY_PATH, err)
	}

	log.Printf("SSH Server initialized keys for Kubernetes Phase")
	return
}

func getAttestationPhaseKeys() (ppPrivateKeyBytes []byte, tePublicKeyBytes []byte) {
	var err error

	// Attestation Phase - may have unproven tePublicKeyBytes
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
	log.Printf("SSH Server initialized keys for Attastation Phase")
	return
}

func setConfigHostKey(config *ssh.ServerConfig, ppPrivateKeyBytes []byte) {
	serverSigner, err := ssh.ParsePrivateKey(ppPrivateKeyBytes)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}
	config.AddHostKey(serverSigner)
}

func setPublicKey(config *ssh.ServerConfig, tePublicKeyBytes []byte) {
	teSshPublicKey, _, _, _, err := ssh.ParseAuthorizedKey(tePublicKeyBytes)
	if err != nil {
		log.Fatal(fmt.Errorf("ssh.ParseAuthorizedKey of tePublicKeyBytes %w", err))
	}

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config.PublicKeyCallback = func(c ssh.ConnMetadata, clientPublicKey ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(teSshPublicKey.Marshal(), clientPublicKey.Marshal()) {
			return &ssh.Permissions{
				// Record the public key used for authentication.
				Extensions: map[string]string{
					"pubkey-fp": ssh.FingerprintSHA256(clientPublicKey),
				},
			}, nil
		}
		return nil, fmt.Errorf("unknown public key for %q", c.User())
	}
}

func InitAttestationPhaseSshConfig() *ssh.ServerConfig {
	config := &ssh.ServerConfig{}

	ppPrivateKeyBytes, tePublicKeyBytes := getAttestationPhaseKeys()

	if tePublicKeyBytes != nil { // connect with an client public key
		setPublicKey(config, tePublicKeyBytes)
	} else {
		config.NoClientAuth = true
		log.Printf("SSH Server Attestation Phase initialized with NoClientAuth")
	}
	setConfigHostKey(config, ppPrivateKeyBytes)
	return config
}

func InitKubernetesPhaseSshConfig() *ssh.ServerConfig {
	config := &ssh.ServerConfig{}

	ppPrivateKeyBytes, tePublicKeyBytes := getKubernetesPhaseKeys()

	if ppPrivateKeyBytes == nil || tePublicKeyBytes == nil || len(ppPrivateKeyBytes) == 0 || len(tePublicKeyBytes) == 0 { // connect with an client public key
		log.Fatalf("Kubernetes Phase missing SSH Server key") // should never happen
	}
	setPublicKey(config, tePublicKeyBytes)
	setConfigHostKey(config, ppPrivateKeyBytes)
	return config
}

func KubernetesSShService(ctx context.Context, nConn net.Conn) (done chan bool, err error) {
	done = make(chan bool, 1)

	log.Printf("Kubernetes Phase connected")
	kubernetesPhaseConfig := InitKubernetesPhaseSshConfig()
	// Handshake on the incoming net.Conn.
	conn, chans, sshReqs, err := ssh.NewServerConn(nConn, kubernetesPhaseConfig)
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
	peer := sshproxy.NewSshPeer(ctx, done, conn, chans, sshReqs)
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
	/*
		err = peer.AddInbound("53") // DNS
		if err != nil {
			log.Printf("Failed to initiate peer: %s", err)
			return
		}
	*/
	return
}

func AttestationSShService(ctx context.Context, nConn net.Conn) (done chan bool, err error) {
	done = make(chan bool, 1)
	log.Printf("Attestation Phase connected")
	attestationPhaseConfig := InitAttestationPhaseSshConfig()
	// Handshake on the incoming net.Conn.
	conn, chans, sshReqs, err := ssh.NewServerConn(nConn, attestationPhaseConfig)
	if err != nil {
		err = fmt.Errorf("failed to handshake: %s", err)
		return
	}

	if conn.Permissions != nil {
		log.Printf("Logged in with key %s", conn.Permissions.Extensions["pubkey-fp"])
	} else {
		log.Printf("Logged in without key")
	}

	// Starting ssh tunnel services for attestation phase

	peer := sshproxy.NewSshPeer(ctx, done, conn, chans, sshReqs)
	err = peer.AddInbound("7000")
	if err != nil {
		err = fmt.Errorf("failed to initiate peer: %s", err)
		return
	}
	// wait for a provenPpPrivateKey
	WaitForProvenKeys(ctx, peer)

	return
}
