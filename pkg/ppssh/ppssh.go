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

	"github.com/davidhadas/sec-peer-pods/pkg/sshproxy"
	"github.com/davidhadas/sec-peer-pods/pkg/sshutil"
	"golang.org/x/crypto/ssh"
)

const (
	PROVEN_PP_PRIVATE_KEY_PATH  = "/tmp/provenPpPrivateKey"
	PROVEN_WN_PUBLIC_KEY_PATH   = "/tmp/provenTePublicKey"
	UNPROVEN_WN_PUBLIC_KEY_PATH = "/tmp/unprovenTePublicKey"
	SIGNELTON_PATH              = "/tmp/sshSingleton"
	PP_SID                      = "pp-sid/"
	PP_PRIVATE_KEY              = PP_SID + "privateKey"
	WN_PUBLIC_KEY               = "sshclient/publicKey"
)

func k8sPhase(listener net.Listener, inbounds sshproxy.Inbounds, outbounds sshproxy.Outbounds, ppSecrets *PpSecrets) {
	log.Printf("waiting for Kubernetes client to connect\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var peer *sshproxy.SshPeer
	for peer == nil {
		nConn, err := listener.Accept()
		if err != nil {
			log.Fatal("failed to accept incoming connection (Kubernetes Phase): ", err)
		}
		//ctx, cancel := context.WithCancel(context.Background())
		//defer cancel()

		log.Printf("Kubernetes client connected\n")
		peer, err = KubernetesSShService(ctx, nConn, ppSecrets)
		if err != nil {
			log.Printf("Failed k8sPhase: %s", err)
			peer = nil
			continue
		}
		peer.AddOutbounds(outbounds)
		err = peer.AddInbounds(inbounds)
		if err != nil {
			log.Printf("Failed addInbounds during k8sPhase: %s", err)
			return
		}
		peer.Wait()
		log.Printf("KubernetesSShService exiting")
	}
}

func attestationPhase(listener net.Listener, inbounds sshproxy.Inbounds, outbounds sshproxy.Outbounds, ppSecrets *PpSecrets) {
	// Singleton - accept an unproven connection for attestation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var peer *sshproxy.SshPeer
	for peer == nil {
		log.Printf("Attastation Phase: waiting for client to connect\n")
		nConn, err := listener.Accept()
		if err != nil {
			log.Fatal("Attastation Phase: failed to accept incoming connection: ", err)
		}

		log.Printf("Attastation Phase: client connected\n")

		peer, err = AttestationSShService(ctx, nConn)
		if err != nil {
			log.Print(err.Error())
			peer = nil
		}
	}

	peer.AddOutbounds(outbounds)
	if err := peer.AddInbounds(inbounds); err != nil {
		log.Fatal("Attastation Phase: failed to add Inbounds: ", err)
	}
	ppSecrets.AddKey(WN_PUBLIC_KEY)
	ppSecrets.AddKey(PP_PRIVATE_KEY)
	ppSecrets.Go() // wait for the keys

	// wait for a provenPpPrivateKey
	//WaitForProvenKeys(ctx, peer)
	//peer.Wait()
}

func InitSshServer(attestationInbounds, attestationOutbounds, kubernetesInbounds, kubernetesOutbounds []string, getSecret GetSecret) {
	Singleton()
	var attestation_inbounds, k8s_inbounds sshproxy.Inbounds
	var attestation_outbounds, k8s_outbounds sshproxy.Outbounds
	for _, tag := range attestationInbounds {
		if err := attestation_inbounds.Add(tag, ""); err != nil {
			log.Fatalf("Attastation Phase: Failed to open port %s:  %v", tag, err)
		}
	}
	for _, tag := range attestationOutbounds {
		attestation_outbounds.Add(tag)
	}
	for _, tag := range kubernetesInbounds {
		if err := k8s_inbounds.Add(tag, ""); err != nil {
			log.Fatalf("Kubernetes Phase: Failed to open port %s:  %v", tag, err)
		}
	}
	for _, tag := range kubernetesOutbounds {
		k8s_outbounds.Add(tag)
	}

	log.Printf("SSH Service starting 0.0.0.0:%s\n", sshutil.SSHPORT)
	listener, err := net.Listen("tcp", "0.0.0.0:"+sshutil.SSHPORT)
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}
	ppSecrets := NewPpSecrets(getSecret)

	go func() {
		attestationPhase(listener, attestation_inbounds, attestation_outbounds, ppSecrets)
		for {
			k8sPhase(listener, k8s_inbounds, k8s_outbounds, ppSecrets)
		}
	}()
}

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

func getAttestationPhaseKeys() (ppPrivateKeyBytes []byte, tePublicKeyBytes []byte) {
	var err error

	// Attestation Phase - may have unproven tePublicKeyBytes
	tePublicKeyBytes, err = os.ReadFile(UNPROVEN_WN_PUBLIC_KEY_PATH)
	if err != nil {
		tePublicKeyBytes = nil
	}

	// Private Key generation - unproven to the clinet, key is generated on the fly
	ppPrivateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		log.Fatalf("Attastation Phase: Failed to generate host key, err: %v", err)
	}

	// Validate Private Key
	err = ppPrivateKey.Validate()
	if err != nil {
		log.Fatalf("Attastation Phase: Failed to validate host key, err: %v", err)
	}

	ppPrivateKeyBytes = sshutil.RsaPrivateKeyPEM(ppPrivateKey)
	log.Printf("Attastation Phase: SSH Server initialized keys")
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
		log.Printf("Attastation Phase: SSH Server initialized with NoClientAuth")
	}
	setConfigHostKey(config, ppPrivateKeyBytes)
	return config
}

func InitKubernetesPhaseSshConfig(ppSecrets *PpSecrets) *ssh.ServerConfig {
	config := &ssh.ServerConfig{}

	ppPrivateKeyBytes := ppSecrets.GetKey(PP_PRIVATE_KEY)
	wnPublicKeyBytes := ppSecrets.GetKey(WN_PUBLIC_KEY)
	//ppPrivateKeyBytes, wnPublicKeyBytes := getKubernetesPhaseKeys()

	if ppPrivateKeyBytes == nil || wnPublicKeyBytes == nil || len(ppPrivateKeyBytes) == 0 || len(wnPublicKeyBytes) == 0 { // connect with an client public key
		log.Fatalf("Kubernetes Phase: missing SSH Server key") // should never happen
	}
	setPublicKey(config, wnPublicKeyBytes)
	setConfigHostKey(config, ppPrivateKeyBytes)
	return config
}

func KubernetesSShService(ctx context.Context, nConn net.Conn, ppSecrets *PpSecrets) (*sshproxy.SshPeer, error) {
	log.Printf("Kubernetes Phase: connected")

	kubernetesPhaseConfig := InitKubernetesPhaseSshConfig(ppSecrets)
	// Handshake on the incoming net.Conn.
	conn, chans, sshReqs, err := ssh.NewServerConn(nConn, kubernetesPhaseConfig)
	if err != nil {
		log.Printf("Kubernetes Phase: Failed to handshake: %s", err)
		return nil, err
	}

	if conn.Permissions != nil {
		log.Printf("Kubernetes Phase: Logged in with key %s", conn.Permissions.Extensions["pubkey-fp"])
	} else {
		log.Printf("Kubernetes Phase: Logged in without key")
	}

	// Starting ssh tunnel services for attestation phase
	peer := sshproxy.NewSshPeer(ctx, "Kubernetes", conn, chans, sshReqs, "")
	return peer, nil
}

func AttestationSShService(ctx context.Context, nConn net.Conn) (*sshproxy.SshPeer, error) {
	log.Printf("Attestation Phase: connected")
	attestationPhaseConfig := InitAttestationPhaseSshConfig()
	// Handshake on the incoming net.Conn.
	conn, chans, sshReqs, err := ssh.NewServerConn(nConn, attestationPhaseConfig)
	if err != nil {
		err = fmt.Errorf("failed to handshake: %v", err)
		return nil, err
	}

	if conn.Permissions != nil {
		log.Printf("Attestation Phase: Logged in with key %s", conn.Permissions.Extensions["pubkey-fp"])
	} else {
		log.Printf("Attestation Phase: Logged in without key")
	}

	// Starting ssh tunnel services for attestation phase
	peer := sshproxy.NewSshPeer(ctx, "Attestation", conn, chans, sshReqs, "")
	return peer, nil
}

func CopyFile(source, dest string) {
	input, err := os.ReadFile(source)
	if err != nil {
		log.Printf("Error reading %s: %s", source, err.Error())
		return
	}

	err = os.WriteFile(dest, input, 0644)
	if err != nil {
		log.Printf("Error creating %s: %s", dest, err.Error())
		return
	}
}
