package wnssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/davidhadas/sec-peer-pods/pkg/kubemgr"
	"github.com/davidhadas/sec-peer-pods/pkg/sshproxy"
	"github.com/davidhadas/sec-peer-pods/pkg/sshutil"
	"golang.org/x/crypto/ssh"
)

const ADAPTOR_SSH_SECRET = "sshclient"
const SSH_PORT = ":2022"

type SshClient struct {
	wnSigner                  *ssh.Signer
	kubernetesPhaseInbounds   []int
	kubernetesPhaseOutbounds  []int
	attestationPhaseInbounds  []int
	attestationPhaseOutbounds []int
}

type SshClientInstance struct {
	publicKey               []byte
	ppAddr                  []string
	sshClient               *SshClient
	ctx                     context.Context
	cancel                  context.CancelFunc
	k8sPhase                bool
	attestationInbounds     sshproxy.Inbounds
	attestationOutbounds    sshproxy.Outbounds
	kubernetesInbounds      sshproxy.Inbounds
	kubernetesOutbounds     sshproxy.Outbounds
	attestationInboundPorts map[int]int
	kubernetesInboundPorts  map[int]int
}

func PpSecretName(sid string) string {
	//return "pp-" + sid
	log.Printf("Using fake secrets << DEVELOPMENT ONLY! >>")
	return "pp-fake"
}

func InitSshClient(attestationInbounds, attestationOutbounds, kubernetesInbounds, kubernetesOutbounds []int) (*SshClient, error) {
	kubemgr.InitKubeMgr()

	// Read WN Secret
	wnPrivateKey, _, err := kubemgr.KubeMgr.ReadSecret(ADAPTOR_SSH_SECRET)
	if err != nil {
		// auto-create a secret
		wnPrivateKey, _, err = kubemgr.KubeMgr.CreateSecret(ADAPTOR_SSH_SECRET)
		if err != nil {
			return nil, fmt.Errorf("failed to auto create WN Secret: %w", err)
		}
	}
	if len(wnPrivateKey) == 0 {
		return nil, fmt.Errorf("missing keys for PeerPod")
	}
	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(wnPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %v", err)
	}

	sshClient := &SshClient{
		wnSigner:                  &signer,
		attestationPhaseInbounds:  attestationInbounds,
		attestationPhaseOutbounds: attestationOutbounds,
		kubernetesPhaseInbounds:   kubernetesInbounds,
		kubernetesPhaseOutbounds:  kubernetesOutbounds,
	}

	return sshClient, nil
}

func (ci *SshClientInstance) GetInPorts() []int {
	ports := []int{}
	for _, inPort := range ci.attestationInboundPorts {
		ports = append(ports, inPort)
	}
	for _, inPort := range ci.kubernetesInboundPorts {
		ports = append(ports, inPort)
	}
	return ports
}

func (ci *SshClientInstance) GetPort(outPort int) int {
	var ok bool
	var inPort int
	inPort, ok = ci.kubernetesInboundPorts[outPort]
	if !ok {
		inPort, ok = ci.attestationInboundPorts[outPort]
		if !ok {
			return 0
		}
	}
	return inPort
}
func (ci *SshClientInstance) DisconnectPP(sid string) {
	log.Print("SshClientInstance DisconnectPP")
	// Cancel the VM connction
	ci.cancel()

	// Remove peerPod Secret named peerPodId
	// TBD: Add this code once KBS integration is complete
	// kubemgr.KubeMgr.DeleteSecret(PpSecretName(sid))
}

func (c *SshClient) InitPP(ctx context.Context, sid string, ipAddr []netip.Addr) *SshClientInstance {
	// Create peerPod Secret named peerPodId
	var publicKey []byte
	var err error

	// Try reading first in case we resume an existing PP
	_, publicKey, err = kubemgr.KubeMgr.ReadSecret(PpSecretName(sid))
	if err != nil {
		_, publicKey, err = kubemgr.KubeMgr.CreateSecret(PpSecretName(sid))
		if err != nil {
			log.Printf("failed to create PP Secret: %v", err)
			return nil
		}
	}

	var serverSshPublicKeyBytes []byte

	if len(publicKey) > 0 {
		serverSshPublicKey, _, _, _, err := ssh.ParseAuthorizedKey(publicKey)
		if err != nil {
			log.Printf("unable to ParseAuthorizedKey serverPublicKey: %v", err)
			return nil
		}
		serverSshPublicKeyBytes = serverSshPublicKey.Marshal()
	}

	ppAddr := make([]string, len(ipAddr))
	for i, ip := range ipAddr {
		ppAddr[i] = ip.String() + ":" + sshutil.SSHPORT
	}

	ctx, cancel := context.WithCancel(ctx)
	ci := &SshClientInstance{
		publicKey:               serverSshPublicKeyBytes,
		ppAddr:                  ppAddr,
		sshClient:               c,
		ctx:                     ctx,
		cancel:                  cancel,
		attestationInboundPorts: make(map[int]int),
		kubernetesInboundPorts:  make(map[int]int),
	}

	for _, outPort := range c.attestationPhaseInbounds {
		inPort := sshutil.GetRandomPort()
		for ci.attestationInbounds.Add(outPort, inPort) != nil {
			inPort = sshutil.GetRandomPort()
		}
		ci.kubernetesInboundPorts[outPort] = inPort
	}
	for _, outPort := range c.attestationPhaseOutbounds {
		ci.attestationOutbounds.Add(outPort)
	}
	for _, outPort := range c.kubernetesPhaseInbounds {
		inPort := sshutil.GetRandomPort()
		for ci.kubernetesInbounds.Add(outPort, inPort) != nil {
			inPort = sshutil.GetRandomPort()
		}
		ci.kubernetesInboundPorts[outPort] = inPort
	}
	for _, outPort := range c.kubernetesPhaseOutbounds {
		ci.kubernetesOutbounds.Add(outPort)
	}

	return ci
}

func (ci *SshClientInstance) Start() error {
	if !ci.k8sPhase {
		// Attestation Phase
		log.Println("Starting Attstation Phase")
		if err := ci.StartAttestation(); err != nil {
			return fmt.Errorf("failed StartAttestation: %v", err)
		}
		log.Println("Attstation Phase Done")
		ci.k8sPhase = true
	}

	// Kubernetes Phase
	go func() {
		restarts := 0
		for {
			select {
			case <-ci.ctx.Done():
				log.Printf("Connect VM Done")
				return
			default:
				log.Printf("Starting Kubernetes Phase (Number of restarts %d)", restarts)
				if err := ci.StartKubernetes(); err != nil {
					log.Printf("failed during StartKubernetes: %v", err)
				}
				time.Sleep(time.Second)
				restarts += 1
			}
		}
	}()
	return nil
}

func (ci *SshClientInstance) StartKubernetes() error {
	ctx, cancel := context.WithCancel(ci.ctx)

	peer := ci.StartSshClient(ctx, ci.publicKey)
	if peer == nil {
		cancel()
		return fmt.Errorf("failed StartSshClient")
	}

	peer.AddOutbounds(ci.kubernetesOutbounds)
	err := peer.AddInbounds(ci.kubernetesInbounds)
	if err != nil {
		peer.Close("Inbounds failed")
		cancel()
		peer = nil
		return fmt.Errorf("inbounds failed: %w", err)
	} else {
		peer.Wait()
		cancel()
	}
	return nil
}

func (ci *SshClientInstance) StartAttestation() error {
	ctx, cancel := context.WithCancel(ci.ctx)

	peer := ci.StartSshClient(ctx, nil)
	if peer == nil {
		cancel()
		return fmt.Errorf("failed StartSshClient")
	}
	peer.AddOutbounds(ci.attestationOutbounds)
	err := peer.AddInbounds(ci.attestationInbounds)
	if err != nil {
		peer.Close("Inbounds failed")
		cancel()
		peer = nil
		return fmt.Errorf("inbounds failed: %w", err)
	} else {
		peer.Wait()
		cancel()
	}

	return nil
}

func (ci *SshClientInstance) StartSshClient(ctx context.Context, publicKey []byte) *sshproxy.SshPeer {
	config := &ssh.ClientConfig{
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if len(publicKey) == 0 {
				log.Printf("ssh Client skip validating server's HOST KEY (%s) during attestation", key.Type())
				return nil
			}
			if !bytes.Equal(key.Marshal(), ci.publicKey) {
				log.Printf("ssh Client HOST KEY mismatch - %s", key.Type())
				return fmt.Errorf("ssh: host key mismatch")
			}
			log.Printf("ssh Client HOST KEY match - %s", key.Type())
			return nil
		},
		HostKeyAlgorithms: []string{"rsa-sha2-256", "rsa-sha2-512"},
		Auth: []ssh.AuthMethod{
			// Use the PublicKeys method for remote authentication.
			ssh.PublicKeys(*ci.sshClient.wnSigner),
		},
		Timeout: 5 * time.Minute,
	}

	// Dial your ssh server.
	delay := time.Millisecond * 100
	for {
		for _, ppAddr := range ci.ppAddr {
			conn, err := net.DialTimeout("tcp", ppAddr, config.Timeout)
			if err != nil {
				log.Printf("unable to Dial %s: %v", ppAddr, err)
				continue
			}
			log.Printf("ssh Client connected - %s", conn.RemoteAddr())
			netConn, chans, sshReqs, err := ssh.NewClientConn(conn, ppAddr, config)
			if err != nil {
				log.Printf("unable to connect: %v", err)
				conn.Close()
				continue
			}
			return sshproxy.NewSshPeer(ctx, netConn, chans, sshReqs)
		}
		time.Sleep(delay)
		delay *= 2
		if delay > 60*time.Second {
			return nil
		}
	}
}

func InitClientKeys(keyType string) []byte {
	clientPrivateKeyFile := "/tmp/" + keyType
	clientPublicKeyFile := "/tmp/" + keyType + ".pub"

	if clientPrivateKeyBytes, err := readKeyFromFile(clientPrivateKeyFile); err == nil {
		return clientPrivateKeyBytes
	}

	bitSize := 4096

	clientPrivateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		log.Printf("InitClientKeys rsa.GenerateKey: %v", err)
		return nil
	}

	// Validate Private Key
	err = clientPrivateKey.Validate()
	if err != nil {
		log.Printf("InitClientKeys clientPrivateKey.Validate: %v", err)
		return nil
	}

	clientPublicKey, err := ssh.NewPublicKey(&clientPrivateKey.PublicKey)
	if err != nil {
		log.Printf("InitClientKeys ssh.NewPublicKey: %v", err)
		return nil
	}

	clientPublicKeyBytes := ssh.MarshalAuthorizedKey(clientPublicKey)

	clientPrivateKeyBytes := sshutil.RsaPrivateKeyPEM(clientPrivateKey)

	err = WriteKeyToFile(clientPrivateKeyBytes, clientPrivateKeyFile)
	if err != nil {
		log.Printf("InitClientKeys writeKeyToFile Private: %v", err)
		return nil
	}

	err = WriteKeyToFile([]byte(clientPublicKeyBytes), clientPublicKeyFile)
	if err != nil {
		log.Printf("InitClientKeys writeKeyToFile public: %v", err)
		return nil
	}
	return clientPrivateKeyBytes
}

// writePemToFile writes keys to a file
func WriteKeyToFile(keyBytes []byte, saveFileTo string) error {
	err := os.WriteFile(saveFileTo, keyBytes, 0600)
	if err != nil {
		return err
	}

	log.Printf("Key saved to: %s", saveFileTo)
	return nil
}

// writePemToFile writes keys to a file
func readKeyFromFile(filePath string) ([]byte, error) {
	bytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	log.Printf("Key read to: %s", filePath)
	return bytes, nil
}
