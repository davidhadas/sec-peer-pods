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
	"sync"
	"time"

	"github.com/davidhadas/sec-peer-pods/pkg/kubemgr"
	"github.com/davidhadas/sec-peer-pods/pkg/sshproxy"
	"github.com/davidhadas/sec-peer-pods/pkg/sshutil"
	"golang.org/x/crypto/ssh"
)

const KBS_CLIENT_SECRET = "kbs-client"
const ADAPTOR_SSH_SECRET = "sshclient"
const SSH_PORT = ":2022"

type SshClient struct {
	kc              *KbsClient
	wnSigner        *ssh.Signer
	inboundStrings  []string
	outboundStrings []string
}

type SshClientInstance struct {
	sid          string
	publicKey    []byte
	ppAddr       []string
	sshClient    *SshClient
	ctx          context.Context
	cancel       context.CancelFunc
	k8sPhase     bool
	inbounds     sshproxy.Inbounds
	outbounds    sshproxy.Outbounds
	inboundPorts map[string]string
	wg           sync.WaitGroup
}

var logger = log.New(log.Writer(), "[adaptor/wnssh] ", log.LstdFlags|log.Lmsgprefix)

func PpSecretName(sid string) string {
	return "pp-" + sid
}

func InitSshClient(inbound_strings, outbound_strings []string, kbsUrl string) (*SshClient, error) {
	err := kubemgr.InitKubeMgr()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize KubeMgr: %w", err)
	}

	// Read WN Secret
	wnPrivateKey, wnPublicKey, err := kubemgr.KubeMgr.ReadSecret(ADAPTOR_SSH_SECRET)
	if err != nil {
		// auto-create a secret
		wnPrivateKey, wnPublicKey, err = kubemgr.KubeMgr.CreateSecret(ADAPTOR_SSH_SECRET)
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

	kbscPrivateKey, _, err := kubemgr.KubeMgr.ReadSecret(KBS_CLIENT_SECRET)
	if err != nil {
		return nil, fmt.Errorf("failed to read KBS Client Secret: %w", err)
	}

	kc := InitKbsClient(kbsUrl)
	err = kc.SetPemSecret(kbscPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("KbsClient - %v", err)
	}

	wnSecretPath := "default/sshclient/publicKey"
	log.Printf("Updating KBS with secret for: %s", wnSecretPath)
	err = kc.PostResource(wnSecretPath, wnPublicKey)
	if err != nil {
		return nil, fmt.Errorf("PostResource: %v", err)
	}

	sshClient := &SshClient{
		kc:              kc,
		wnSigner:        &signer,
		inboundStrings:  inbound_strings,
		outboundStrings: outbound_strings,
	}

	return sshClient, nil
}

func (ci *SshClientInstance) GetPort(name string) string {
	var ok bool
	var inPort string
	inPort, ok = ci.inboundPorts[name]
	if !ok {
		return ""
	}
	return inPort
}
func (ci *SshClientInstance) DisconnectPP(sid string) {

	ci.inbounds.DelAll()

	// Cancel the VM connction
	ci.cancel()
	ci.wg.Wait()
	log.Print("SshClientInstance DisconnectPP Success")

	// Remove peerPod Secret named peerPodId
	// TBD: Add this code once KBS integration is complete
	// kubemgr.KubeMgr.DeleteSecret(PpSecretName(sid))
}

func (c *SshClient) InitPP(ctx context.Context, sid string, ipAddr []netip.Addr) *SshClientInstance {
	// Create peerPod Secret named peerPodId
	var publicKey, privateKey []byte
	var err error

	// Try reading first in case we resume an existing PP
	log.Printf("InitPP Read/Create PP Secret named: %s", PpSecretName(sid))
	privateKey, publicKey, err = kubemgr.KubeMgr.ReadSecret(PpSecretName(sid))
	if err != nil {
		privateKey, publicKey, err = kubemgr.KubeMgr.CreateSecret(PpSecretName(sid))
		if err != nil {
			log.Printf("failed to create PP Secret: %v", err)
			return nil
		}
	}

	// >>> Update the KBS about the SID's Secret !!! <<<
	sidSecretPath := fmt.Sprintf("default/pp-%s/privateKey", sid)
	log.Printf("Updating KBS with secret for: %s", sidSecretPath)
	err = c.kc.PostResource(sidSecretPath, privateKey)
	if err != nil {
		log.Printf("failed to PostResource PP Secret: %v", err)
		return nil
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
		sid:          sid,
		publicKey:    serverSshPublicKeyBytes,
		ppAddr:       ppAddr,
		sshClient:    c,
		ctx:          ctx,
		cancel:       cancel,
		inboundPorts: make(map[string]string),
	}

	for _, tag := range c.inboundStrings {
		name, inPort, err := ci.inbounds.Add(tag, &ci.wg)
		if err != nil {
			log.Printf("failed to add inbound: %v", err)
		}
		ci.inboundPorts[name] = inPort
	}
	for _, tag := range c.outboundStrings {
		ci.outbounds.Add(tag)
	}

	return ci
}

func (ci *SshClientInstance) Start() error {
	if !ci.k8sPhase {
		// Attestation Phase
		log.Println("Attstation Phase: Starting")
		if err := ci.StartAttestation(); err != nil {
			return fmt.Errorf("attstation Phase failed: %v", err)
		}
		log.Println("Attstation Phase: Done")
		ci.k8sPhase = true
	}

	// Kubernetes Phase
	ci.wg.Add(1)
	go func() {
		defer ci.wg.Done()
		restarts := 0
		for {
			select {
			case <-ci.ctx.Done():
				log.Printf("Kubernetes Phase: Done")
				return
			default:
				log.Printf("Kubernetes Phase: Starting (Number of restarts %d)", restarts)
				if err := ci.StartKubernetes(); err != nil {
					log.Printf("Kubernetes Phase: failed: %v", err)
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
	defer cancel()
	peer := ci.StartSshClient(ctx, sshproxy.KUBERNETES, ci.publicKey, ci.sid)
	if peer == nil {

		return fmt.Errorf("Kubernetes Phase: failed StartSshClient")
	}

	peer.AddOutbounds(ci.outbounds)
	err := peer.AddInbounds(ci.inbounds)
	if err != nil {
		peer.Close("Inbounds failed")
		peer = nil
		return fmt.Errorf("inbounds failed: %w", err)
	}
	peer.Wait()
	return nil
}

func (ci *SshClientInstance) StartAttestation() error {
	ctx, cancel := context.WithCancel(ci.ctx)
	defer cancel()
	peer := ci.StartSshClient(ctx, sshproxy.ATTESTATION, nil, ci.sid)
	if peer == nil {
		return fmt.Errorf("Attestation Phase: failed StartSshClient")
	}
	peer.AddOutbounds(ci.outbounds)
	err := peer.AddInbounds(ci.inbounds)
	if err != nil {
		peer.Close("Inbounds failed")
		peer = nil
		return fmt.Errorf("inbounds failed: %w", err)
	}
	peer.Wait()
	if !peer.IsUpgraded() {
		return fmt.Errorf("Attestation PHASE closed without being upgraded")
	}
	return nil
}

func (ci *SshClientInstance) StartSshClient(ctx context.Context, phase string, publicKey []byte, sid string) *sshproxy.SshPeer {
	config := &ssh.ClientConfig{
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if len(publicKey) == 0 {
				log.Printf("%s Phase: ssh Client skip validating server's HOST KEY (%s) during attestation", phase, key.Type())
				return nil
			}
			if !bytes.Equal(key.Marshal(), ci.publicKey) {
				log.Printf("%s Phase: ssh Client HOST KEY mismatch - %s", phase, key.Type())
				return fmt.Errorf("%s Phase: ssh host key mismatch", phase)
			}
			log.Printf("%s Phase: ssh Client HOST KEY match - %s", phase, key.Type())
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
				log.Printf("%s Phase: unable to Dial %s: %v", phase, ppAddr, err)
				continue
			}
			log.Printf("%s Phase: ssh Client connected - %s", phase, conn.RemoteAddr())
			netConn, chans, sshReqs, err := ssh.NewClientConn(conn, ppAddr, config)
			if err != nil {
				log.Printf("%s Phase: unable to connect: %v", phase, err)
				conn.Close()
				continue
			}
			return sshproxy.NewSshPeer(ctx, phase, netConn, chans, sshReqs, sid)
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
