package wnssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/davidhadas/sec-peer-pods/pkg/kubemgr"
	"github.com/davidhadas/sec-peer-pods/pkg/sshproxy"
	"github.com/davidhadas/sec-peer-pods/pkg/sshutil"
	"golang.org/x/crypto/ssh"
)

const CLIENT_SSH_SECRET = "sshclient"

func TerminatePeerPodTunnel(peerPodId string) {
	// Remove peerPod Secret named peerPodId
	kubemgr.KubeMgr.DeleteSecret(peerPodId)
}

func GetPeerPodKeys(peerPodId string) (ppPublicKey []byte, tePrivateKey []byte) {
	var err error
	// Create peerPod Secret named peerPodId
	_, ppPublicKey, err = kubemgr.KubeMgr.CreateSecret(peerPodId)
	if err != nil {
		log.Printf("failed to create PP Secret: %v", err)
		return
	}

	// Read WN Secret
	tePrivateKey, _, err = kubemgr.KubeMgr.ReadSecret(CLIENT_SSH_SECRET)
	if err != nil {
		// auto-create a secret
		tePrivateKey, _, err = kubemgr.KubeMgr.CreateSecret(CLIENT_SSH_SECRET)
		if err != nil {
			log.Printf("failed to auto create WN Secret")
			return
		}
	}
	return
}

func StartSshClient(ctx context.Context, ppAddr string, clientPrivateKey []byte, serverPublicKey []byte) (peer *sshproxy.SshPeer, done chan bool) {
	done = make(chan bool, 1)

	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(clientPrivateKey)
	if err != nil {
		log.Printf("unable to parse private key: %v", err)
		return
	}

	var serverSshPublicKey ssh.PublicKey
	if len(serverPublicKey) > 0 {
		serverSshPublicKey, _, _, _, err = ssh.ParseAuthorizedKey(serverPublicKey)
		if err != nil {
			log.Printf("unable to ParseAuthorizedKey serverPublicKey: %v", err)
			return
		}
	}

	config := &ssh.ClientConfig{
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if len(serverPublicKey) == 0 {
				log.Printf("ssh Client skip validating server's HOST KEY - %s", key.Type())
				return nil
			}
			if !bytes.Equal(key.Marshal(), serverSshPublicKey.Marshal()) {
				log.Printf("ssh Client HOST KEY mismatch - %s", key.Type())
				return fmt.Errorf("ssh: host key mismatch")
			}
			log.Printf("ssh Client HOST KEY match - %s", key.Type())
			return nil
		},
		HostKeyAlgorithms: []string{"rsa-sha2-256", "rsa-sha2-512"},
		Auth: []ssh.AuthMethod{
			// Use the PublicKeys method for remote authentication.
			ssh.PublicKeys(signer),
		},
		Timeout: 5 * time.Minute,
	}
	// Dial your ssh server.
	conn, err := net.DialTimeout("tcp", ppAddr, config.Timeout)
	if err != nil {
		log.Printf("unable to Dial: %v", err)
		return
	}
	log.Printf("ssh Client connected - %s", conn.RemoteAddr())
	netConn, chans, sshReqs, err := ssh.NewClientConn(conn, ppAddr, config)
	if err != nil {
		log.Printf("unable to connect: %v", err)
	}
	peer = sshproxy.NewSshPeer(ctx, done, netConn, chans, sshReqs)
	return
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
