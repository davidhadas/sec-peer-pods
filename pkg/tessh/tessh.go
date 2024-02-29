package tessh

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

	"github.com/davidhadas/sec-peer-pods/pkg/sshproxy"
	"github.com/davidhadas/sec-peer-pods/pkg/sshutil"
	"golang.org/x/crypto/ssh"
)

func StartSshClient(clientPrivateKey []byte, serverPublicKey []byte) (peer *sshproxy.SshPeer, ctx context.Context) {
	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(clientPrivateKey)
	if err != nil {
		log.Fatalf("unable to parse private key: %v", err)
	}

	config := &ssh.ClientConfig{
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if len(serverPublicKey) == 0 {
				log.Printf("ssh Client skip validating server's HOST KEY - %s", key.Type())
				return nil
			}
			if !bytes.Equal(key.Marshal(), serverPublicKey) {
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
	addr := "localhost:2022"
	// Dial your ssh server.
	conn, err := net.DialTimeout("tcp", addr, config.Timeout)
	if err != nil {
		log.Fatal("unable to Dial: ", err)
	}
	log.Printf("ssh Client connected - %s", conn.RemoteAddr())
	netConn, chans, sshReqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		log.Fatal("unable to connect: ", err)
	}
	ctx = context.Background()
	ctx, cancel := context.WithCancel(ctx)
	peer = sshproxy.NewSshPeer(ctx, cancel, netConn, chans, sshReqs)
	return
}

func CreateSecret(id string) {

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
		log.Fatal(err.Error())
	}

	// Validate Private Key
	err = clientPrivateKey.Validate()
	if err != nil {
		log.Fatal(err.Error())
	}

	clientPublicKey, err := ssh.NewPublicKey(&clientPrivateKey.PublicKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	clientPublicKeyBytes := ssh.MarshalAuthorizedKey(clientPublicKey)

	clientPrivateKeyBytes := sshutil.RsaPrivateKeyPEM(clientPrivateKey)

	err = writeKeyToFile(clientPrivateKeyBytes, clientPrivateKeyFile)
	if err != nil {
		log.Fatal(err.Error())
	}

	err = writeKeyToFile([]byte(clientPublicKeyBytes), clientPublicKeyFile)
	if err != nil {
		log.Fatal(err.Error())
	}
	return clientPrivateKeyBytes
}

// writePemToFile writes keys to a file
func writeKeyToFile(keyBytes []byte, saveFileTo string) error {
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
