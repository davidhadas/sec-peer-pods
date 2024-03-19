package sshutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"math/big"
	"time"
)

const SSHPORT = "2222"

// RsaPrivateKeyPEM return a PEM for the RSA Private Key
func RsaPrivateKeyPEM(pKey *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(pKey),
	})
}

func GetRandomPort() int {
	for i := 0; i < 100; i++ {
		if inPort, err := rand.Int(rand.Reader, big.NewInt(50000)); err == nil {
			return int(inPort.Uint64()) + 10000
		}
		time.Sleep(100 * time.Millisecond)
	}
	log.Fatalf("Failed to GetRandomPort")
	return 0 // never used
}
