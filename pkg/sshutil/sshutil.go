package sshutil

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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
