package wnssh

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type KbsClient struct {
	secretKey crypto.PrivateKey
	url       string
}

func InitKbsClient(url string) *KbsClient {
	return &KbsClient{
		url: url,
	}
}

func (kc *KbsClient) SetPemSecret(keyBytes []byte) error {
	key, err := jwt.ParseEdPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return fmt.Errorf("SetPemSecret unable to parse as private key: %w", err)
	}
	kc.secretKey = key
	return nil
}

func (kc *KbsClient) addToken(req *http.Request) error {
	now := time.Now()
	//Ed25519KeyPair
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA,
		jwt.MapClaims{
			"issued_at":      now.Unix(),
			"expires_at":     now.Add(time.Hour * 24).Unix(),
			"invalid_before": now.Unix(),
			"audiences":      "",
			"issuer":         "",
			"jwt_id":         "",
			"subject":        "",
			"nonce":          "",
			"custom":         "",
		})

	tokenString, err := token.SignedString(kc.secretKey)
	if err != nil {
		return err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tokenString))
	return nil
}

func (kc *KbsClient) PostResource(path string, data []byte) error {
	url := fmt.Sprintf("%s/resource/%s", kc.url, path)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("KbsClient faield to PostResource - %v", err)
	}
	err = kc.addToken(req)
	if err != nil {
		return fmt.Errorf("KbsClient failed to create token - %v", err)
	}
	req.Header.Add("Accept", "application/octet-stream")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("KbsClient failed to send set-resource request to Trusty - %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 { // Success
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("KbsClient while reading the response bytes - %v", err)
	}
	return fmt.Errorf("KbsClient failed to set secfret at Trusty: %s", string([]byte(body)))
}
