package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/davidhadas/sec-peer-pods/pkg/kubemgr"
	"github.com/davidhadas/sec-peer-pods/pkg/ppssh"
	"github.com/davidhadas/sec-peer-pods/pkg/wnssh"
	"github.com/davidhadas/sec-peer-pods/test"
)

func main() {
	kubemgr.InitKubeMgr()
	os.Remove(ppssh.PROVEN_PP_PRIVATE_KEY_PATH)
	os.Remove(ppssh.PROVEN_WN_PUBLIC_KEY_PATH)
	os.Remove(ppssh.UNPROVEN_WN_PUBLIC_KEY_PATH)
	os.Remove(ppssh.SIGNELTON_PATH)

	go test.HttpServer("7111")

	ppssh.InitSshServer([]string{"KBS:7000"}, []string{}, []string{"KUBEAPI:6443", "DNS:9053"}, []string{"KATAAPI:127.0.0.1:7111"}, ppssh.GetSecret(getKey))
	//ppssh.InitSshServer([]string{"KBS:7000"}, []string{}, []string{}, []string{}, ppssh.GetSecret(getKey))

	go test.HttpClient("http://127.0.0.1:7000/")
	time.Sleep(30 * time.Second)

	sid := "myppid"
	_, tePublicKey, _ := kubemgr.KubeMgr.ReadSecret(wnssh.ADAPTOR_SSH_SECRET)
	ppPrivateKey, _, _ := kubemgr.KubeMgr.ReadSecret(wnssh.PpSecretName(sid))

	if err := os.WriteFile("/var"+ppssh.PROVEN_WN_PUBLIC_KEY_PATH, tePublicKey, 0600); err != nil {
		log.Print(err.Error())
		return
	}
	if err := os.WriteFile("/var"+ppssh.PROVEN_PP_PRIVATE_KEY_PATH, ppPrivateKey, 0600); err != nil {
		log.Print(err.Error())
		return
	}

	ppssh.CopyFile("/var"+ppssh.PROVEN_WN_PUBLIC_KEY_PATH, ppssh.PROVEN_WN_PUBLIC_KEY_PATH)
	ppssh.CopyFile("/var"+ppssh.PROVEN_PP_PRIVATE_KEY_PATH, ppssh.PROVEN_PP_PRIVATE_KEY_PATH)

	time.Sleep(10 * time.Minute)
}

func getKey(key string) (data []byte, err error) {
	switch key {
	case ppssh.WN_PUBLIC_KEY:
		data, err = os.ReadFile(ppssh.PROVEN_WN_PUBLIC_KEY_PATH)

	case ppssh.PP_PRIVATE_KEY:
		data, err = os.ReadFile(ppssh.PROVEN_PP_PRIVATE_KEY_PATH)
	}
	if err == nil && len(data) == 0 {
		err = fmt.Errorf("getKey returns and empty key")
	}
	return
}

/*
	func WaitForProvenKeys(ctx context.Context, peer *sshproxy.SshPeer) {
		go func() {
			ticker := time.NewTicker(200 * time.Millisecond)
		OUT:
			for {
				select {
				case <-ticker.C:
					if key, err := os.ReadFile(ppssh.PROVEN_PP_PRIVATE_KEY_PATH); err != nil || len(key) == 0 {
						continue
					}
					if key, err := os.ReadFile(ppssh.PROVEN_WN_PUBLIC_KEY_PATH); err != nil || len(key) == 0 {
						continue
					}

					log.Printf("Found files %s, %s", ppssh.PROVEN_PP_PRIVATE_KEY_PATH, ppssh.PROVEN_WN_PUBLIC_KEY_PATH)

					peer.Close("Found proven files")
					break OUT
				case <-ctx.Done():
					break OUT
				}
			}
			ticker.Stop()
		}()
	}
*/
/*
func getKubernetesPhaseKeys() (ppPrivateKeyBytes []byte, tePublicKeyBytes []byte) {
	var err error

	ppPrivateKeyBytes, err = os.ReadFile(ppssh.PROVEN_PP_PRIVATE_KEY_PATH)
	if err != nil {
		log.Fatalf("SSH Server failed to get PP Private Key from %s, err: %v", ppssh.PROVEN_PP_PRIVATE_KEY_PATH, err)
	}

	// Kubernetes Phase  - must have WN proven tePublicKeyBytes and ppPrivateKeyBytes
	tePublicKeyBytes, err = os.ReadFile(ppssh.PROVEN_WN_PUBLIC_KEY_PATH)
	if err != nil {
		log.Fatalf("SSH Server failed to get WN Public Key from %s, err: %v", ppssh.PROVEN_WN_PUBLIC_KEY_PATH, err)
	}

	log.Printf("SSH Server initialized keys for Kubernetes Phase")
	return
}
*/
