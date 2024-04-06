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
	kubemgr.SkipVerify = true
	err := kubemgr.InitKubeMgr()
	if err != nil {
		fmt.Printf("failed to initialize KubeMgr: %v", err)
		return
	}
	os.Remove(ppssh.PROVEN_PP_PRIVATE_KEY_PATH)
	os.Remove(ppssh.PROVEN_WN_PUBLIC_KEY_PATH)
	os.Remove(ppssh.UNPROVEN_WN_PUBLIC_KEY_PATH)
	os.Remove(ppssh.SIGNELTON_PATH)

	go test.HttpServer("7111")

	ppssh.InitSshServer([]string{"B:KBS:7000", "K:KUBEAPI:16443", "K:DNS:9053"}, []string{"K:KATAAPI:127.0.0.1:7111"}, ppssh.GetSecret(getKey))

	//go test.HttpClient("http://127.0.0.1:7000/")
	go test.HttpClient("http://127.0.0.1:7000/kbs/v0/resource/default/sshclient/publicKey")
	//go test.HttpClient("http://127.0.0.1:7000/kbs/0/default/pp-" + ppssh.PP_SID + "privateKey")

	time.Sleep(120 * time.Second)

	// >>>>>>>>>>>>>>>>>>>>> Testing only <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
	sid := "fake"
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
	// >>>>>>>>>>>>>>>>>>>>> End of Testing only <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

	time.Sleep(15 * time.Second)
	go test.HttpClient("http://127.0.0.1:7000/xxx/yyy/some-resource")

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
