package main

import (
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
	os.Remove(ppssh.PROVEN_TE_PUBLIC_KEY_PATH)
	os.Remove(ppssh.UNPROVEN_TE_PUBLIC_KEY_PATH)
	os.Remove(ppssh.SIGNELTON_PATH)

	go test.Server(7100)

	ppssh.InitSshServer([]int{7000}, []int{}, []int{6443, 9053}, []int{7100})

	time.Sleep(30 * time.Second)

	sid := "myppid"
	_, tePublicKey, _ := kubemgr.KubeMgr.ReadSecret(wnssh.ADAPTOR_SSH_SECRET)
	ppPrivateKey, _, _ := kubemgr.KubeMgr.ReadSecret(wnssh.PpSecretName(sid))

	if err := os.WriteFile("/var"+ppssh.PROVEN_TE_PUBLIC_KEY_PATH, tePublicKey, 0600); err != nil {
		log.Print(err.Error())
		return
	}
	if err := os.WriteFile("/var"+ppssh.PROVEN_PP_PRIVATE_KEY_PATH, ppPrivateKey, 0600); err != nil {
		log.Print(err.Error())
		return
	}

	ppssh.CopyFile("/var"+ppssh.PROVEN_TE_PUBLIC_KEY_PATH, ppssh.PROVEN_TE_PUBLIC_KEY_PATH)
	ppssh.CopyFile("/var"+ppssh.PROVEN_PP_PRIVATE_KEY_PATH, ppssh.PROVEN_PP_PRIVATE_KEY_PATH)

	time.Sleep(10 * time.Minute)
}
