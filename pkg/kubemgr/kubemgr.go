package kubemgr

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"log"
	"path/filepath"

	"github.com/davidhadas/sec-peer-pods/pkg/sshutil"
	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

var KubeMgr *KubeMgrStruct

const (
	cocoNamespace = "confidential-containers-system"
)

type KubeMgrStruct struct {
	client        *kubernetes.Clientset
	cocoNamespace string
}

func InitKubeMgr() error {
	var err error
	KubeMgr = &KubeMgrStruct{
		cocoNamespace: cocoNamespace,
	}

	var kubeCfg *rest.Config
	var devKubeConfigStr *string

	// Try to detect in-cluster config
	if kubeCfg, err = rest.InClusterConfig(); err != nil {
		// Not running in cluster
		if home := homedir.HomeDir(); home != "" {
			devKubeConfigStr = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
		} else {
			devKubeConfigStr = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
		}
		flag.Parse()

		// Use the current context in kubeconfig
		if kubeCfg, err = clientcmd.BuildConfigFromFlags("", *devKubeConfigStr); err != nil {
			return fmt.Errorf("no Config found to access KubeApi! err: %w", err)
		}
	}

	// Create a secrets client
	KubeMgr.client, err = kubernetes.NewForConfig(kubeCfg)
	if err != nil {
		return fmt.Errorf("failed to configure KubeApi using config: %w", err)
	}
	return nil
}

func (kubeMgr *KubeMgrStruct) ReadSecret(secretName string) (privateKey []byte, publicKey []byte, err error) {
	secrets := kubeMgr.client.CoreV1().Secrets(kubeMgr.cocoNamespace)
	secret, err := secrets.Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		log.Printf("ReadSecret return an error: %s", err.Error())
		return
	}
	privateKey = secret.Data["privateKey"]
	publicKey = secret.Data["publicKey"]
	return
}

func (kubeMgr *KubeMgrStruct) DeleteSecret(secretName string) {
	secrets := kubeMgr.client.CoreV1().Secrets(kubeMgr.cocoNamespace)
	secrets.Delete(context.Background(), secretName, metav1.DeleteOptions{})
}

func (kubeMgr *KubeMgrStruct) CreateSecret(secretName string) (privateKey []byte, publicKey []byte, err error) {
	kubeMgr.DeleteSecret(secretName)
	bitSize := 4096
	clientPrivateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, nil, fmt.Errorf("CreateSecret rsa.GenerateKey err: %w", err)
	}

	// Validate Private Key
	err = clientPrivateKey.Validate()
	if err != nil {
		return nil, nil, fmt.Errorf("CreateSecret clientPrivateKey.Validate err: %w", err)
	}

	clientPublicKey, err := ssh.NewPublicKey(&clientPrivateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("CreateSecret ssh.NewPublicKey err: %w", err)
	}

	publicKey = ssh.MarshalAuthorizedKey(clientPublicKey)

	privateKey = sshutil.RsaPrivateKeyPEM(clientPrivateKey)

	secrets := kubeMgr.client.CoreV1().Secrets(kubeMgr.cocoNamespace)
	s := corev1.Secret{}
	s.Name = secretName
	s.Namespace = kubeMgr.cocoNamespace
	s.Data = map[string][]byte{}
	s.Data["privateKey"] = privateKey
	s.Data["publicKey"] = publicKey

	_, err = secrets.Create(context.Background(), &s, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("CreateSecret secrets.Create err: %w", err)
	}
	log.Printf("CreateSecret '%s'", secretName)
	return
}
