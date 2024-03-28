package ppssh

import (
	"log"
	"time"
)

type PpSecrets struct {
	keys      []string
	secrets   map[string][]byte
	getSecret GetSecret
}

type GetSecret func(name string) ([]byte, error)

func NewPpSecrets(getSecret GetSecret) *PpSecrets {
	return &PpSecrets{
		keys:      []string{},
		secrets:   make(map[string][]byte),
		getSecret: getSecret,
	}
}

func (fs *PpSecrets) AddKey(key string) {
	fs.keys = append(fs.keys, key)
}

func (fs *PpSecrets) GetKey(key string) []byte {
	return fs.secrets[key]
}

func (fs *PpSecrets) Go() {
	sleeptime := time.Duration(1)

	for len(fs.keys) > 0 {
		key := fs.keys[0]
		log.Printf("PpSecrets obtaining key %s", key)

		data, err := fs.getSecret(key)
		if err == nil {
			log.Printf("PpSecrets %s success", key)
			fs.secrets[key] = data
			fs.keys = fs.keys[1:]
			continue
		}
		log.Printf("PpSecrets %s getSecret err: %v", key, err)
		time.Sleep(sleeptime * time.Second)
		sleeptime *= 2
		if sleeptime > 30 {
			sleeptime = 30
		}
	}
}

/*
namespace := "podns"
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				log.Printf("ForwarderSecrets client.DialContext() network: %s addr: %s", network, addr)
				ns, err := netns.GetFromName(namespace)
				if err != nil {
					log.Printf("ForwarderSecrets get ns '%s': %v", namespace, err)
					return nil, fmt.Errorf("get ns '%s': %w", namespace, err)
				}
				defer ns.Close()

				runtime.LockOSThread()
				if err := netns.Set(ns); err != nil {
					log.Printf("ForwarderSecrets setns '%s': %v", namespace, err)
					return nil, fmt.Errorf("setns '%s': %w", namespace, err)
				}
				log.Printf("ForwarderSecrets client.DialContext() success")

				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	}
	resp, err := client.Get("http://127.0.0.1:8006/cdh/resource/default/" + key) //key = pp-fake/privateKey, sshclient/publicKey
		if err != nil {
			log.Printf("ForwarderSecrets %s client.Get() err: %v", key, err)
			break
		} else {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Printf("ForwarderSecrets %s io.ReadAll err: %v", key, err)
			} else {
				success = true
				log.Printf("ForwarderSecrets %s success", key)
				fs.secrets[key] = body
				//err = os.WriteFile(ppssh.PROVEN_PP_PRIVATE_KEY_PATH, body, 0644)
				//if err != nil {
				//	log.Printf("Error creating %s: %s", ppssh.PROVEN_PP_PRIVATE_KEY_PATH, err.Error())
				//	return
				//}
			}
			resp.Body.Close()
*/
