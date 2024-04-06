package test

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

func HttpClient(dest string) {
	fmt.Printf("HttpClient start : %s\n", dest)
	for {
		fmt.Printf("HttpClient sending req: %s\n", dest)
		c := http.Client{}
		resp, err := c.Get(dest)
		if err != nil {
			fmt.Printf("HttpClient %s Error %s", dest, err)
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("HttpClient %s ReadAll Error %s", dest, err)
			return
		}
		fmt.Printf("HttpClient %s Body : %s\n", dest, body)
		time.Sleep(time.Second * 5)
	}
}
