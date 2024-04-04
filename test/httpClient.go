package test

import (
	"fmt"
	"io"
	"net/http"
)

func HttpClient(dest string) {
	fmt.Printf("HttpClient start : %s\n", dest)
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
}
