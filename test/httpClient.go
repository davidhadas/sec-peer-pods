package test

import (
	"fmt"
	"io"
	"net/http"
)

func HttpClient(dest string) {
	c := http.Client{}
	resp, err := c.Get(dest)
	if err != nil {
		fmt.Printf("HttpClient Error %s", err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("HttpClient ReadAll Error %s", err)
		return
	}
	fmt.Printf("HttpClient Body : %s", body)
}
