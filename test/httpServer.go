package test

import (
	"fmt"
	"io"
	"net/http"
)

func getRoot(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("got request %s\n", r.URL)
	io.WriteString(w, "This is my website!\n")
}

func HttpServer(port string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", getRoot)
	s := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	err := s.ListenAndServe()
	fmt.Printf("ListenAndServe Error %v", err)
}
