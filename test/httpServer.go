package test

import (
	"fmt"
	"io"
	"net/http"
)

type myport string

func (p myport) getRoot(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("HttpServer port %s got request %s\n", p, r.URL)
	io.WriteString(w, fmt.Sprintf("port %s - this is my website!\n", p))
}

func HttpServer(port string) {
	p := myport(port)
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.getRoot)
	s := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	err := s.ListenAndServe()
	fmt.Printf("ListenAndServe Error %v", err)
}
