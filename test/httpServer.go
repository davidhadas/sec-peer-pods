package test

import (
	"fmt"
	"io"
	"net/http"
)

func getRoot(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("got / request %s\n", r.URL)
	io.WriteString(w, "This is my website!\n")
}

func HttpServer(port string) {
	http.HandleFunc("/", getRoot)

	err := http.ListenAndServe(":"+port, nil)
	fmt.Printf("ListenAndServe Error %v", err)
}
