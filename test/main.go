package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", test)
	http.ListenAndServe("localhost:8081", nil)
}

func test(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.Header)
	var buf []byte
	r.Body.Read(buf)
	fmt.Println(string(buf))
}
