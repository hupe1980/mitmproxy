package main

import (
	"log"
	"net/http"

	"github.com/hupe1980/golog"
	"github.com/hupe1980/mitmproxy"
)

func main() {
	proxy, err := mitmproxy.New(func(o *mitmproxy.Options) {
		o.Logger = golog.NewGoLogger(golog.DEBUG, log.Default())
	})
	if err != nil {
		panic(err)
	}

	log.Fatal(http.ListenAndServe(":8000", proxy))
}
