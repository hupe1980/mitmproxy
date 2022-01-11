package main

import (
	"log"
	"net/http"

	"github.com/hupe1980/golog"
	"github.com/hupe1980/mitmproxy"
)

func main() {
	certstorage, err := mitmproxy.NewLRUStorage(100)
	if err != nil {
		panic(err)
	}

	ca, privKey, err := mitmproxy.NewCA()
	if err != nil {
		panic(err)
	}

	mitmCfg, err := mitmproxy.NewMITMConfig(ca, privKey, func(m *mitmproxy.MITMOptions) {
		m.CertStorage = certstorage
	})
	if err != nil {
		panic(err)
	}

	proxy, err := mitmproxy.New(func(o *mitmproxy.Options) {
		o.Logger = golog.NewGoLogger(golog.DEBUG, log.Default())
		o.MITMConfig = mitmCfg
	})
	if err != nil {
		panic(err)
	}

	log.Fatal(http.ListenAndServe(":8000", proxy))
}
