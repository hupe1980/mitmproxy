package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/hupe1980/golog"
	"github.com/hupe1980/mitmproxy"
)

func main() {
	certstorage, err := mitmproxy.NewLRUStorage(100)
	if err != nil {
		panic(err)
	}

	ca, privKey, err := mitmproxy.LoadOrCreateCA("ca.cert", "ca.key", func(c *mitmproxy.CAOptions) {
		c.Validity = 365 * 24 * time.Hour
	})
	if err != nil {
		panic(err)
	}

	tlsServerConfig := mitmproxy.DefaultTLSServerConfig.Clone()
	tlsServerConfig.NextProtos = []string{"h2", "http/1.1"}

	mitmCfg, err := mitmproxy.NewMITMConfig(ca, privKey, func(m *mitmproxy.MITMOptions) {
		m.CertStorage = certstorage
		m.TLSServerConfig = tlsServerConfig
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

	proxy.OnRequest(func(req *http.Request) {
		log.Printf("MITM [%s] -> %s", req.Proto, req.URL)
	})

	proxy.OnResponse((func(res *http.Response) error {
		log.Printf("MITM [%s] -> %s", res.Proto, res.Status)
		return nil
	}))

	router := mux.NewRouter().SkipClean(true)

	router.Host("proxy.cert").Handler(mitmproxy.NewCertHandler(ca))
	router.PathPrefix("").Handler(proxy)

	log.Fatal(http.ListenAndServe(":8000", router))
}
