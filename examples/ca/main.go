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
	ca, privateKey, err := mitmproxy.LoadOrCreateCA("ca.cert", "ca.key", func(c *mitmproxy.CAOptions) {
		c.Validity = 365 * 24 * time.Hour
	})
	if err != nil {
		panic(err)
	}

	mitmCfg, err := mitmproxy.NewMITMConfig(func(m *mitmproxy.MITMOptions) {
		m.CA = ca
		m.PrivateKey = privateKey
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

	router.Host("proxy.cert").Handler(mitmproxy.NewCertHandler(mitmCfg.CA()))
	router.PathPrefix("").Handler(proxy)

	log.Fatal(http.ListenAndServe(":8000", router))
}
