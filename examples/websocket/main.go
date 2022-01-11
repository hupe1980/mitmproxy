package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hupe1980/mitmproxy"
)

var upgrader = websocket.Upgrader{} // use default options

func echo(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	defer c.Close()

	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			log.Println("read:", err)
			break
		}

		log.Printf("recv: %s", message)

		if err = c.WriteMessage(mt, message); err != nil {
			log.Println("write:", err)
			break
		}
	}
}

func StartEchoServer(wg *sync.WaitGroup) {
	log.Println("Starting echo server")

	go func() {
		http.HandleFunc("/", echo)

		if err := http.ListenAndServeTLS("localhost:12345", "localhost.crt", "localhost.key", nil); err != nil {
			panic("ListenAndServe: " + err.Error())
		}
	}()

	wg.Done()
}

func StartProxy(wg *sync.WaitGroup) {
	log.Println("Starting proxy server")

	proxy, err := mitmproxy.New()
	if err != nil {
		panic(err)
	}

	proxy.OnWSMessage(func(msg *mitmproxy.WSMessage) {
		log.Printf("MITM [%s] -> %s", msg.Direction(), msg.Msg)
	})

	go func() {
		if err := http.ListenAndServe("localhost:54321", proxy); err != nil {
			log.Fatal(err)
		}
	}()

	wg.Done()
}

func main() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	wg := &sync.WaitGroup{}
	wg.Add(2)

	StartEchoServer(wg)
	StartProxy(wg)

	wg.Wait()

	endpointURL := "wss://localhost:12345"
	proxyURL := "http://localhost:54321"

	surl, _ := url.Parse(proxyURL)
	dialer := websocket.Dialer{
		Subprotocols:    []string{"p1"},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // nolint:gosec // ok
		Proxy:           http.ProxyURL(surl),
	}

	c, res, err := dialer.Dial(endpointURL, nil)
	if err != nil {
		log.Fatal("dial:", err)
	}

	defer func() {
		res.Body.Close()
		c.Close()
	}()

	done := make(chan struct{})

	go func() {
		defer c.Close()
		defer close(done)

		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				log.Println("read:", err)
				return
			}

			log.Printf("recv: %s", message)
		}
	}()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case t := <-ticker.C:
			err := c.WriteMessage(websocket.TextMessage, []byte(t.String()))
			if err != nil {
				log.Println("write:", err)
				return
			}
		case <-interrupt:
			log.Println("interrupt")
			// To cleanly close a connection, a client should send a close
			// frame and wait for the server to close the connection.
			err := c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("write close:", err)
				return
			}
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			c.Close()

			return
		}
	}
}
