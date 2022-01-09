# mitmproxy
![Build Status](https://github.com/hupe1980/mitmproxy/workflows/build/badge.svg) 
[![Go Reference](https://pkg.go.dev/badge/github.com/hupe1980/mitmproxy.svg)](https://pkg.go.dev/github.com/hupe1980/mitmproxy)
> Golang mitm proxy implementation

:warning: This is experimental and subject to breaking changes.

## Usage
```golang
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
```

### Documentation
See [godoc](https://pkg.go.dev/github.com/hupe1980/mitmproxy).

### Examples
See more complete [examples](https://github.com/hupe1980/mitmproxy/tree/main/_examples).

## License
[MIT](LICENCE)