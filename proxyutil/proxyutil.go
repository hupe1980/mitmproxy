package proxyutil

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

// NewResponse builds a new HTTP response.
// If body is nil, an empty byte.Buffer will be provided to be consistent with
// the guarantees provided by http.Transport and http.Client.
func NewResponse(code int, body io.Reader, req *http.Request) *http.Response {
	if body == nil {
		body = &bytes.Buffer{}
	}

	rc, ok := body.(io.ReadCloser)
	if !ok {
		rc = ioutil.NopCloser(body)
	}

	res := &http.Response{
		StatusCode: code,
		Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
		Body:       rc,
		Request:    req,
	}

	if req != nil {
		res.Close = req.Close
		res.Proto = req.Proto
		res.ProtoMajor = req.ProtoMajor
		res.ProtoMinor = req.ProtoMinor
	}

	return res
}

// ReadDecompressedBody reads full response body and decompresses it if necessary
func ReadDecompressedBody(res *http.Response) ([]byte, error) {
	rBody := res.Body
	if res.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(rBody)
		if err != nil {
			return nil, err
		}

		rBody = gzReader

		defer gzReader.Close()
	}

	return ioutil.ReadAll(rBody)
}

// DecodeLatin1 - decodes Latin1 string from the reader
// This method is useful for editing response bodies when you don't want
// to handle different encodings
func DecodeLatin1(reader io.Reader) (string, error) {
	r := transform.NewReader(reader, charmap.ISO8859_1.NewDecoder())

	b, err := ioutil.ReadAll(r)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// EncodeLatin1 - encodes the string as a byte array using Latin1
func EncodeLatin1(str string) ([]byte, error) {
	return charmap.ISO8859_1.NewEncoder().Bytes([]byte(str))
}
