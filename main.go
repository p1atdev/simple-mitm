package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/AdguardTeam/gomitmproxy"
	"github.com/AdguardTeam/gomitmproxy/mitm"
	"github.com/AdguardTeam/gomitmproxy/proxyutil"
)

func main() {

	tlsCert, err := tls.LoadX509KeyPair("demo.crt", "demo.key")
	if err != nil {
		log.Fatal(err)
	}
	privateKey := tlsCert.PrivateKey.(*rsa.PrivateKey)

	x509c, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}

	mitmConfig, err := mitm.NewConfig(x509c, privateKey, nil)
	if err != nil {
		log.Fatal(err)
	}

	mitmConfig.SetValidity(time.Hour * 24 * 365 * 1) // generate certs valid for 1 year
	mitmConfig.SetOrganization("Simple Proxy")       // cert organization

	proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
		ListenAddr: &net.TCPAddr{
			IP:   net.IPv4(0, 0, 0, 0),
			Port: 9090,
		},
		OnRequest: func(session *gomitmproxy.Session) (request *http.Request, response *http.Response) {
			req := session.Request()

			log.Printf("onRequest: %s %s", req.Method, req.URL.String())

			return nil, nil
		},
		OnResponse: func(session *gomitmproxy.Session) *http.Response {
			log.Printf("onResponse: %s", session.Request().URL.String())

			if _, ok := session.GetProp("blocked"); ok {
				log.Printf("onResponse: was blocked")
			}

			res := session.Response()
			req := session.Request()

			if req.URL.Host == "simple.proxy" {
				switch req.URL.Path {
				case "/":
					html, err := indexHtml()
					if err != nil {
						log.Println(err)
						return nil
					}

					body := bytes.NewReader(html)
					res := proxyutil.NewResponse(http.StatusOK, body, req)
					res.Header.Set("Content-Type", "text/html")

					res.Body = ioutil.NopCloser(body)
					res.Header.Del("Content-Encoding")
					res.ContentLength = int64(len(html))

					return res
				}
			}

			if strings.Index(res.Header.Get("Content-Type"), "text/html") != 0 {
				// Do nothing with non-HTML responses
				fmt.Println("non-html response")
				return nil
			}

			b, err := proxyutil.ReadDecompressedBody(res)
			// Close the original body
			_ = res.Body.Close()
			if err != nil {
				return proxyutil.NewErrorResponse(req, err)
			}

			// Use latin1 before modifying the body
			// Using this 1-byte encoding will let us preserve all original characters
			// regardless of what exactly is the encoding
			body, err := proxyutil.DecodeLatin1(bytes.NewReader(b))
			if err != nil {
				return proxyutil.NewErrorResponse(session.Request(), err)
			}

			if req.URL.Host == "google.com" {
				// print html
				fmt.Println("Google:", body)
			}

			// Modifying the original body
			modifiedBody, err := proxyutil.EncodeLatin1(body + "<!-- EDITED -->")
			if err != nil {
				return proxyutil.NewErrorResponse(session.Request(), err)
			}

			res.Body = ioutil.NopCloser(bytes.NewReader(modifiedBody))
			res.Header.Del("Content-Encoding")
			res.ContentLength = int64(len(modifiedBody))
			return res
		},
		MITMConfig: mitmConfig,

		APIHost: "simple.proxy",
	})

	proxyErr := proxy.Start()

	if proxyErr != nil {
		log.Fatal(err)
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	// Clean up
	proxy.Close()
}

func indexHtml() ([]byte, error) {
	b, err := ioutil.ReadFile("index.html")
	if err != nil {
		return nil, err
	}

	return b, nil
}
