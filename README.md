# Simple MITM with gomitmproxy

A example of [gomitmproxy](https://github.com/AdguardTeam/gomitmproxy)

## TLS Cert

following the [instructions](https://github.com/AdguardTeam/gomitmproxy#tls-interception),

```bash
openssl genrsa -out demo.key 2048
openssl req -new -x509 -key demo.key -out demo.crt
```

## Install Cert

First you need to connect to the proxy server.

Then access the following URL: http://simple.proxy/cert.crt

and install the certificate.

The URL only works when you are connected to the proxy server.
