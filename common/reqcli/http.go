package reqcli

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"
)

var (
	dftHttpCli  *http.Client
	cliLoadOnce sync.Once
)
var httpTimeout = 90 * time.Second

func getDefaultTransPort() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 60 * time.Second,
			DualStack: true,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       180 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
}
func GetDefaultHttpClient() *http.Client {
	cliLoadOnce.Do(func() {
		dftHttpCli = &http.Client{
			Timeout:   httpTimeout,
			Transport: getDefaultTransPort(),
		}
	})
	return dftHttpCli
}
