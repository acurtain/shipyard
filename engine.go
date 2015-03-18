package shipyard

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	httpTimeout = time.Duration(1 * time.Second)
)

type (
	Health struct {
		Status       string `json:"status,omitempty" gorethink:"status,omitempty"`
		ResponseTime int64  `json:"response_time,omitempty" gorethink:"response_time,omitempty"`
	}

	Engine struct {
		Addr           string  `json:"addr,omitempty" gorethink:"addr,omitempty"`
		CACertificate  string  `json:"ca_cert,omitempty" gorethink:"ca_cert,omitempty"`
		DockerVersion  string  `json:"docker_version,omitempty"`
		Health         *Health `json:"health,omitempty" gorethink:"health,omitempty"`
		ID             string  `json:"id,omitempty" gorethink:"id,omitempty"`
		SSLCertificate string  `json:"ssl_cert,omitempty" gorethink:"ssl_cert,omitempty"`
		SSLKey         string  `json:"ssl_key,omitempty" gorethink:"ssl_key,omitempty"`
	}
)

func dialTimeout(network, addr string) (net.Conn, error) {
	return net.DialTimeout(network, addr, httpTimeout)
}

func (e *Engine) Certificate() (*tls.Certificate, error) {

	if e.SSLCertificate == "" {
		return nil, nil
	}
	cert, err := tls.X509KeyPair([]byte(e.SSLCertificate), []byte(e.SSLKey))
	return &cert, err
}

func (e *Engine) Version() (string, error) {
	return "TODO", nil
}

func (e *Engine) Ping() (int, error) {
	status := 0
	addr := e.Addr
	tlsConfig := &tls.Config{}

	// check for https
	if strings.Index(addr, "https") != -1 {
		cert, err := e.Certificate()
		if err != nil {
			return 0, err
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{*cert},
		}

		// use custom ca cert if specified
		if e.CACertificate != "" {
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM([]byte(e.CACertificate))
			tlsConfig.RootCAs = caCertPool
		}
	}
	// allow insecure
	tlsConfig.InsecureSkipVerify = true

	transport := http.Transport{
		Dial:            dialTimeout,
		TLSClientConfig: tlsConfig,
	}

	client := http.Client{
		Transport: &transport,
	}
	uri := fmt.Sprintf("%s/_ping", addr)
	resp, err := client.Get(uri)
	if err != nil {
		return 0, err
	} else {
		defer resp.Body.Close()
		status = resp.StatusCode
	}
	return status, nil
}
