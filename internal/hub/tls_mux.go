package hub

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"time"
)

type sniffedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *sniffedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

type chanListener struct {
	net.Listener
	ch chan net.Conn
}

func (l *chanListener) Accept() (net.Conn, error) {
	c, ok := <-l.ch
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}

// ListenDualHTTPAndTLS serves both HTTP and HTTPS traffic on the exact same port.
func ListenDualHTTPAndTLS(addr string, handler http.Handler) error {
	baseLn, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	tlsCert, err := generateSelfSignedCert()
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{tlsCert}}

	httpLn := &chanListener{Listener: baseLn, ch: make(chan net.Conn, 64)}
	tlsLn := &chanListener{Listener: baseLn, ch: make(chan net.Conn, 64)}

	go func() {
		_ = http.Serve(httpLn, handler)
	}()
	go func() {
		_ = http.Serve(tls.NewListener(tlsLn, tlsConfig), handler)
	}()

	for {
		rawConn, err := baseLn.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			br := bufio.NewReader(c)
			b, err := br.Peek(1)
			if err != nil {
				_ = c.Close()
				return
			}
			sc := &sniffedConn{Conn: c, r: br}
			// 0x16 indicates a TLS Handshake record
			if b[0] == 0x16 {
				tlsLn.ch <- sc
			} else {
				httpLn.ch <- sc
			}
		}(rawConn)
	}
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(202610),
		Subject:      pkix.Name{Organization: []string{"Sahand Traffic Matrix Pro"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}
