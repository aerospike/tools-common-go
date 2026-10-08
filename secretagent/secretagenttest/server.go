// Package secretagenttest provides an in-process Aerospike Secret Agent for
// tests, in the spirit of net/http/httptest.
package secretagenttest

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerospike/tools-common-go/secretagent/internal/wire"
)

const connTimeout = 10 * time.Second

// Secrets maps resource to key to value. A request without a resource is
// looked up under the "" resource.
type Secrets map[string]map[string]string

// Server is a fake Secret Agent. It is closed automatically when the test that
// created it ends.
type Server struct {
	listener       net.Listener
	secrets        Secrets
	network        string
	caFile         string
	clientCertFile string
	clientKeyFile  string
	wg             sync.WaitGroup
	closeOnce      sync.Once
}

// NewServer starts a plaintext agent on a free TCP port on 127.0.0.1.
func NewServer(tb testing.TB, secrets Secrets) *Server {
	tb.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("secretagenttest: listen: %v", err)
	}

	s := &Server{network: "tcp"}

	return s.start(tb, ln, secrets)
}

// NewUnixServer starts a plaintext agent on a unix socket.
func NewUnixServer(tb testing.TB, secrets Secrets) *Server {
	tb.Helper()

	// os.MkdirTemp keeps the path under the unix socket length limit, which
	// tb.TempDir can exceed on macOS.
	dir, err := os.MkdirTemp("", "sa")
	if err != nil {
		tb.Fatalf("secretagenttest: create socket dir: %v", err)
	}

	tb.Cleanup(func() { _ = os.RemoveAll(dir) })

	ln, err := net.Listen("unix", filepath.Join(dir, "agent.sock"))
	if err != nil {
		tb.Fatalf("secretagenttest: listen: %v", err)
	}

	s := &Server{network: "unix"}

	return s.start(tb, ln, secrets)
}

// NewTLSServer starts a TLS agent on a free TCP port on 127.0.0.1. Its
// certificate is valid for 127.0.0.1 and localhost and is signed by the CA in
// CAFile.
func NewTLSServer(tb testing.TB, secrets Secrets) *Server {
	tb.Helper()

	return newTLSServer(tb, secrets, false)
}

// NewMutualTLSServer is like NewTLSServer, but it also requires a client
// certificate. ClientCertFile and ClientKeyFile hold one it accepts.
func NewMutualTLSServer(tb testing.TB, secrets Secrets) *Server {
	tb.Helper()

	return newTLSServer(tb, secrets, true)
}

// Addr returns host:port for TCP servers and the socket path for unix servers.
func (s *Server) Addr() string {
	return s.listener.Addr().String()
}

// Network returns "tcp" or "unix".
func (s *Server) Network() string {
	return s.network
}

// CAFile returns the PEM file of the CA that signed the server certificate, or
// "" for plaintext servers.
func (s *Server) CAFile() string {
	return s.caFile
}

// ClientCertFile returns a PEM client certificate accepted by a mutual TLS
// server, or "" for other servers.
func (s *Server) ClientCertFile() string {
	return s.clientCertFile
}

// ClientKeyFile returns the PEM key for ClientCertFile, or "" for other servers.
func (s *Server) ClientKeyFile() string {
	return s.clientKeyFile
}

// Close stops the server and waits for open connections to finish. It is safe
// to call more than once.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		_ = s.listener.Close()
		s.wg.Wait()
	})
}

func (s *Server) start(tb testing.TB, ln net.Listener, secrets Secrets) *Server {
	tb.Helper()

	s.listener = ln
	s.secrets = make(Secrets, len(secrets))

	for resource, values := range secrets {
		s.secrets[resource] = make(map[string]string, len(values))
		for key, value := range values {
			s.secrets[resource][key] = value
		}
	}

	s.wg.Add(1)

	go s.serve()

	tb.Cleanup(s.Close)

	return s
}

func (s *Server) serve() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		s.wg.Add(1)

		go func() {
			defer s.wg.Done()

			s.handle(conn)
		}()
	}
}

func (s *Server) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(connTimeout))

	var req wire.Request
	if err := wire.Read(conn, &req); err != nil {
		return
	}

	_ = wire.Write(conn, s.lookup(req))
}

func (s *Server) lookup(req wire.Request) wire.Response {
	if value, ok := s.secrets[req.Resource][req.SecretKey]; ok {
		return wire.Response{SecretValue: value}
	}

	return wire.Response{Error: fmt.Sprintf("secret %q not found in resource %q", req.SecretKey, req.Resource)}
}

func newTLSServer(tb testing.TB, secrets Secrets, mutual bool) *Server {
	tb.Helper()

	pki, err := GeneratePKI(tb.TempDir())
	if err != nil {
		tb.Fatal(err)
	}

	serverCert, err := tls.LoadX509KeyPair(pki.ServerCertFile, pki.ServerKeyFile)
	if err != nil {
		tb.Fatalf("secretagenttest: load server certificate: %v", err)
	}

	s := &Server{network: "tcp", caFile: pki.CAFile}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}

	if mutual {
		caPEM, readErr := os.ReadFile(pki.CAFile)
		if readErr != nil {
			tb.Fatalf("secretagenttest: read CA: %v", readErr)
		}

		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caPEM)

		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = pool
		s.clientCertFile, s.clientKeyFile = pki.ClientCertFile, pki.ClientKeyFile
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("secretagenttest: listen: %v", err)
	}

	return s.start(tb, tls.NewListener(ln, cfg), secrets)
}
