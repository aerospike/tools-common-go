//go:build e2e

package secretagent_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	docker "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/require"

	"github.com/aerospike/tools-common-go/secretagent"
	"github.com/aerospike/tools-common-go/secretagent/secretagenttest"
)

const (
	defaultAgentImage = "aerospike/aerospike-secret-agent:1.1.0"
	agentPlatform     = "linux/amd64"
	agentPort         = nat.Port("3005/tcp")
	agentDir          = "/agent"
	agentReadyLine    = "Started TCP listener"
	agentStartTimeout = 2 * time.Minute
	e2eTimeout        = 10 * time.Second

	otherValue   = "other-value"
	pemValue     = "-----BEGIN TEST-----\nAQIDBA==\n-----END TEST-----\n"
	unicodeValue = "pässwörd ✓"
)

var e2e struct {
	pki       secretagenttest.PKI
	plainAddr string
	tlsAddr   string
	mtlsAddr  string
}

type agentSpec struct {
	addr      *string
	name      string
	tls       string
	clientTLS secretagent.TLSOptions
}

func TestMain(m *testing.M) {
	os.Exit(runE2E(m))
}

func runE2E(m *testing.M) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli, err := docker.NewClientWithOpts(docker.FromEnv, docker.WithAPIVersionNegotiation())
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: docker client:", err)
		return 1
	}

	defer func() { _ = cli.Close() }()

	dir, err := os.MkdirTemp("", "secretagent-e2e")
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e:", err)
		return 1
	}

	defer func() { _ = os.RemoveAll(dir) }()

	// Docker Desktop shares host paths by their real location.
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		fmt.Fprintln(os.Stderr, "e2e:", err)
		return 1
	}

	ids, err := startAgents(ctx, cli, dir)

	defer func() {
		for _, id := range ids {
			_ = cli.ContainerRemove(context.Background(), id, container.RemoveOptions{Force: true})
		}
	}()

	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e:", err)
		return 1
	}

	return m.Run()
}

func startAgents(ctx context.Context, cli *docker.Client, dir string) ([]string, error) {
	agentImage := os.Getenv("SECRET_AGENT_IMAGE")
	if agentImage == "" {
		agentImage = defaultAgentImage
	}

	if err := ensureImage(ctx, cli, agentImage); err != nil {
		return nil, err
	}

	pki, err := secretagenttest.GeneratePKI(dir)
	if err != nil {
		return nil, err
	}

	e2e.pki = pki

	if err := writeSecrets(dir); err != nil {
		return nil, err
	}

	serverTLS := fmt.Sprintf("    tls:\n      cert-file: %q\n      key-file: %q\n",
		inAgent(pki.ServerCertFile), inAgent(pki.ServerKeyFile))
	specs := []agentSpec{
		{name: "plain", addr: &e2e.plainAddr},
		{
			name:      "tls",
			addr:      &e2e.tlsAddr,
			tls:       serverTLS,
			clientTLS: secretagent.TLSOptions{CAFile: pki.CAFile},
		},
		{
			name:      "mtls",
			addr:      &e2e.mtlsAddr,
			tls:       serverTLS + fmt.Sprintf("      ca-file: %q\n", inAgent(pki.CAFile)),
			clientTLS: secretagent.TLSOptions{CAFile: pki.CAFile, CertFile: pki.ClientCertFile, KeyFile: pki.ClientKeyFile},
		},
	}

	for i := range specs {
		if err := writeAgentConfig(dir, &specs[i]); err != nil {
			return nil, err
		}
	}

	if err := shareWithAgent(dir); err != nil {
		return nil, err
	}

	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		ids  []string
		errs []error
	)

	for i := range specs {
		spec := &specs[i]

		wg.Add(1)

		go func() {
			defer wg.Done()

			id, addr, startErr := startAgent(ctx, cli, agentImage, dir, spec)

			mu.Lock()
			defer mu.Unlock()

			if id != "" {
				ids = append(ids, id)
			}

			if startErr != nil {
				errs = append(errs, fmt.Errorf("%s agent: %w", spec.name, startErr))
				return
			}

			*spec.addr = addr
		}()
	}

	wg.Wait()

	return ids, errors.Join(errs...)
}

func ensureImage(ctx context.Context, cli *docker.Client, ref string) error {
	if _, err := cli.ImageInspect(ctx, ref); err == nil {
		return nil
	}

	var err error

	for attempt := 1; attempt <= 3; attempt++ {
		if err = pullImage(ctx, cli, ref); err == nil {
			return nil
		}

		select {
		case <-ctx.Done():
			return err
		case <-time.After(time.Duration(attempt) * 5 * time.Second):
		}
	}

	return err
}

func pullImage(ctx context.Context, cli *docker.Client, ref string) error {
	rc, err := cli.ImagePull(ctx, ref, image.PullOptions{Platform: agentPlatform})
	if err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}

	defer func() { _ = rc.Close() }()

	if _, err = io.Copy(io.Discard, rc); err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}

	return nil
}

func writeSecrets(dir string) error {
	files := map[string]map[string]string{
		"aql.json":   {passwordKey: testSecret, "pem": pemValue, "unicode": unicodeValue},
		"other.json": {passwordKey: otherValue},
	}

	for name, secrets := range files {
		data, err := json.Marshal(secrets)
		if err != nil {
			return err
		}

		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return err
		}
	}

	return nil
}

func writeAgentConfig(dir string, spec *agentSpec) error {
	config := "service:\n  tcp:\n    endpoint: 0.0.0.0:3005\n" + spec.tls +
		"secret-manager:\n  file:\n    convert-to-base64: true\n    resources:\n" +
		"      aql: \"/agent/aql.json\"\n      other: \"/agent/other.json\"\n" +
		"log:\n  level: debug\n"

	return os.WriteFile(filepath.Join(dir, spec.name+".yaml"), []byte(config), 0o600)
}

// shareWithAgent makes the flat dir readable by the container user, whatever
// uid it is mapped to. Everything in dir is throwaway test material.
func shareWithAgent(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if err := os.Chmod(filepath.Join(dir, entry.Name()), 0o644); err != nil {
			return err
		}
	}

	return os.Chmod(dir, 0o755)
}

func startAgent(
	ctx context.Context, cli *docker.Client, agentImage, dir string, spec *agentSpec,
) (id, addr string, err error) {
	configFile := spec.name + ".yaml"

	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)

	created, err := cli.ContainerCreate(ctx,
		&container.Config{
			Image:        agentImage,
			Cmd:          []string{"--config-file", agentDir + "/" + configFile},
			ExposedPorts: nat.PortSet{agentPort: {}},
		},
		&container.HostConfig{
			PortBindings: nat.PortMap{agentPort: {{HostIP: "127.0.0.1"}}},
			Mounts:       []mount.Mount{{Type: mount.TypeBind, Source: dir, Target: agentDir, ReadOnly: true}},
		},
		nil, nil, "secretagent-e2e-"+spec.name+"-"+hex.EncodeToString(suffix))
	if err != nil {
		return "", "", fmt.Errorf("create container: %w", err)
	}

	if err = cli.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {
		return created.ID, "", fmt.Errorf("start container: %w", err)
	}

	if err := waitReady(ctx, cli, created.ID); err != nil {
		return created.ID, "", err
	}

	info, err := cli.ContainerInspect(ctx, created.ID)
	if err != nil {
		return created.ID, "", err
	}

	bindings := info.NetworkSettings.Ports[agentPort]
	if len(bindings) == 0 {
		return created.ID, "", errors.New("agent port is not published")
	}

	addr = "127.0.0.1:" + bindings[0].HostPort

	if err := waitServing(ctx, addr, spec.clientTLS); err != nil {
		return created.ID, "", err
	}

	return created.ID, addr, nil
}

// waitServing polls until the agent returns a known secret. The agent logs
// that it is listening before its file backend has loaded, so the log line
// alone is not enough.
func waitServing(ctx context.Context, addr string, opts secretagent.TLSOptions) error {
	tlsConfig, err := secretagent.NewTLSConfig(opts)
	if err != nil {
		return err
	}

	client, err := secretagent.NewClient(secretagent.Config{
		Address: addr, TLS: tlsConfig, Base64: true, Timeout: e2eTimeout,
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, agentStartTimeout)
	defer cancel()

	for {
		got, err := client.Resolve(ctx, "secrets:aql:password")
		if err == nil && got == testSecret {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("agent at %s never served secrets: %w", addr, err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func waitReady(ctx context.Context, cli *docker.Client, id string) error {
	ctx, cancel := context.WithTimeout(ctx, agentStartTimeout)
	defer cancel()

	for {
		logs, err := agentLogs(ctx, cli, id)
		if err == nil && strings.Contains(logs, agentReadyLine) {
			return nil
		}

		info, inspectErr := cli.ContainerInspect(ctx, id)
		if inspectErr == nil && !info.State.Running {
			return fmt.Errorf("agent exited with code %d:\n%s", info.State.ExitCode, logs)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("agent not ready: %w:\n%s", ctx.Err(), logs)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func agentLogs(ctx context.Context, cli *docker.Client, id string) (string, error) {
	rc, err := cli.ContainerLogs(ctx, id, container.LogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {
		return "", err
	}

	defer func() { _ = rc.Close() }()

	var out bytes.Buffer

	_, err = stdcopy.StdCopy(&out, &out, rc)

	return out.String(), err
}

func inAgent(hostPath string) string {
	return agentDir + "/" + filepath.Base(hostPath)
}

func e2eClient(t *testing.T, addr string, opts secretagent.TLSOptions, decode bool) *secretagent.Client {
	t.Helper()

	tlsConfig, err := secretagent.NewTLSConfig(opts)
	require.NoError(t, err)

	return newClient(t, secretagent.Config{Address: addr, TLS: tlsConfig, Base64: decode, Timeout: e2eTimeout})
}

func TestE2EResolve(t *testing.T) {
	t.Parallel()

	client := e2eClient(t, e2e.plainAddr, secretagent.TLSOptions{}, true)

	tests := map[string]string{
		"secrets:aql:password":   testSecret,
		"secrets:other:password": otherValue,
		"secrets:aql:pem":        pemValue,
		"secrets:aql:unicode":    unicodeValue,
		literal:                  literal,
	}

	for value, want := range tests {
		t.Run(value, func(t *testing.T) {
			t.Parallel()

			got, err := client.Resolve(t.Context(), value)
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}

func TestE2EGetSecret(t *testing.T) {
	t.Parallel()

	client := e2eClient(t, e2e.plainAddr, secretagent.TLSOptions{}, true)

	got, err := client.GetSecret(t.Context(), "aql", passwordKey)
	require.NoError(t, err)
	require.Equal(t, testSecret, got)
}

func TestE2ERawValue(t *testing.T) {
	t.Parallel()

	client := e2eClient(t, e2e.plainAddr, secretagent.TLSOptions{}, false)

	got, err := client.Resolve(t.Context(), "secrets:aql:password")
	require.NoError(t, err)
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte(testSecret)), got)
}

func TestE2EAgentErrors(t *testing.T) {
	t.Parallel()

	client := e2eClient(t, e2e.plainAddr, secretagent.TLSOptions{}, true)

	tests := map[string]string{
		"secrets:aql:missing":   "not present",
		"secrets:none:password": "resource not found",
		"secrets:password":      "multiple resources",
	}

	for ref, agentMessage := range tests {
		t.Run(ref, func(t *testing.T) {
			t.Parallel()

			_, err := client.Resolve(t.Context(), ref)
			requireClass(t, err, secretagent.ErrRequestFailed)
			require.ErrorContains(t, err, ref)
			require.ErrorContains(t, err, agentMessage)
			require.NotContains(t, err.Error(), testSecret)
		})
	}
}

func TestE2ETLS(t *testing.T) {
	t.Parallel()

	untrusted, err := secretagenttest.GeneratePKI(t.TempDir())
	require.NoError(t, err)

	ca := e2e.pki.CAFile

	tests := map[string]struct {
		addr string
		opts secretagent.TLSOptions
		ok   bool
	}{
		"CA": {addr: e2e.tlsAddr, opts: secretagent.TLSOptions{CAFile: ca}, ok: true},
		"server name": {
			addr: e2e.tlsAddr, opts: secretagent.TLSOptions{CAFile: ca, ServerName: serverName}, ok: true,
		},
		"TLS 1.3": {
			addr: e2e.tlsAddr, opts: secretagent.TLSOptions{CAFile: ca, MinVersion: tls.VersionTLS13}, ok: true,
		},
		"wrong server name": {
			addr: e2e.tlsAddr, opts: secretagent.TLSOptions{CAFile: ca, ServerName: "agent.example.com"},
		},
		"untrusted CA":           {addr: e2e.tlsAddr, opts: secretagent.TLSOptions{CAFile: untrusted.CAFile}},
		"plaintext to TLS agent": {addr: e2e.tlsAddr},
		"TLS to plaintext agent": {addr: e2e.plainAddr, opts: secretagent.TLSOptions{CAFile: ca}},
		"client cert, not needed": {
			addr: e2e.tlsAddr,
			opts: secretagent.TLSOptions{CAFile: ca, CertFile: e2e.pki.ClientCertFile, KeyFile: e2e.pki.ClientKeyFile},
			ok:   true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := e2eClient(t, tt.addr, tt.opts, true).Resolve(t.Context(), "secrets:aql:password")
			if !tt.ok {
				requireClass(t, err, secretagent.ErrRequestFailed)
				return
			}

			require.NoError(t, err)
			require.Equal(t, testSecret, got)
		})
	}
}

func TestE2EMutualTLS(t *testing.T) {
	t.Parallel()

	untrusted, err := secretagenttest.GeneratePKI(t.TempDir())
	require.NoError(t, err)

	pki := e2e.pki

	tests := map[string]struct {
		opts secretagent.TLSOptions
		ok   bool
	}{
		"client cert": {
			opts: secretagent.TLSOptions{CAFile: pki.CAFile, CertFile: pki.ClientCertFile, KeyFile: pki.ClientKeyFile},
			ok:   true,
		},
		"no client cert": {
			opts: secretagent.TLSOptions{CAFile: pki.CAFile},
		},
		"client cert from untrusted CA": {
			opts: secretagent.TLSOptions{
				CAFile: pki.CAFile, CertFile: untrusted.ClientCertFile, KeyFile: untrusted.ClientKeyFile,
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := e2eClient(t, e2e.mtlsAddr, tt.opts, true).Resolve(t.Context(), "secrets:aql:password")
			if !tt.ok {
				requireClass(t, err, secretagent.ErrRequestFailed)
				return
			}

			require.NoError(t, err)
			require.Equal(t, testSecret, got)
		})
	}
}

func TestE2EConcurrent(t *testing.T) {
	t.Parallel()

	client := e2eClient(t, e2e.mtlsAddr, secretagent.TLSOptions{
		CAFile:   e2e.pki.CAFile,
		CertFile: e2e.pki.ClientCertFile,
		KeyFile:  e2e.pki.ClientKeyFile,
	}, true)

	var wg sync.WaitGroup

	errs := make(chan error, 50)

	for range cap(errs) {
		wg.Add(1)

		go func() {
			defer wg.Done()

			got, err := client.Resolve(t.Context(), "secrets:aql:password")
			if err == nil && got != testSecret {
				err = errors.New("unexpected secret value")
			}

			errs <- err
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
}
