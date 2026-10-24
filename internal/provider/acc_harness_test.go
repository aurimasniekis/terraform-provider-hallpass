package provider

// Acceptance test harness: when TF_ACC is set, TestMain starts a real `hallpass serve` in development mode (free ports,
// temporary data directory), completes the first-administrator setup with TOTP, issues an API token and points the
// provider at it. It also runs a small SSH server on loopback that stands in for a destination (and a git host) so
// login keys can be test-logged-in and activated.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // TOTP (RFC 6238) is defined over HMAC-SHA1
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

// accEnv describes the HallPass instance the acceptance tests run against.
type accEnv struct {
	Endpoint   string // public URL (http://127.0.0.1:PORT)
	Token      string // API token with the administrator role
	AdminEmail string
	// DestHost and DestPort are the loopback SSH server; DestHostKey is its host key (authorized_keys format).
	DestHost    string
	DestPort    int
	DestHostKey string
	logDir      string
}

var acc *accEnv

var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"hallpass": providerserver.NewProtocol6WithError(New("test")()),
}

func TestMain(m *testing.M) {
	// Use a locally installed Terraform CLI so nothing is downloaded.
	if os.Getenv("TF_ACC_TERRAFORM_PATH") == "" {
		if p, err := exec.LookPath("terraform"); err == nil {
			_ = os.Setenv("TF_ACC_TERRAFORM_PATH", p)
		}
	}
	_ = os.Setenv("CHECKPOINT_DISABLE", "1")
	if os.Getenv("TF_ACC") == "" {
		os.Exit(m.Run())
	}
	env, stop, err := startHallPass()
	if err != nil {
		fmt.Fprintln(os.Stderr, "acceptance harness:", err)
		stop()
		os.Exit(1)
	}
	acc = env
	_ = os.Setenv(EnvEndpoint, env.Endpoint)
	_ = os.Setenv(EnvToken, env.Token)
	code := m.Run()
	if code != 0 {
		dumpLog(filepath.Join(env.logDir, "hallpass.log"))
	}
	stop()
	os.Exit(code)
}

func dumpLog(p string) {
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	if len(b) > 8000 {
		b = b[len(b)-8000:]
	}
	fmt.Fprintf(os.Stderr, "--- tail of %s\n%s\n", p, b)
}

func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// startHallPass launches HallPass and the loopback SSH destination, and returns the environment and a stop function.
func startHallPass() (*accEnv, func(), error) {
	var procs []*exec.Cmd
	var closers []io.Closer
	work, err := os.MkdirTemp("", "hallpass-tfacc-")
	stop := func() {
		for _, p := range procs {
			if p.Process != nil {
				_ = p.Process.Kill()
				_, _ = p.Process.Wait()
			}
		}
		for _, c := range closers {
			_ = c.Close()
		}
		if work != "" && os.Getenv("HALLPASS_ACC_KEEP") == "" {
			_ = os.RemoveAll(work)
		}
	}
	if err != nil {
		return nil, stop, err
	}
	if err := os.Chmod(work, 0o700); err != nil {
		return nil, stop, err
	}
	bin := os.Getenv("HALLPASS_BINARY")
	if bin == "" {
		bin = filepath.Join(repoRoot(), "bin", "hallpass")
	}
	if _, err := os.Stat(bin); err != nil {
		return nil, stop, fmt.Errorf("hallpass binary not found at %s (run `make hallpass-bin` or set HALLPASS_BINARY)", bin)
	}
	httpPort, err := freePort()
	if err != nil {
		return nil, stop, err
	}
	sshPort, err := freePort()
	if err != nil {
		return nil, stop, err
	}
	origin := fmt.Sprintf("http://127.0.0.1:%d", httpPort)
	cfgPath := filepath.Join(work, "hallpass.yaml")
	cfg := fmt.Sprintf(`mode: development
data_dir: %s
public_url: %s
kek:
  file: ""
ssh:
  listen: "127.0.0.1:%d"
http:
  listen: "127.0.0.1:%d"
log:
  level: warn
  format: text
egress:
  allow_cidrs: [127.0.0.0/8]
  allow_special_cidrs: [127.0.0.1/32]
`, filepath.Join(work, "data"), origin, sshPort, httpPort)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		return nil, stop, err
	}
	// HallPass refuses unknown HALLPASS_* environment variables (the provider's own included).
	childEnv := []string{}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "HALLPASS_") {
			childEnv = append(childEnv, kv)
		}
	}
	run := func(args ...string) (string, error) {
		cmd := exec.Command(bin, args...) //nolint:gosec // test binary
		cmd.Env = childEnv
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := run("migrate", "--config", cfgPath); err != nil {
		return nil, stop, fmt.Errorf("migrate: %w: %s", err, out)
	}
	out, err := run("admin", "bootstrap", "--config", cfgPath)
	if err != nil {
		return nil, stop, fmt.Errorf("bootstrap token: %w: %s", err, out)
	}
	m := regexp.MustCompile(`token: (\S+)`).FindStringSubmatch(out)
	if m == nil {
		return nil, stop, errors.New("admin bootstrap printed no token")
	}
	setupToken := m[1]
	logf, err := os.Create(filepath.Join(work, "hallpass.log"))
	if err != nil {
		return nil, stop, err
	}
	srv := exec.Command(bin, "serve", "--config", cfgPath) //nolint:gosec // test binary
	srv.Stdout, srv.Stderr, srv.Env = logf, logf, childEnv
	if err := srv.Start(); err != nil {
		return nil, stop, err
	}
	procs = append(procs, srv)
	ready := false
	for range 150 {
		resp, err := http.Get(origin + "/readyz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		dumpLog(filepath.Join(work, "hallpass.log"))
		return nil, stop, errors.New("hallpass did not become ready")
	}

	env := &accEnv{Endpoint: origin, AdminEmail: "ada@example.com", logDir: work}
	if env.Token, err = firstAdminToken(origin, setupToken, env.AdminEmail); err != nil {
		return nil, stop, err
	}
	dest, hostKey, err := startDestination()
	if err != nil {
		return nil, stop, err
	}
	closers = append(closers, dest)
	addr := dest.Addr().(*net.TCPAddr)
	env.DestHost, env.DestPort, env.DestHostKey = "127.0.0.1", addr.Port, hostKey
	return env, stop, nil
}

// firstAdminToken runs the first-administrator flow (bootstrap, sign-in, TOTP enrollment, MFA) like a browser and
// issues an administrator API token.
func firstAdminToken(origin, setupToken, email string) (string, error) {
	b := &browser{origin: origin, cookies: map[string]string{}}
	password := "acc-" + randomString(24)
	if err := b.json(http.MethodPost, "/api/v1/auth/bootstrap", map[string]string{"token": setupToken, "email": email,
		"display_name": "Ada Lovelace", "password": password}, nil); err != nil {
		return "", fmt.Errorf("bootstrap: %w", err)
	}
	var login struct {
		Me struct {
			CSRF string `json:"csrf_token"`
		} `json:"me"`
	}
	if err := b.json(http.MethodPost, "/api/v1/auth/login", map[string]string{"email": email, "password": password}, &login); err != nil {
		return "", fmt.Errorf("login: %w", err)
	}
	b.csrf = login.Me.CSRF
	var enroll struct {
		Secret string `json:"secret"`
	}
	if err := b.json(http.MethodPost, "/api/v1/me/mfa/totp", nil, &enroll); err != nil {
		return "", fmt.Errorf("begin TOTP: %w", err)
	}
	if err := b.json(http.MethodPost, "/api/v1/me/mfa/totp/confirm", map[string]string{"code": totp(enroll.Secret, time.Now())}, nil); err != nil {
		return "", fmt.Errorf("confirm TOTP: %w", err)
	}
	// A TOTP step can be used once: wait for the next one.
	time.Sleep(time.Duration(31-time.Now().Unix()%30) * time.Second)
	var me struct {
		CSRF string `json:"csrf_token"`
	}
	if err := b.json(http.MethodPost, "/api/v1/auth/mfa", map[string]string{"code": totp(enroll.Secret, time.Now())}, &me); err != nil {
		return "", fmt.Errorf("MFA: %w", err)
	}
	b.csrf = me.CSRF
	var tok struct {
		Token string `json:"token"`
	}
	if err := b.json(http.MethodPost, "/api/v1/api-tokens", map[string]any{"name": "tf-acc", "role": "administrator", "expires_in_days": 1}, &tok); err != nil {
		return "", fmt.Errorf("API token: %w", err)
	}
	return tok.Token, nil
}

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))[:n]
}

// totp computes an RFC 6238 code (SHA-1, 30 s, 6 digits).
func totp(secretB32 string, now time.Time) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(secretB32, "=")))
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(now.Unix()/30)) //nolint:gosec // positive
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1_000_000)
}

// startDestination runs an SSH server that accepts any public key and immediately ends sessions: enough for HallPass
// to verify the pinned host key and test a login key.
func startDestination() (net.Listener, string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, "", err
	}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					_ = ch.Reject(ssh.Prohibited, "test destination")
				}
			}()
		}
	}()
	return l, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}

// browser is a minimal cookie-aware client for the first-run flow (cookies are tracked by hand).
type browser struct {
	origin  string
	csrf    string
	cookies map[string]string
}

func (b *browser) json(method, p string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, b.origin+p, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", b.origin)
	if b.csrf != "" {
		req.Header.Set("X-CSRF-Token", b.csrf)
	}
	var cs []string
	for k, v := range b.cookies {
		cs = append(cs, k+"="+v)
	}
	if len(cs) > 0 {
		req.Header.Set("Cookie", strings.Join(cs, "; "))
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c.Value
		}
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %d %s", method, p, resp.StatusCode, data)
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// testAccPreCheck guards acceptance tests.
func testAccPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance tests need TF_ACC=1")
	}
	if acc == nil {
		t.Fatal("acceptance environment not initialised (TF_ACC must be set)")
	}
}

// apiClient is an out-of-band API client for drift and destroy checks.
func apiClient(t *testing.T) *client.Client {
	t.Helper()
	c, err := client.New(client.Config{Endpoint: acc.Endpoint, Token: acc.Token, UserAgent: "tfacc-oob"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
