package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

type Config struct {
	ListenAddr              string
	CLIUpstreamAddr         string
	AntigravityUpstreamAddr string
	Fingerprint             string
	DomainAllowlist         []string
	DisableProxyBypass      bool
	DialTimeout             time.Duration
	RequestTimeout          time.Duration
	DisableHTTP2Pooling     bool
}

type Server struct {
	cfg            Config
	server         *http.Server
	transport      *smartTransport
	cliUpstream    *url.URL
	agUpstreams    []*url.URL
}

func New(cfg Config) (*Server, error) {
	if strings.TrimSpace(cfg.ListenAddr) == "" {
		cfg.ListenAddr = "127.0.0.1:9813"
	}
	if strings.TrimSpace(cfg.CLIUpstreamAddr) == "" {
		cfg.CLIUpstreamAddr = "http://127.0.0.1:9317"
	}
	if strings.TrimSpace(cfg.AntigravityUpstreamAddr) == "" {
		cfg.AntigravityUpstreamAddr = "https://daily-cloudcode-pa.googleapis.com"
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 15 * time.Second
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 90 * time.Second
	}

	cliUpstreamURL, err := url.Parse(cfg.CLIUpstreamAddr)
	if err != nil {
		return nil, err
	}
	if cliUpstreamURL.Scheme == "" {
		cliUpstreamURL.Scheme = "http"
	}

	agUpstreamURLs, err := parseUpstreamList(cfg.AntigravityUpstreamAddr)
	if err != nil {
		return nil, err
	}

	fingerprint := strings.ToLower(strings.TrimSpace(cfg.Fingerprint))
	if fingerprint == "" {
		fingerprint = "chrome"
	}

	tr, err := newSmartTransport(cfg, fingerprint, cfg.DomainAllowlist)
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:       cfg,
		transport: tr,
		cliUpstream: cliUpstreamURL,
		agUpstreams: agUpstreamURLs,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/", s.handleProxy)

	s.server = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
	}

	return s, nil
}

func (s *Server) Start() error {
	if s == nil || s.server == nil {
		return errors.New("server not initialized")
	}
	err := s.server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	agList := make([]string, 0, len(s.agUpstreams))
	for _, item := range s.agUpstreams {
		agList = append(agList, item.String())
	}
	payload := fmt.Sprintf(`{"ok":true,"cli_upstream":"%s","antigravity_upstreams":"%s"}`, s.cliUpstream.String(), strings.Join(agList, ","))
	_, _ = w.Write([]byte(payload))
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.RequestTimeout)
	defer cancel()
	isAGPath := isAntigravityInternalPath(r.URL.Path)
	if isAGPath {
		s.proxyAntigravity(w, r, ctx)
		return
	}
	s.proxySingleUpstream(w, r, ctx, s.cliUpstream, false)
}

func (s *Server) proxyAntigravity(w http.ResponseWriter, r *http.Request, ctx context.Context) {
	if len(s.agUpstreams) == 0 {
		http.Error(w, "no antigravity upstream configured", http.StatusBadGateway)
		return
	}
	client := &http.Client{Transport: s.transport}
	for idx, target := range s.agUpstreams {
		proxyReq, err := s.buildProxyRequest(ctx, r, target, true)
		if err != nil {
			http.Error(w, "failed to build proxy request: "+err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := client.Do(proxyReq)
		if err != nil {
			if idx+1 < len(s.agUpstreams) {
				log.Printf("antigravity upstream failed: %s err=%v, fallback => %s", target.String(), err, s.agUpstreams[idx+1].String())
				continue
			}
			http.Error(w, "upstream request failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		if idx+1 < len(s.agUpstreams) && shouldRetryAntigravityStatus(resp.StatusCode) {
			_ = resp.Body.Close()
			log.Printf("antigravity upstream status=%d on %s, fallback => %s", resp.StatusCode, target.String(), s.agUpstreams[idx+1].String())
			continue
		}
		defer resp.Body.Close()
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}
	http.Error(w, "all antigravity upstreams failed", http.StatusBadGateway)
}

func (s *Server) proxySingleUpstream(w http.ResponseWriter, r *http.Request, ctx context.Context, target *url.URL, isAntigravityPath bool) {
	proxyReq, err := s.buildProxyRequest(ctx, r, target, isAntigravityPath)
	if err != nil {
		http.Error(w, "failed to build proxy request: "+err.Error(), http.StatusBadRequest)
		return
	}
	client := &http.Client{Transport: s.transport}
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, "upstream request failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) buildProxyRequest(ctx context.Context, r *http.Request, target *url.URL, isAntigravityPath bool) (*http.Request, error) {
	if r == nil {
		return nil, errors.New("request is nil")
	}
	if target == nil {
		return nil, errors.New("upstream target is nil")
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if r.Body != nil {
		_ = r.Body.Close()
	}

	newURL := *target
	newURL.Path = r.URL.Path
	newURL.RawPath = r.URL.RawPath
	newURL.RawQuery = r.URL.RawQuery

	proxyReq, err := http.NewRequestWithContext(ctx, r.Method, newURL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	proxyReq.Header = cloneHeader(r.Header)
	proxyReq.Host = target.Host

	if isAntigravityPath {
		proxyReq.Header = sanitizeAntigravityHeaders(proxyReq.Header, r.URL.Path)
	}

	return proxyReq, nil
}

func sanitizeAntigravityHeaders(src http.Header, path string) http.Header {
	out := make(http.Header)
	if authz := strings.TrimSpace(src.Get("Authorization")); authz != "" {
		out.Set("Authorization", authz)
	}
	if ct := strings.TrimSpace(src.Get("Content-Type")); ct != "" {
		out.Set("Content-Type", ct)
	} else {
		out.Set("Content-Type", "application/json")
	}
	if accept := strings.TrimSpace(src.Get("Accept")); accept != "" {
		out.Set("Accept", accept)
	} else if strings.Contains(strings.ToLower(strings.TrimSpace(path)), ":streamgeneratecontent") {
		out.Set("Accept", "text/event-stream")
	} else {
		out.Set("Accept", "application/json")
	}
	out.Set("User-Agent", "antigravity")
	return out
}

func shouldRetryAntigravityStatus(code int) bool {
	switch code {
	case http.StatusForbidden,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func parseUpstreamList(raw string) ([]*url.URL, error) {
	parts := strings.Split(strings.TrimSpace(raw), ",")
	out := make([]*url.URL, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		u, err := url.Parse(item)
		if err != nil {
			return nil, err
		}
		if u.Scheme == "" {
			u.Scheme = "https"
		}
		key := strings.ToLower(strings.TrimSpace(u.String()))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, u)
	}
	if len(out) == 0 {
		for _, item := range []string{
			"https://daily-cloudcode-pa.googleapis.com",
			"https://daily-cloudcode-pa.sandbox.googleapis.com",
		} {
			u, _ := url.Parse(item)
			out = append(out, u)
		}
	}
	return out, nil
}

func isAntigravityInternalPath(path string) bool {
	normalized := strings.ToLower(strings.TrimSpace(path))
	return strings.HasPrefix(normalized, "/v1internal")
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, values := range h {
		copied := make([]string, len(values))
		copy(copied, values)
		out[k] = copied
	}
	return out
}

func copyHeader(dst, src http.Header) {
	for k, values := range src {
		for _, v := range values {
			dst.Add(k, v)
		}
	}
}

type smartTransport struct {
	cfg         Config
	proxyDialer proxy.Dialer
	base        *http.Transport
	helloID     utls.ClientHelloID
	allowlist   map[string]struct{}

	mu          sync.Mutex
	connections map[string]*http2.ClientConn
	pending     map[string]*sync.Cond
}

func newSmartTransport(cfg Config, fingerprint string, domains []string) (*smartTransport, error) {
	helloID := utls.HelloChrome_Auto
	if fingerprint == "firefox" {
		helloID = utls.HelloFirefox_Auto
	}
	allowlist := normalizeDomainAllowlist(domains)

	proxyURL := strings.TrimSpace(env("HTTPS_PROXY"))
	if proxyURL == "" {
		proxyURL = strings.TrimSpace(env("HTTP_PROXY"))
	}

	base := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: cfg.DialTimeout}).DialContext,
		TLSHandshakeTimeout: cfg.DialTimeout,
	}

	st := &smartTransport{
		cfg:         cfg,
		base:        base,
		helloID:     helloID,
		allowlist:   allowlist,
		connections: make(map[string]*http2.ClientConn),
		pending:     make(map[string]*sync.Cond),
	}

	if cfg.DisableProxyBypass {
		st.proxyDialer = proxy.Direct
		return st, nil
	}

	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err == nil {
			if d, errDialer := proxy.FromURL(u, proxy.Direct); errDialer == nil {
				st.proxyDialer = d
			}
		}
	}
	if st.proxyDialer == nil {
		st.proxyDialer = proxy.Direct
	}
	return st, nil
}

func (t *smartTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return t.base.RoundTrip(req)
	}
	host := strings.ToLower(req.URL.Hostname())
	if _, ok := t.allowlist[host]; !ok {
		return t.base.RoundTrip(req)
	}
	if t.cfg.DisableHTTP2Pooling {
		return t.roundTripNoPool(req)
	}
	return t.roundTripWithPool(req)
}

func (t *smartTransport) roundTripNoPool(req *http.Request) (*http.Response, error) {
	addr, host := targetAddrAndHost(req)
	conn, err := t.proxyDialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	tlsConn := utls.UClient(conn, &utls.Config{ServerName: host}, t.helloID)
	if err := tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	h2 := &http2.Transport{}
	h2Conn, err := h2.NewClientConn(tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	resp, err := h2Conn.RoundTrip(req)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return resp, nil
}

func (t *smartTransport) roundTripWithPool(req *http.Request) (*http.Response, error) {
	addr, host := targetAddrAndHost(req)

	h2Conn, err := t.getOrCreateConnection(host, addr)
	if err != nil {
		return nil, err
	}

	resp, err := h2Conn.RoundTrip(req)
	if err != nil {
		t.mu.Lock()
		if cached, ok := t.connections[host]; ok && cached == h2Conn {
			delete(t.connections, host)
		}
		t.mu.Unlock()

		h2ConnRetry, errRetry := t.getOrCreateConnection(host, addr)
		if errRetry != nil {
			return nil, err
		}
		return h2ConnRetry.RoundTrip(req)
	}
	return resp, nil
}

func (t *smartTransport) getOrCreateConnection(host, addr string) (*http2.ClientConn, error) {
	t.mu.Lock()
	if h2Conn, ok := t.connections[host]; ok && h2Conn.CanTakeNewRequest() {
		t.mu.Unlock()
		return h2Conn, nil
	}
	if cond, ok := t.pending[host]; ok {
		cond.Wait()
		if h2Conn, ok := t.connections[host]; ok && h2Conn.CanTakeNewRequest() {
			t.mu.Unlock()
			return h2Conn, nil
		}
	}
	cond := sync.NewCond(&t.mu)
	t.pending[host] = cond
	t.mu.Unlock()

	h2Conn, err := t.createConnection(host, addr)

	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.pending, host)
	cond.Broadcast()

	if err == nil {
		t.connections[host] = h2Conn
	}
	return h2Conn, err
}

func (t *smartTransport) createConnection(host, addr string) (*http2.ClientConn, error) {
	conn, err := t.proxyDialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	tlsConn := utls.UClient(conn, &utls.Config{ServerName: host}, t.helloID)
	if err := tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	h2 := &http2.Transport{}
	return h2.NewClientConn(tlsConn)
}

func targetAddrAndHost(req *http.Request) (addr string, host string) {
	host = req.URL.Hostname()
	addr = req.URL.Host
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}
	return addr, host
}

func normalizeDomainAllowlist(domains []string) map[string]struct{} {
	allowlist := make(map[string]struct{}, len(domains))
	for _, item := range domains {
		d := strings.ToLower(strings.TrimSpace(item))
		if d == "" {
			continue
		}
		allowlist[d] = struct{}{}
	}
	if len(allowlist) == 0 {
		for _, item := range []string{
			"cloudcode-pa.googleapis.com",
			"daily-cloudcode-pa.googleapis.com",
			"daily-cloudcode-pa.sandbox.googleapis.com",
		} {
			allowlist[item] = struct{}{}
		}
	}
	return allowlist
}

func env(key string) string {
	v, _ := os.LookupEnv(key)
	return v
}

func (s *Server) String() string {
	if s == nil {
		return "plugin-server<nil>"
	}
	return fmt.Sprintf("plugin-server<listen=%s cli_upstream=%s antigravity_upstream=%s>", s.cfg.ListenAddr, s.cfg.CLIUpstreamAddr, s.cfg.AntigravityUpstreamAddr)
}
