// Package proxy is a reverse proxy for Vault/OpenBao that answers a LIST on
// a KV folder, which Vault rejected with 403, with the keys the token's
// policies name below that folder.
package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Jwrede/vault-kv-reach/internal/reach"
)

// Config for the proxy.
type Config struct {
	Upstream *url.URL
	// HTTP is used for the proxy's own API calls (mounts, ACL, capabilities).
	HTTP *http.Client
	// Transport is used for proxied requests; nil means http.DefaultTransport.
	Transport http.RoundTripper
	CacheTTL  time.Duration
	Logger    *log.Logger
}

type cached struct {
	at     time.Time
	mounts []reach.Mount
	acl    *reach.ACL
}

// Proxy is an http.Handler.
type Proxy struct {
	cfg   Config
	rp    *httputil.ReverseProxy
	mu    sync.Mutex
	cache map[[32]byte]cached

	statsMu sync.Mutex
	stats   map[string]int
}

// New builds a proxy.
func New(cfg Config) *Proxy {
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 10 * time.Second
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	p := &Proxy{cfg: cfg, cache: map[[32]byte]cached{}, stats: map[string]int{}}
	rp := httputil.NewSingleHostReverseProxy(cfg.Upstream)
	orig := rp.Director
	rp.Director = func(r *http.Request) {
		orig(r)
		r.Host = cfg.Upstream.Host
	}
	if cfg.Transport != nil {
		rp.Transport = cfg.Transport
	}
	rp.ModifyResponse = p.modify
	p.rp = rp
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/-/vault-kv-reach/metrics" {
		p.writeMetrics(w)
		return
	}
	p.rp.ServeHTTP(w, r)
}

func (p *Proxy) count(k string) {
	p.statsMu.Lock()
	p.stats[k]++
	p.statsMu.Unlock()
}

func (p *Proxy) writeMetrics(w http.ResponseWriter) {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	io.WriteString(w, "# HELP vault_kv_reach_list_total LIST requests answered with 403 by the upstream, by outcome.\n# TYPE vault_kv_reach_list_total counter\n")
	for _, k := range []string{"derived", "unchanged", "error"} {
		io.WriteString(w, "vault_kv_reach_list_total{outcome=\""+k+"\"} "+strconv.Itoa(p.stats[k])+"\n")
	}
}

// IsList reports whether r is a Vault LIST request.
func IsList(r *http.Request) bool {
	if r.Method == "LIST" {
		return true
	}
	if r.Method == http.MethodGet {
		v := r.URL.Query().Get("list")
		return v == "true" || v == "1"
	}
	return false
}

// Token returns the Vault token of a request.
func Token(r *http.Request) string {
	if t := r.Header.Get("X-Vault-Token"); t != "" {
		return t
	}
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		return strings.TrimPrefix(a, "Bearer ")
	}
	return ""
}

func (p *Proxy) state(ctx context.Context, c *reach.Client) ([]reach.Mount, *reach.ACL, error) {
	key := sha256.Sum256([]byte(c.Token + "\x00" + c.Namespace))
	p.mu.Lock()
	e, ok := p.cache[key]
	p.mu.Unlock()
	if ok && time.Since(e.at) < p.cfg.CacheTTL {
		return e.mounts, e.acl, nil
	}
	mounts, err := c.KVMounts(ctx)
	if err != nil {
		return nil, nil, err
	}
	acl, err := c.ResultantACL(ctx)
	if err != nil {
		return nil, nil, err
	}
	p.mu.Lock()
	for k, v := range p.cache {
		if time.Since(v.at) >= p.cfg.CacheTTL {
			delete(p.cache, k)
		}
	}
	p.cache[key] = cached{at: time.Now(), mounts: mounts, acl: acl}
	p.mu.Unlock()
	return mounts, acl, nil
}

// folderOf maps an API path to a KV mount and a mount-relative folder that
// a LIST would enumerate.
func folderOf(mounts []reach.Mount, apiPath string) (reach.Mount, string, bool) {
	m, ok := reach.MountFor(mounts, apiPath)
	if !ok {
		return m, "", false
	}
	rest := strings.TrimPrefix(apiPath, m.Path)
	if apiPath+"/" == m.Path {
		rest = ""
	}
	if m.Version == 2 {
		if !strings.HasPrefix(rest, "metadata/") && rest != "metadata" {
			return m, "", false
		}
		rest = strings.TrimPrefix(strings.TrimPrefix(rest, "metadata"), "/")
	}
	if rest != "" && !strings.HasSuffix(rest, "/") {
		rest += "/"
	}
	return m, rest, true
}

func (p *Proxy) modify(resp *http.Response) error {
	r := resp.Request
	if resp.StatusCode != http.StatusForbidden || !IsList(r) || !strings.HasPrefix(r.URL.Path, "/v1/") {
		return nil
	}
	tok := Token(r)
	if tok == "" {
		return nil
	}
	c := &reach.Client{Addr: p.cfg.Upstream.String(), Token: tok, Namespace: r.Header.Get("X-Vault-Namespace"), HTTP: p.cfg.HTTP}
	ctx := r.Context()
	mounts, acl, err := p.state(ctx, c)
	if err != nil {
		// Invalid or expired tokens end up here; keep Vault's answer.
		p.count("error")
		return nil
	}
	apiPath := strings.TrimPrefix(r.URL.Path, "/v1/")
	m, folder, ok := folderOf(mounts, apiPath)
	if !ok {
		p.count("unchanged")
		return nil
	}
	l, err := reach.Derive(ctx, c, acl, m, folder)
	if err != nil {
		p.cfg.Logger.Printf("derive %s: %v", apiPath, err)
		p.count("error")
		return nil
	}
	if len(l.Keys) == 0 {
		p.count("unchanged")
		return nil
	}
	body, _ := json.Marshal(map[string]any{
		"request_id":     resp.Header.Get("X-Vault-Request-Id"),
		"lease_id":       "",
		"renewable":      false,
		"lease_duration": 0,
		"data":           map[string]any{"keys": l.Keys},
		"wrap_info":      nil,
		"warnings":       nil,
		"auth":           nil,
		"mount_type":     "kv",
	})
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.StatusCode = http.StatusOK
	resp.Status = "200 OK"
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Del("Content-Encoding")
	resp.Header.Set("X-Vault-Kv-Reach", "derived")
	p.count("derived")
	return nil
}
