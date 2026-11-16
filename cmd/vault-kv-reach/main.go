// Command vault-kv-reach shows which KV secrets a Vault or OpenBao token can
// reach, and runs a proxy that lets LIST on KV folders return the paths a
// token's policies grant even when the token may not list the parent.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Jwrede/vault-kv-reach/internal/proxy"
	"github.com/Jwrede/vault-kv-reach/internal/reach"
)

var version = "dev"

const usage = `vault-kv-reach: KV paths a Vault/OpenBao token can reach

Usage:
  vault-kv-reach tree [flags] [mount/prefix]
  vault-kv-reach proxy -listen 127.0.0.1:8201 -upstream https://vault:8200
  vault-kv-reach version

Environment: VAULT_ADDR (or BAO_ADDR), VAULT_TOKEN (or BAO_TOKEN),
VAULT_NAMESPACE, VAULT_SKIP_VERIFY. The token is read from ~/.vault-token
if no variable is set.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "tree":
		os.Exit(runTree(os.Args[2:]))
	case "proxy":
		os.Exit(runProxy(os.Args[2:]))
	case "version", "--version":
		fmt.Println(version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

func env(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

func httpClient(insecure bool) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: tr}
}

func defaultToken() string {
	if t := env("VAULT_TOKEN", "BAO_TOKEN"); t != "" {
		return t
	}
	home, _ := os.UserHomeDir()
	for _, f := range []string{".vault-token", ".bao-token"} {
		if b, err := os.ReadFile(home + "/" + f); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

func runTree(args []string) int {
	fs := flag.NewFlagSet("tree", flag.ExitOnError)
	addr := fs.String("addr", env("VAULT_ADDR", "BAO_ADDR"), "Vault address")
	ns := fs.String("namespace", env("VAULT_NAMESPACE", "BAO_NAMESPACE"), "namespace")
	asJSON := fs.Bool("json", false, "print JSON lines")
	depth := fs.Int("depth", 0, "maximum folder depth (0 = unlimited)")
	maxEntries := fs.Int("max", 10000, "stop after this many entries (0 = unlimited)")
	insecure := fs.Bool("insecure", env("VAULT_SKIP_VERIFY") != "", "skip TLS verification")
	fs.Parse(args)
	if *addr == "" {
		*addr = "http://127.0.0.1:8200"
	}
	c := &reach.Client{Addr: *addr, Token: defaultToken(), Namespace: *ns, HTTP: httpClient(*insecure)}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	mounts, err := c.KVMounts(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	acl, err := c.ResultantACL(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	prefix := fs.Arg(0)
	if prefix != "" {
		m, ok := reach.MountFor(mounts, prefix)
		if !ok {
			fmt.Fprintf(os.Stderr, "error: %s is not in a KV mount this token can see\n", prefix)
			return 1
		}
		mounts = []reach.Mount{m}
	}
	es, err := reach.Walk(ctx, c, acl, mounts, prefix, reach.WalkOptions{MaxDepth: *depth, MaxEntries: *maxEntries})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		for _, e := range es {
			enc.Encode(e)
		}
	} else {
		reach.PrintTree(os.Stdout, mounts, es)
	}
	if *maxEntries > 0 && len(es) >= *maxEntries {
		fmt.Fprintf(os.Stderr, "stopped after %d entries (-max)\n", *maxEntries)
	}
	return 0
}

func runProxy(args []string) int {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8201", "listen address")
	upstream := fs.String("upstream", env("VAULT_ADDR", "BAO_ADDR"), "Vault address")
	certFile := fs.String("tls-cert", "", "TLS certificate for the listener")
	keyFile := fs.String("tls-key", "", "TLS key for the listener")
	insecure := fs.Bool("insecure", env("VAULT_SKIP_VERIFY") != "", "skip TLS verification towards the upstream")
	ttl := fs.Duration("cache-ttl", 10*time.Second, "how long mounts and ACL of a token are cached")
	fs.Parse(args)
	if *upstream == "" {
		fmt.Fprintln(os.Stderr, "error: -upstream or VAULT_ADDR is required")
		return 2
	}
	u, err := url.Parse(*upstream)
	if err != nil || u.Host == "" {
		fmt.Fprintf(os.Stderr, "error: bad upstream %q\n", *upstream)
		return 2
	}
	hc := httpClient(*insecure)
	p := proxy.New(proxy.Config{Upstream: u, HTTP: hc, Transport: hc.Transport, CacheTTL: *ttl})
	srv := &http.Server{Addr: *listen, Handler: p, ReadHeaderTimeout: 30 * time.Second}
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()
	log.Printf("vault-kv-reach %s proxy on %s -> %s", version, *listen, u)
	if *certFile != "" {
		err = srv.ListenAndServeTLS(*certFile, *keyFile)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Print(err)
		return 1
	}
	return 0
}
