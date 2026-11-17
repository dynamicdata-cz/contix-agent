// Command contix-agent runs the CONTIX agent or concentrator role.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dynamicdata-cz/contix-agent/internal/agent"
	"github.com/dynamicdata-cz/contix-agent/internal/concentrator"
	"github.com/dynamicdata-cz/contix-agent/internal/spool"
)

// version is set at build time via -ldflags "-X main.version=…".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	case "concentrator":
		return concentratorCmd(args[1:], stdout, stderr)
	case "agent":
		return agentCmd(args[1:], stdout, stderr)
	default:
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `usage:
  contix-agent concentrator register --url https://contix.example --code ctxr_… [--ca-file ca.crt] [--listen :8443] [--server-name konc.example] [--force]
  contix-agent concentrator run
  contix-agent concentrator token [--uses 1] [--ttl 24h]
  contix-agent concentrator status
  contix-agent agent enroll --concentrator https://konc.example:8443 --token ctxe_… --ca-fingerprint <sha256> [--force]
  contix-agent agent run
  contix-agent agent status
  contix-agent agent collect        (prints what the agent would send, sends nothing)
  contix-agent version
common flag: --state-dir (concentrator default `+concentrator.DefaultStateDir+`, agent default `+agent.DefaultStateDir+`)`)
}

func concentratorCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	fs := flag.NewFlagSet("concentrator "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", concentrator.DefaultStateDir, "state directory (keys, certificates, queue)")
	url := fs.String("url", "", "CONTIX address, e.g. https://contix.example.cz")
	code := fs.String("code", "", "one-time registration code from CONTIX (ctxr_…)")
	caFile := fs.String("ca-file", "", "extra CA certificate trusted for CONTIX (PEM)")
	listen := fs.String("listen", concentrator.DefaultListen, "address for agents")
	force := fs.Bool("force", false, "register again (new key)")
	serverNames := fs.String("server-name", "", "extra DNS names / IPs agents use to reach this concentrator, comma separated")
	uses := fs.Int("uses", 1, "how many agents may enroll with the token")
	ttl := fs.Duration("ttl", 24*time.Hour, "token validity")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	p := concentrator.Paths{Dir: *stateDir}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fail := func(err error) int {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	switch args[0] {
	case "register":
		if *url == "" || *code == "" {
			fmt.Fprintln(stderr, "error: --url and --code are required")
			return 2
		}
		st, err := concentrator.Register(ctx, p, concentrator.RegisterOptions{URL: *url, Code: *code, CAFile: *caFile, Listen: *listen, Version: version, Force: *force, ServerNames: splitList(*serverNames)})
		if err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "Registered: concentrator %s, zone %q at %s\nStart the service: systemctl enable --now contix-concentrator\n", st.ConcentratorID, st.Zone, st.URL)
		return 0
	case "run":
		log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
		if err := concentrator.Run(ctx, p, version, log); err != nil {
			return fail(err)
		}
		return 0
	case "token":
		st, _, err := concentrator.LoadState(p)
		if err != nil {
			return fail(err)
		}
		reg, err := concentrator.LoadRegistry(p)
		if err != nil {
			return fail(err)
		}
		tok, err := reg.CreateToken(*uses, *ttl)
		if err != nil {
			return fail(err)
		}
		ca, _, err := concentrator.EnsureCA(p, st.Zone, st.ConcentratorID)
		if err != nil {
			return fail(err)
		}
		host, _ := os.Hostname()
		if len(st.ServerNames) > 0 {
			host = st.ServerNames[0]
		}
		port := st.Listen
		if i := strings.LastIndex(port, ":"); i >= 0 {
			port = port[i+1:]
		}
		fmt.Fprintf(stdout, "Enrollment token (shown once, %d use(s), valid %s):\n  %s\nZone CA SHA-256 fingerprint (agents pin it):\n  %s\n\nInstall an agent (on the server, with contix-agent and packaging/; use a name or IP agents can reach):\n  sudo sh packaging/install-agent.sh --concentrator https://%s:%s --token %s --ca-fingerprint %s --binary ./contix-agent\n",
			*uses, *ttl, tok, concentrator.CAFingerprint(ca), host, port, tok, concentrator.CAFingerprint(ca))
		return 0
	case "status":
		st, _, err := concentrator.LoadState(p)
		if err != nil {
			return fail(err)
		}
		reg, err := concentrator.LoadRegistry(p)
		if err != nil {
			return fail(err)
		}
		q, err := spool.NewQueue(p.Queue(), 1, time.Hour)
		if err != nil {
			return fail(err)
		}
		files, bytes := q.Stats()
		fmt.Fprintf(stdout, "concentrator %s\nzone        %s\ncontix      %s\nlisten      %s\nagents      %d\nqueue       %d files, %d bytes\n", st.ConcentratorID, st.Zone, st.URL, st.Listen, reg.Agents(), files, bytes)
		if ca, _, err := concentrator.EnsureCA(p, st.Zone, st.ConcentratorID); err == nil {
			fmt.Fprintf(stdout, "zone CA     %s (until %s)\n", concentrator.CAFingerprint(ca), ca.NotAfter.Format("2006-01-02"))
		}
		return 0
	default:
		usage(stderr)
		return 2
	}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func agentCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	fs := flag.NewFlagSet("agent "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", agent.DefaultStateDir, "state directory (keys, certificates, outbox)")
	conc := fs.String("concentrator", "", "concentrator address, e.g. https://konc.example.cz:8443")
	token := fs.String("token", "", "zone enrollment token from the concentrator (ctxe_…)")
	fp := fs.String("ca-fingerprint", "", "SHA-256 fingerprint of the zone CA (from `concentrator token`)")
	force := fs.Bool("force", false, "enroll again (new identity)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	p := agent.Paths{Dir: *stateDir}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fail := func(err error) int {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	switch args[0] {
	case "enroll":
		if *conc == "" || *token == "" || *fp == "" {
			fmt.Fprintln(stderr, "error: --concentrator, --token and --ca-fingerprint are required")
			return 2
		}
		st, err := agent.Enroll(ctx, p, agent.NewCollector(), agent.EnrollOptions{Concentrator: *conc, Token: *token, CAFingerprint: *fp, Version: version, Force: *force})
		if err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "Enrolled: agent %s (%s in CONTIX) via %s\nStart the service: systemctl enable --now contix-agent\n", st.AgentID, st.Status, st.Concentrator)
		return 0
	case "run":
		log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
		if err := agent.Run(ctx, p, version, log); err != nil {
			return fail(err)
		}
		return 0
	case "status":
		s, err := agent.Status(p)
		if err != nil {
			return fail(err)
		}
		fmt.Fprint(stdout, s)
		return 0
	case "collect":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(agent.NewCollector().Collect(ctx, agent.AllModules)); err != nil {
			return fail(err)
		}
		return 0
	default:
		usage(stderr)
		return 2
	}
}
