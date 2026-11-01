// Command driftwatch-agent is the Driftwatch lab execution agent.
//
//	driftwatch-agent enroll -config agent.json -token <ttl token>
//	driftwatch-agent run    -config agent.json
//	driftwatch-agent hygiene              (print the local baseline report; no server needed)
//	driftwatch-agent catalog              (list the compiled-in Safe Action Catalog)
//	driftwatch-agent version
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"syscall"
	"time"

	"github.com/blackdalc7/DriftWatch-Project/agent/internal/agent"
	"github.com/blackdalc7/DriftWatch-Project/agent/internal/catalog"
	"github.com/blackdalc7/DriftWatch-Project/agent/internal/client"
	"github.com/blackdalc7/DriftWatch-Project/agent/internal/config"
	"github.com/blackdalc7/DriftWatch-Project/agent/internal/hygiene"
	"github.com/blackdalc7/DriftWatch-Project/agent/internal/metrics"
	"github.com/blackdalc7/DriftWatch-Project/agent/internal/state"
)

// Version is set at build time with -ldflags "-X main.Version=...".
var Version = "1.0.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	var err error
	switch os.Args[1] {
	case "enroll":
		err = enroll(os.Args[2:])
	case "run":
		err = run(os.Args[2:], logger)
	case "hygiene":
		err = printHygiene()
	case "catalog":
		ids := make([]string, 0, len(catalog.Actions))
		for id := range catalog.Actions {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			fmt.Println(id)
		}
	case "version":
		fmt.Printf("driftwatch-agent %s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: driftwatch-agent enroll|run|hygiene|catalog|version [-config agent.json] [-token T]")
}

func loadConfig(fs *flag.FlagSet, args []string) (*config.Config, error) {
	path := fs.String("config", defaultConfigPath(), "path to agent.json")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return config.Load(*path)
}

func defaultConfigPath() string {
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\Driftwatch\agent.json`
	}
	return "/etc/driftwatch/agent.json"
}

func osVersion() string {
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range splitLines(string(data)) {
			if len(line) > 12 && line[:12] == "PRETTY_NAME=" {
				return trimQuotes(line[12:])
			}
		}
	}
	return runtime.GOOS
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func trimQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func enroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	token := fs.String("token", os.Getenv("DRIFTWATCH_ENROLL_TOKEN"), "one-time enrollment token")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	if *token == "" {
		return errors.New("an enrollment token is required (-token or DRIFTWATCH_ENROLL_TOKEN)")
	}
	store := &state.Store{Dir: cfg.StateDir}
	if store.Enrolled() {
		return fmt.Errorf("already enrolled; remove %s to enroll again", cfg.StateDir)
	}
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	csr, err := store.NewKeyAndCSR(hostname)
	if err != nil {
		return err
	}
	c, err := client.New(cfg.ServerURL, cfg.CAFile, nil)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := c.Enroll(ctx, client.EnrollRequest{Token: *token, CSRPEM: csr, Hostname: hostname,
		Platform: config.Platform(), OSVersion: osVersion(), AgentVersion: Version})
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}
	if err := store.SaveEnrollment(state.Identity{AgentID: resp.AgentID, Hostname: hostname, Tags: resp.Tags,
		HeartbeatInterval: resp.HeartbeatInterval}, resp.CertificatePEM); err != nil {
		return err
	}
	fmt.Printf("enrolled as %s with tags %v\n", resp.AgentID, resp.Tags)
	return nil
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func run(args []string, logger *slog.Logger) error {
	cfg, err := loadConfig(flag.NewFlagSet("run", flag.ExitOnError), args)
	if err != nil {
		return err
	}
	store := &state.Store{Dir: cfg.StateDir}
	id, err := store.Identity()
	if err != nil {
		return err
	}
	cert, err := store.Certificate()
	if err != nil {
		return fmt.Errorf("cannot load client certificate: %w", err)
	}
	c, err := client.New(cfg.ServerURL, cfg.CAFile, &cert)
	if err != nil {
		return err
	}
	pub, _ := cfg.PublicKey()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a := &agent.Agent{API: c, State: store, Identity: id, PublicKey: pub, Platform: config.Platform(),
		Scope: cfg.LabScope, Workspace: cfg.Workspace, Version: Version, Metrics: metrics.Collect,
		Hygiene: hygiene.Collector(config.Platform(), cfg.Workspace), Log: logger, Now: time.Now, Sleep: sleep}
	logger.Info("agent started", "agent_id", id.AgentID, "server", cfg.ServerURL, "scope", cfg.LabScope)
	a.Run(ctx, cfg.Poll)
	logger.Info("agent stopped")
	return nil
}

func printHygiene() error {
	dir, err := os.MkdirTemp("", "driftwatch-hygiene")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	report, err := hygiene.Collector(config.Platform(), dir)(ctx)
	if err != nil {
		return err
	}
	out, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(out))
	return nil
}
