package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/B-A-M-N/gripline/internal/config"
	"github.com/B-A-M-N/gripline/internal/statepg"
)

// runClusterCLI exposes shared authority diagnostics through the authenticated
// admin listener. It never opens or mutates the database locally, which keeps
// status accurate when the CLI runs on a different operator workstation.
func runClusterCLI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("cluster: expected status or behavior")
	}
	if args[0] == "behavior" {
		return runClusterBehaviorCLI(args[1:])
	}
	if args[0] != "status" {
		return fmt.Errorf("cluster: expected status or behavior")
	}
	return runRemoteStatusCLI("cluster status", "/admin/cluster", args[1:])
}

func runClusterBehaviorCLI(args []string) error {
	if len(args) == 0 || (args[0] != "plan" && args[0] != "apply") {
		return fmt.Errorf("cluster behavior: expected plan or apply")
	}
	action := args[0]
	fs := newCLIFlagSet("cluster behavior " + action)
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	timeout := fs.Duration("timeout", 2*time.Minute, "maximum time for the behavior read or update")
	expectedDigest := fs.String("expected-current-digest", "", "current authoritative digest, or none before initialization")
	actor := fs.String("actor", "operator", "operator identity recorded in the audit history")
	reason := fs.String("reason", "", "audited reason for the behavior update")
	output := fs.String("output", "table", "output format: table, json, or jsonl")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	format, err := parseCLIOutput(*output)
	if err != nil {
		return fmt.Errorf("cluster behavior %s: %w", action, err)
	}
	if *timeout <= 0 {
		return fmt.Errorf("cluster behavior %s: --timeout must be positive", action)
	}
	if action == "apply" && strings.TrimSpace(*reason) == "" {
		return fmt.Errorf("cluster behavior apply: --reason is required")
	}
	if action == "apply" && strings.TrimSpace(*expectedDigest) == "" {
		return fmt.Errorf("cluster behavior apply: --expected-current-digest is required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("cluster behavior %s: %w", action, err)
	}
	if !strings.EqualFold(strings.TrimSpace(cfg.Authority.Backend), "postgres") {
		return fmt.Errorf("cluster behavior %s: authority.backend must be postgres", action)
	}
	dsn := os.Getenv(cfg.Authority.DSNEnv)
	if dsn == "" {
		return fmt.Errorf("cluster behavior %s: authority DSN environment variable %q is empty", action, cfg.Authority.DSNEnv)
	}
	connectTimeout := cfg.Authority.ConnectTimeout.D()
	if connectTimeout <= 0 {
		connectTimeout = 10 * time.Second
	}
	operationTimeout := cfg.Authority.OperationTimeout.D()
	if operationTimeout <= 0 {
		operationTimeout = 2 * time.Second
	}
	behavior := clusterBehaviorFromConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	store, err := statepg.Open(ctx, statepg.Options{
		DSN: dsn, MaxConns: cfg.Authority.MaxConns, MinConns: cfg.Authority.MinConns,
		LeaseTTL: cfg.Authority.LeaseTTL.D(), RenewEvery: cfg.Authority.RenewEvery.D(),
		MaxSourceScopes: cfg.Server.MaxSourceScopes, SourceScopeIdle: cfg.Server.SourceScopeIdle.D(),
		MaxSourceAliasIdentities: cfg.Authority.MaxSourceAliasIdentities,
		ClusterBehavior:          behavior, ConnectTimeout: connectTimeout, OperationTimeout: operationTimeout,
	})
	if err != nil {
		return fmt.Errorf("cluster behavior %s: %w", action, err)
	}
	defer store.Close()
	var plan statepg.ClusterBehaviorPlan
	if action == "plan" {
		plan, err = store.PlanClusterBehavior(ctx, *behavior)
	} else {
		plan, err = store.ApplyClusterBehavior(ctx, *behavior, *expectedDigest, *actor, *reason)
	}
	if err != nil {
		return fmt.Errorf("cluster behavior %s: %w", action, err)
	}
	if format == outputJSON || format == outputJSONL {
		return encodeCLIOutput(format, plan)
	}
	printClusterBehaviorPlan(action, plan)
	return nil
}

func printClusterBehaviorPlan(action string, plan statepg.ClusterBehaviorPlan) {
	current := plan.CurrentDigest
	if current == "" {
		current = "none"
	}
	status := "unchanged"
	if !plan.Initialized {
		status = "uninitialized"
	} else if len(plan.Changes) > 0 {
		status = "changes pending"
	}
	fmt.Printf("cluster behavior %s: %s\n", action, status)
	fmt.Printf("current digest: %s\ndesired digest: %s\n", current, plan.DesiredDigest)
	for _, change := range plan.Changes {
		currentValue := "<unset>"
		if change.Current != nil {
			currentValue = fmt.Sprint(change.Current)
		}
		fmt.Printf("  %s: %s -> %v\n", change.Field, currentValue, change.Desired)
	}
}
