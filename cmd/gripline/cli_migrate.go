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

// runMigrateCLI is deliberately separate from the serving runtime. The
// migration role may create/alter the authority schema; serving nodes only
// perform the read-only compatibility check in statepg.Open.
func runMigrateCLI(args []string) error {
	if len(args) == 0 || (args[0] != "plan" && args[0] != "apply") {
		return fmt.Errorf("migrate: expected plan or apply")
	}
	fs := newCLIFlagSet("migrate")
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	migrationTimeout := fs.Duration("timeout", 5*time.Minute, "maximum time for schema inspection or migration")
	output := fs.String("output", "", "output format: table, json, or jsonl")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	format, err := parseCLIOutput(*output)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if *migrationTimeout <= 0 {
		return fmt.Errorf("migrate: --timeout must be positive")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if strings.ToLower(strings.TrimSpace(cfg.Authority.Backend)) != "postgres" {
		return fmt.Errorf("migrate: authority.backend must be postgres")
	}
	dsn := os.Getenv(cfg.Authority.DSNEnv)
	if dsn == "" {
		return fmt.Errorf("migrate: authority DSN environment variable %q is empty", cfg.Authority.DSNEnv)
	}
	connectTimeout := cfg.Authority.ConnectTimeout.D()
	if connectTimeout <= 0 {
		connectTimeout = 10 * time.Second
	}
	operationTimeout := cfg.Authority.OperationTimeout.D()
	if operationTimeout <= 0 {
		operationTimeout = 2 * time.Second
	}
	opts := statepg.Options{
		DSN: dsn, MaxConns: cfg.Authority.MaxConns, MinConns: cfg.Authority.MinConns,
		LeaseTTL: cfg.Authority.LeaseTTL.D(), RenewEvery: cfg.Authority.RenewEvery.D(),
		ConnectTimeout: connectTimeout, OperationTimeout: operationTimeout,
	}
	switch args[0] {
	case "plan":
		ctx, cancel := context.WithTimeout(context.Background(), *migrationTimeout)
		defer cancel()
		status, err := statepg.InspectSchema(ctx, opts)
		if err != nil {
			return fmt.Errorf("migrate plan: %w", err)
		}
		if !status.Present {
			if format == outputJSON || format == outputJSONL {
				if err := encodeCLIOutput(format, map[string]any{"present": false, "migration_required": true, "supported_version": status.SupportedVersion}); err != nil {
					return err
				}
			} else {
				fmt.Printf("schema uninitialized: migration required (supported %d)\n", status.SupportedVersion)
			}
		} else if status.Version != status.SupportedVersion {
			if format == outputJSON || format == outputJSONL {
				if err := encodeCLIOutput(format, map[string]any{"present": true, "version": status.Version, "supported_version": status.SupportedVersion, "migration_required": true}); err != nil {
					return err
				}
			} else {
				fmt.Printf("schema version %d (supported %d): migration required\n", status.Version, status.SupportedVersion)
			}
		} else {
			if format == outputJSON || format == outputJSONL {
				if err := encodeCLIOutput(format, map[string]any{"present": true, "version": status.Version, "supported_version": status.SupportedVersion, "migration_required": false}); err != nil {
					return err
				}
			} else {
				fmt.Printf("schema version %d: current\n", status.Version)
			}
		}
		return errSubcommand
	case "apply":
		ctx, cancel := context.WithTimeout(context.Background(), *migrationTimeout)
		defer cancel()
		opts.Migrate = true
		store, err := statepg.Open(ctx, opts)
		if err != nil {
			return fmt.Errorf("migrate apply: %w", err)
		}
		store.Close()
		if format == outputJSON || format == outputJSONL {
			if err := encodeCLIOutput(format, map[string]any{"result": "schema migration applied", "version": statepg.SupportedSchemaVersion()}); err != nil {
				return err
			}
		} else {
			fmt.Printf("schema migration applied: version %d\n", statepg.SupportedSchemaVersion())
		}
		return errSubcommand
	}
	return nil
}
