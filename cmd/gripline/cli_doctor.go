package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/B-A-M-N/gripline/internal/config"
	"github.com/B-A-M-N/gripline/internal/statebolt"
	"github.com/B-A-M-N/gripline/internal/statepg"
)

func runDoctorCommandCLI(ctx *cliContext, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("doctor does not accept arguments")
	}
	return runDoctorCLI(ctx)
}

type doctorCheck struct {
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Blocking bool   `json:"blocking"`
	Detail   string `json:"detail"`
}

type doctorReport struct {
	Ready          bool          `json:"ready"`
	BlockingIssues int           `json:"blocking_issues"`
	Checks         []doctorCheck `json:"checks"`
}

func runDoctorCLI(ctx *cliContext) error {
	checks := make([]doctorCheck, 0, 10)
	add := func(name string, ok, blocking bool, detail string) {
		checks = append(checks, doctorCheck{Name: name, OK: ok, Blocking: blocking, Detail: detail})
	}
	localCtx, cancel := context.WithTimeout(context.Background(), ctx.Timeout)
	defer cancel()
	cfg, err := config.Load(ctx.ConfigPath)
	if err != nil {
		add("configuration", false, true, err.Error())
		return printDoctor(ctx.Output, checks)
	}
	if err := cfg.ValidateCertificates(); err != nil {
		add("TLS configuration", false, true, err.Error())
	} else {
		add("TLS configuration", true, true, "valid")
	}
	trustMode := string(cfg.Backend.TrustMode)
	trustOK := trustMode == "mtls" || trustMode == "private_network" || trustMode == "development"
	add("backend trust mode", trustOK, true, trustMode)
	clustered := strings.EqualFold(strings.TrimSpace(cfg.Authority.Backend), "postgres")
	if clustered {
		// The admin cluster probe is the authoritative PostgreSQL readiness
		// surface; standalone deployments must never be judged by it.
	} else if cfg.Paths.State != "" {
		state, stateErr := statebolt.OpenReadOnly(cfg.Paths.State, statebolt.Options{})
		if stateErr != nil {
			add("state authority", false, true, stateErr.Error())
		} else {
			readyErr := state.Ready(localCtx)
			_ = state.Close()
			if readyErr != nil {
				add("state authority", false, true, readyErr.Error())
			} else {
				add("state authority", true, true, "standalone state is readable")
			}
		}
	} else {
		add("state authority", true, false, "ephemeral standalone state is enabled")
	}

	token, tokenErr := operatorTokenFromFile(ctx.Token, ctx.TokenFile)
	adminConfigured := cfg.Admin != nil && strings.TrimSpace(cfg.Admin.Listen) != ""
	if tokenErr != nil {
		add("operator credentials", false, adminConfigured, tokenErr.Error())
	} else if token == "" {
		add("operator credentials", false, adminConfigured, "set GRIPLINE_OPERATOR_TOKEN, GRIPLINE_OPERATOR_TOKEN_FILE, or pass --token-file")
	} else {
		add("operator credentials", true, false, "configured")
	}
	if token != "" && tokenErr == nil && adminConfigured {
		client, clientErr := newAdminClientWithTimeout(ctx.ConfigPath, ctx.Timeout)
		if clientErr != nil {
			add("admin endpoint", false, true, clientErr.Error())
		} else {
			if clustered {
				var cluster statepg.ClusterStatus
				if err := client.requestContext(localCtx, http.MethodGet, "/admin/cluster", token, nil, &cluster); err != nil {
					var httpErr adminHTTPError
					if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusForbidden {
						add("cluster diagnostics", false, true, "insufficient capability: cluster.read")
					} else {
						add("admin endpoint", false, true, err.Error())
					}
				} else {
					add("admin endpoint", true, true, "reachable and authenticated")
					if cluster.LocalMembershipReady {
						add("state authority", true, true, "local PostgreSQL membership is ready")
					} else {
						add("state authority", false, true, "local PostgreSQL membership is not ready")
					}
					cryptoOK, cryptoDetail := doctorCryptoHealth(cluster)
					add("crypto synchronization", cryptoOK, true, cryptoDetail)
					maintenanceOK, maintenanceDetail := doctorMaintenanceHealth(cluster.Maintenance)
					// Retention maintenance is intentionally diagnostic rather than a
					// data-plane readiness gate. A warning still makes persistent
					// history growth visible without taking healthy admission offline.
					add("maintenance", maintenanceOK, false, maintenanceDetail)
				}
			} else {
				add("admin endpoint", true, false, "standalone deployment uses local readiness")
			}
			var policyStatus struct {
				Active *adminPolicySnapshot `json:"active"`
			}
			if err := client.requestContext(localCtx, http.MethodGet, "/admin/policy", token, nil, &policyStatus); err != nil {
				var httpErr adminHTTPError
				if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusForbidden {
					add("active policy", false, true, "insufficient capability: policy.read")
				} else {
					add("active policy", false, true, err.Error())
				}
			} else if policyStatus.Active == nil || policyStatus.Active.ID == "" || policyStatus.Active.Revision < 1 || policyStatus.Active.Digest == "" {
				add("active policy", false, true, "no valid active policy is installed")
			} else {
				add("active policy", true, true, fmt.Sprintf("%s revision %d", policyStatus.Active.ID, policyStatus.Active.Revision))
			}
		}
	} else if !adminConfigured && clustered {
		add("admin endpoint", false, true, "clustered doctor requires an authenticated private admin listener")
	}
	if !clustered {
		pol, policyErr := policyFor(cfg)
		if policyErr != nil {
			add("active policy", false, true, policyErr.Error())
		} else if pol == nil || pol.ID == "" || pol.Revision < 1 {
			add("active policy", false, true, "no valid active policy is configured")
		} else {
			add("active policy", true, true, fmt.Sprintf("%s revision %d", pol.ID, pol.Revision))
		}
	}
	return printDoctor(ctx.Output, checks)
}

func doctorCryptoHealth(status statepg.ClusterStatus) (bool, string) {
	if !status.Crypto.Initialized {
		return false, "cluster crypto is not initialized"
	}
	if status.Crypto.SignerActiveKID < 1 || status.Crypto.PepperActiveVersion < 1 {
		return false, "active signer and pepper generations are incomplete"
	}
	if !status.LocalCryptoReady {
		for _, generation := range status.Crypto.Generations {
			if generation.State == "active" && generation.AcknowledgedNodes != status.LiveNodeCount {
				return false, fmt.Sprintf("%s/%d acknowledged by %d/%d live nodes", generation.Kind, generation.Generation, generation.AcknowledgedNodes, status.LiveNodeCount)
			}
		}
		return false, "active crypto generations are not synchronized"
	}
	for _, generation := range status.Crypto.Generations {
		if generation.State == "loaded" && generation.RetireAfter != nil && !time.Now().Before(*generation.RetireAfter) {
			return false, fmt.Sprintf("%s generation %d is past its retirement horizon", generation.Kind, generation.Generation)
		}
	}
	return true, fmt.Sprintf("epoch %d synchronized and locally ready", status.Crypto.GenerationEpoch)
}

func doctorMaintenanceHealth(status statepg.ClusterMaintenanceStatus) (bool, string) {
	if status.ConsecutiveErrors == 0 && status.BacklogEstimate == 0 {
		if status.Runs == 0 {
			return true, "no maintenance failures reported yet"
		}
		return true, fmt.Sprintf("healthy after %d run(s)", status.Runs)
	}
	return false, fmt.Sprintf("%d consecutive error(s); backlog estimate %d", status.ConsecutiveErrors, status.BacklogEstimate)
}

func printDoctor(format outputFormat, checks []doctorCheck) error {
	blocking := 0
	for _, check := range checks {
		if check.Blocking && !check.OK {
			blocking++
		}
	}
	report := doctorReport{Ready: blocking == 0, BlockingIssues: blocking, Checks: checks}
	if format == outputJSON || format == outputJSONL {
		if err := encodeCLIOutput(format, report); err != nil {
			return err
		}
		if !report.Ready {
			return &cliExitError{Code: 1}
		}
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "STATUS\tCHECK\tDETAIL")
	for _, check := range checks {
		status := "✓"
		if !check.OK {
			status = "!"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", status, check.Name, check.Detail)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if blocking == 0 {
		fmt.Fprintln(os.Stdout, "READY       no blocking issues")
	} else {
		fmt.Fprintf(os.Stdout, "NOT READY   %d blocking issue(s)\n", blocking)
		return &cliExitError{Code: 1}
	}
	return nil
}
