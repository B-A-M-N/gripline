package main

import (
	"fmt"
)

// runClusterCLI exposes shared authority diagnostics through the authenticated
// admin listener. It never opens or mutates the database locally, which keeps
// status accurate when the CLI runs on a different operator workstation.
func runClusterCLI(args []string) error {
	if len(args) == 0 || args[0] != "status" {
		return fmt.Errorf("cluster: expected status")
	}
	return runRemoteStatusCLI("cluster status", "/admin/cluster", args[1:])
}
