package main

import (
	"fmt"
	"net/http"
)

func runRemoteStatusCLI(command, endpoint string, args []string) error {
	fs := newCLIFlagSet(command)
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	token := fs.String("token", "", "operator token (env GRIPLINE_OPERATOR_TOKEN)")
	tokenFile := fs.String("token-file", "", "read the operator token from this file")
	output := fs.String("output", "", "output format: table, json, or jsonl")
	if err := fs.Parse(args); err != nil {
		return err
	}
	format, err := parseCLIOutput(*output)
	if err != nil {
		return fmt.Errorf("%s: %w", command, err)
	}
	tok, err := operatorTokenFromFile(*token, *tokenFile)
	if err != nil {
		return err
	}
	if tok == "" {
		return fmt.Errorf("%s: --token (or GRIPLINE_OPERATOR_TOKEN) is required", command)
	}
	client, err := newAdminClientWithTimeout(*cfgPath, cliRequestTimeout(fs))
	if err != nil {
		return err
	}
	var status map[string]any
	if err := client.request(http.MethodGet, endpoint, tok, nil, &status); err != nil {
		return fmt.Errorf("%s: %w", command, err)
	}
	if err := encodeRemoteStatus(format, command, status); err != nil {
		return err
	}
	return nil
}
