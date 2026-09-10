package main

// Shared CLI compatibility helpers. Command implementations live in files
// named for their responsibility; the declarative grammar and dispatch remain
// in cli_commands.go.

import (
	"flag"
	"io"
	"time"
)

func newCLIFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	// The compatibility parser is an implementation detail behind the
	// declarative CLI. Its built-in usage would expose legacy flags on parse
	// errors, so the front door owns all user-facing help and diagnostics.
	fs.SetOutput(io.Discard)
	fs.Duration("request-timeout", 30*time.Second, "internal admin request timeout")
	return fs
}

func cliRequestTimeout(fs *flag.FlagSet) time.Duration {
	if fs == nil {
		return 30 * time.Second
	}
	value := fs.Lookup("request-timeout")
	if value == nil {
		return 30 * time.Second
	}
	d, err := time.ParseDuration(value.Value.String())
	if err != nil || d <= 0 {
		return 30 * time.Second
	}
	return d
}

func firstCLITimeout(timeouts []time.Duration) time.Duration {
	if len(timeouts) > 0 && timeouts[0] > 0 {
		return timeouts[0]
	}
	return 30 * time.Second
}

func firstCLIOutputFormat(formats []outputFormat) outputFormat {
	if len(formats) > 0 && formats[0] != "" {
		return formats[0]
	}
	return outputTable
}
