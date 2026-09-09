package main

import "testing"

func TestSelectWritableBackend(t *testing.T) {
	tests := []struct {
		name    string
		states  []backendState
		want    string
		wantErr bool
	}{
		{name: "primary and replica", states: []backendState{{address: "primary", reachable: true, writable: true}, {address: "replica", reachable: true, writable: false}}, want: "primary"},
		{name: "primary down", states: []backendState{{address: "primary", reachable: false}, {address: "replica", reachable: true, writable: false}}, wantErr: true},
		{name: "promoted replica", states: []backendState{{address: "primary", reachable: false}, {address: "replica", reachable: true, writable: true}}, want: "replica"},
		{name: "split brain", states: []backendState{{address: "primary", reachable: true, writable: true}, {address: "replica", reachable: true, writable: true}}, wantErr: true},
		{name: "none reachable", states: []backendState{{address: "primary"}, {address: "replica"}}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := selectWritableBackend(test.states)
			if (err != nil) != test.wantErr {
				t.Fatalf("error=%v, want error=%v", err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("backend=%q, want %q", got, test.want)
			}
		})
	}
}
