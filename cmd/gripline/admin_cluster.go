package main

import (
	"net/http"

	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/statepg"
)

// adminClusterStatus exposes only shared operational metadata. It is kept on
// the authenticated admin listener and requires a dedicated read capability;
// the data plane never uses this diagnostic response as an authority cache.
func adminClusterStatus(svc *control.Service, authority *statepg.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			adminMethodNotAllowed(w)
			return
		}
		if _, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapClusterRead); err != nil {
			writeAdminError(w, err)
			return
		}
		if authority == nil {
			http.Error(w, "cluster authority unavailable", http.StatusServiceUnavailable)
			return
		}
		status, err := authority.ClusterStatus(r.Context())
		if err != nil {
			http.Error(w, "cluster status unavailable", http.StatusServiceUnavailable)
			return
		}
		writeAdminJSON(w, status)
	}
}
