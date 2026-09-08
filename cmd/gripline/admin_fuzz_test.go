package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func FuzzAdminJSONDecoder(f *testing.F) {
	f.Add([]byte(`{"reason":"fuzz"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := httptest.NewRequest(http.MethodPost, "http://admin.local/admin", bytes.NewReader(data))
		w := httptest.NewRecorder()
		var dst struct {
			Reason string `json:"reason"`
		}
		_ = decodeAdminJSON(w, r, &dst)
	})
}
