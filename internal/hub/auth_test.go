package hub

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sahand-matrix/pkg/models"
)

func TestMissingEmptyIncorrectTokens(t *testing.T) {
	aw := NewAuthWatchdog("admin", "pass123", nil, nil)
	aw.SetSharedToken("valid-shared-secret-999")

	okHandler := aw.GuardM2M(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cases := []struct {
		name       string
		headerKey  string
		headerVal  string
		expectCode int
	}{
		{"Missing token header", "", "", http.StatusUnauthorized},
		{"Empty X-Sahand-Token", "X-Sahand-Token", "", http.StatusUnauthorized},
		{"Whitespace X-Sahand-Token", "X-Sahand-Token", "   ", http.StatusUnauthorized},
		{"Incorrect X-Sahand-Token", "X-Sahand-Token", "wrong-token", http.StatusUnauthorized},
		{"Incorrect Bearer token", "Authorization", "Bearer wrong-token", http.StatusUnauthorized},
		{"Valid X-Sahand-Token", "X-Sahand-Token", "valid-shared-secret-999", http.StatusOK},
		{"Valid Bearer token", "Authorization", "Bearer valid-shared-secret-999", http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/snapshot", nil)
			if tc.headerKey != "" {
				req.Header.Set(tc.headerKey, tc.headerVal)
			}
			rr := httptest.NewRecorder()
			okHandler.ServeHTTP(rr, req)
			if rr.Code != tc.expectCode {
				t.Fatalf("%s: expected HTTP %d, got %d", tc.name, tc.expectCode, rr.Code)
			}
		})
	}

	t.Run("Unconfigured empty server token fails closed", func(t *testing.T) {
		unconfigured := NewAuthWatchdog("", "", nil, nil)
		h := unconfigured.GuardM2M(func(w http.ResponseWriter, r *http.Request)
