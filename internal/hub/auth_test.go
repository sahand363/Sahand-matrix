package hub

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"sahand-matrix/internal/analyzer"
)

func TestGuardAPI_FailClosed(t *testing.T) {
	aw := NewAuthWatchdog("admin", "secret123", nil, nil)
	protected := aw.GuardAPI(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// 1. Missing session cookie -> 401
	req1 := httptest.NewRequest(http.MethodGet, "/matrix/sec/api/state", nil)
	rr1 := httptest.NewRecorder()
	protected.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing cookie, got %d", rr1.Code)
	}

	// 2. Empty session cookie -> 401
	req2 := httptest.NewRequest(http.MethodGet, "/matrix/sec/api/state", nil)
	req2.AddCookie(&http.Cookie{Name: "sahand_session", Value: ""})
	rr2 := httptest.NewRecorder()
	protected.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for empty cookie, got %d", rr2.Code)
	}

	// 3. Invalid session cookie -> 401
	req3 := httptest.NewRequest(http.MethodGet, "/matrix/sec/api/state", nil)
	req3.AddCookie(&http.Cookie{Name: "sahand_session", Value: "forged-token-999"})
	rr3 := httptest.NewRecorder()
	protected.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid cookie, got %d", rr3.Code)
	}

	// 4. Valid issued session cookie -> 200
	rrLogin := httptest.NewRecorder()
	aw.issueSessionCookie(rrLogin, req1)
	cookies := rrLogin.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie to be issued")
	}

	req4 := httptest.NewRequest(http.MethodGet, "/matrix/sec/api/state", nil)
	req4.AddCookie(cookies[0])
	rr4 := httptest.NewRecorder()
	protected.ServeHTTP(rr4, req4)
	if rr4.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid session cookie, got %d", rr4.Code)
	}
}

func TestHandleUpdate_MethodAuthAndConcurrency(t *testing.T) {
	aw := NewAuthWatchdog("admin", "secret123", nil, nil)

	rrCookie := httptest.NewRecorder()
	aw.issueSessionCookie(rrCookie, httptest.NewRequest(http.MethodGet, "/", nil))
	validCookie := rrCookie.Result().Cookies()[0]

	// 1. GET request rejected with 405 Method Not Allowed
	reqGet := httptest.NewRequest(http.MethodGet, "/matrix/sec/api/update", nil)
	reqGet.AddCookie(validCookie)
	rrGet := httptest.NewRecorder()
	aw.HandleUpdate(rrGet, reqGet, func() {})
	if rrGet.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET update, got %d", rrGet.Code)
	}

	// 2. Unauthenticated POST rejected with 401 Unauthorized
	reqUnauth := httptest.NewRequest(http.MethodPost, "/matrix/sec/api/update", nil)
	rrUnauth := httptest.NewRecorder()
	aw.HandleUpdate(rrUnauth, reqUnauth, func() {})
	if rrUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated POST update, got %d", rrUnauth.Code)
	}

	// 3. Authenticated POST succeeds and locks concurrent execution (409 Conflict)
	blockCh := make(chan struct{})
	reqPost1 := httptest.NewRequest(http.MethodPost, "/matrix/sec/api/update", nil)
	reqPost1.AddCookie(validCookie)
	rrPost1 := httptest.NewRecorder()
	aw.HandleUpdate(rrPost1, reqPost1, func() {
		<-blockCh
	})
	if rrPost1.Code != http.StatusOK {
		t.Fatalf("expected 200 for first authenticated POST update, got %d", rrPost1.Code)
	}

	// Second concurrent POST must return 409 Conflict
	reqPost2 := httptest.NewRequest(http.MethodPost, "/matrix/sec/api/update", nil)
	reqPost2.AddCookie(validCookie)
	rrPost2 := httptest.NewRecorder()
	aw.HandleUpdate(rrPost2, reqPost2, func() {})
	if rrPost2.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict for concurrent update, got %d", rrPost2.Code)
	}
	close(blockCh)
}

func TestCORSMiddleware_NoWildcard(t *testing.T) {
	aw := NewAuthWatchdog("", "", nil, nil)
	h := aw.CORSMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// 1. Untrusted origin must not receive '*' or origin reflection
	reqEvil := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	reqEvil.Host = "198.51.100.10:8443"
	reqEvil.Header.Set("Origin", "http://evil.example.com")
	rrEvil := httptest.NewRecorder()
	h.ServeHTTP(rrEvil, reqEvil)
	if got := rrEvil.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected empty CORS header for untrusted origin, got %q", got)
	}

	// 2. Untrusted OPTIONS preflight rejected with 403
	reqOpt := httptest.NewRequest(http.MethodOptions, "/api/state", nil)
	reqOpt.Host = "198.51.100.10:8443"
	reqOpt.Header.Set("Origin", "http://evil.example.com")
	rrOpt := httptest.NewRecorder()
	h.ServeHTTP(rrOpt, reqOpt)
	if rrOpt.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for untrusted OPTIONS preflight, got %d", rrOpt.Code)
	}

	// 3. Same-origin request receives matching Origin header
	reqSame := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	reqSame.Host = "198.51.100.10:8443"
	reqSame.Header.Set("Origin", "http://198.51.100.10:8443")
	rrSame := httptest.NewRecorder()
	h.ServeHTTP(rrSame, reqSame)
	if got := rrSame.Header().Get("Access-Control-Allow-Origin"); got != "http://198.51.100.10:8443" {
		t.Fatalf("expected same-origin reflection, got %q", got)
	}
}

func TestCheckpointsCP1ToCP6Intact(t *testing.T) {
	guides := analyzer.AllCheckpointGuides()
	if len(guides) != 6 {
		t.Fatalf("expected 6 checkpoints (CP1-CP6), got %d", len(guides))
	}
}
