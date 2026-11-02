package hub

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type captchaChallenge struct {
	answer  int
	expires time.Time
}

// AuthWatchdog manages HTML Login + Math Captcha, 1h Session Cookies, M2M Token Auth,
// Single-Flight Update Locking, and 10m/1h Auto-Stop Timers.
type AuthWatchdog struct {
	mu           sync.Mutex
	user         string
	pass         string
	token        string
	cookieName   string
	sessions     map[string]time.Time // session token -> 1h expiry
	captchas     map[string]captchaChallenge
	failCount    map[string]int
	lockUntil    map[string]time.Time
	stopAt10m    time.Time
	stopAt1h     time.Time
	didStop10m   bool
	updating     bool
	onAutoStop   func(reason string)
	onSessionEnd func()
}

func NewAuthWatchdog(user, pass string, onAutoStop func(string), onSessionEnd func()) *AuthWatchdog {
	aw := &AuthWatchdog{
		user:         strings.TrimSpace(user),
		pass:         strings.TrimSpace(pass),
		cookieName:   "sahand_session",
		sessions:     make(map[string]time.Time),
		captchas:     make(map[string]captchaChallenge),
		failCount:    make(map[string]int),
		lockUntil:    make(map[string]time.Time),
		onAutoStop:   onAutoStop,
		onSessionEnd: onSessionEnd,
	}
	if aw.user == "" || aw.pass == "" {
		aw.ArmLoginTimers()
	}
	go aw.watchdogLoop()
	return aw
}

// SetSharedToken configures the secret token required for Machine-to-Machine (M2M) authentication.
func (aw *AuthWatchdog) SetSharedToken(token string) {
	aw.mu.Lock()
	defer aw.mu.Unlock()
	aw.token = strings.TrimSpace(token)
}

// SetCookieName overrides the session cookie name (e.g., for Sentinel nodes).
func (aw *AuthWatchdog) SetCookieName(name string) {
	aw.mu.Lock()
	defer aw.mu.Unlock()
	if strings.TrimSpace(name) != "" {
		aw.cookieName = strings.TrimSpace(name)
	}
}

func (aw *AuthWatchdog) ArmLoginTimers() {
	aw.mu.Lock()
	defer aw.mu.Unlock()
	now := time.Now()
	aw.stopAt10m = now.Add(10 * time.Minute)
	aw.stopAt1h = now.Add(60 * time.Minute)
	aw.didStop10m = false
}

func (aw *AuthWatchdog) RemainingSeconds() int {
	aw.mu.Lock()
	defer aw.mu.Unlock()
	now := time.Now()
	if !aw.didStop10m && aw.stopAt10m.After(now) {
		return int(aw.stopAt10m.Sub(now).Seconds())
	}
	if aw.stopAt1h.After(now) {
		return int(aw.stopAt1h.Sub(now).Seconds())
	}
	return 0
}

func (aw *AuthWatchdog) watchdogLoop() {
	for {
		time.Sleep(2 * time.Second)
		now := time.Now()
		var fireReason string
		var fireCleanup bool

		aw.mu.Lock()
		if !aw.didStop10m && !aw.stopAt10m.IsZero() && now.After(aw.stopAt10m) {
			aw.didStop10m = true
			fireReason = "10m post-login auto-stop"
		}
		if !aw.stopAt1h.IsZero() && now.After(aw.stopAt1h) {
			aw.stopAt1h = time.Time{}
			fireReason = "1h session safety cap"
			fireCleanup = true
		}
		for tok, exp := range aw.sessions {
			if now.After(exp) {
				delete(aw.sessions, tok)
				fireCleanup = true
			}
		}
		aw.mu.Unlock()

		if fireReason != "" && aw.onAutoStop != nil {
			aw.onAutoStop(fireReason)
		}
		if fireCleanup && aw.onSessionEnd != nil {
			aw.onSessionEnd()
		}
	}
}

// HasM2MHeader reports whether the request attempts token-based authentication.
func HasM2MHeader(r *http.Request) bool {
	if _, ok := r.Header["X-Sahand-Token"]; ok {
		return true
	}
	if _, ok := r.Header["Authorization"]; ok {
		return true
	}
	if r.URL != nil && r.URL.Query().Has("token") {
		return true
	}
	return false
}

// ValidateM2MToken performs fail-closed, constant-time validation of the shared machine token.
// It never inspects browser cookies.
func (aw *AuthWatchdog) ValidateM2MToken(r *http.Request) bool {
	aw.mu.Lock()
	expected := aw.token
	aw.mu.Unlock()

	if expected == "" {
		return false
	}

	provided := strings.TrimSpace(r.Header.Get("X-Sahand-Token"))
	if provided == "" {
		authHdr := strings.TrimSpace(r.Header.Get("Authorization"))
		if len(authHdr) > 7 && strings.EqualFold(authHdr[:7], "Bearer ") {
			provided = strings.TrimSpace(authHdr[7:])
		}
	}
	if provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

// IsAuthenticated verifies if the request carries a valid, unexpired browser session cookie.
// It fails closed and never accepts M2M tokens.
func (aw *AuthWatchdog) IsAuthenticated(r *http.Request) bool {
	aw.mu.Lock()
	cName := aw.cookieName
	aw.mu.Unlock()

	c, err := r.Cookie(cName)
	if err != nil || strings.TrimSpace(c.Value) == "" {
		return false
	}
	aw.mu.Lock()
	defer aw.mu.Unlock()
	exp, ok := aw.sessions[c.Value]
	if !ok || time.Now().After(exp) {
		delete(aw.sessions, c.Value)
		return false
	}
	return true
}

// GuardUI protects the HTML dashboard. In passwordless mode (user/pass blank), it issues
// an HttpOnly session cookie upon visiting the UI path so subsequent API calls are authenticated.
func (aw *AuthWatchdog) GuardUI(baseRoute string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if aw.IsAuthenticated(r) {
			next(w, r)
			return
		}
		aw.mu.Lock()
		passwordless := aw.user == "" || aw.pass == ""
		aw.mu.Unlock()

		if passwordless {
			aw.issueNewSession(w, r)
			next(w, r)
			return
		}
		aw.ServeLoginPage(w, r, baseRoute, "")
	}
}

// GuardSessionAPI enforces browser session authentication exclusively (rejects M2M tokens).
func (aw *AuthWatchdog) GuardSessionAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if HasM2MHeader(r) || !aw.IsAuthenticated(r) {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

// GuardM2M enforces machine-to-machine token authentication exclusively (rejects browser cookies).
func (aw *AuthWatchdog) GuardM2M(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !aw.ValidateM2MToken(r) {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

// GuardSentinelAPI separates M2M requests (carrying token headers) from browser session requests
// when the Sentinel UI is mounted at root "/".
func (aw *AuthWatchdog) GuardSentinelAPI(allowBrowserSession bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if HasM2MHeader(r) {
			if !aw.ValidateM2MToken(r) {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			next(w, r)
			return
		}
		if allowBrowserSession && aw.IsAuthenticated(r) {
			next(w, r)
			return
		}
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
	}
}

// GuardUpdate enforces POST-only execution, strict authentication, and single-flight concurrency locking.
func (aw *AuthWatchdog) GuardUpdate(runUpdate func()) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}

		authed := false
		if HasM2MHeader(r) {
			authed = aw.ValidateM2MToken(r)
		} else {
			authed = aw.IsAuthenticated(r)
		}
		if !authed {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		if origin := r.Header.Get("Origin"); origin != "" && ! isSameOrigin(origin, r) {
			writeJSONError(w, http.StatusForbidden, "forbidden_origin")
			return
		}

		aw.mu.Lock()
		if aw.updating {
			aw.mu.Unlock()
			writeJSONError(w, http.StatusConflict, "update_in_progress")
			return
		}
		aw.updating = true
		aw.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "updating"})

		go func() {
			defer func() {
				aw.mu.Lock()
				aw.updating = false
				aw.mu.Unlock()
			}()
			if runUpdate != nil {
				runUpdate()
			}
		}()
	}
}

// CORSMiddleware removes wildcard '*' CORS and restricts cross-origin headers to same-origin requests.
func (aw *AuthWatchdog) CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			if isSameOrigin(origin, r) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Sahand-Token, Authorization")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Vary", "Origin")
			} else if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isSameOrigin(origin string, r *http.Request) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host) || strings.EqualFold(u.Hostname(), strings.Split(r.Host, ":")[0])
}

func (aw *AuthWatchdog) issueNewSession(w http.ResponseWriter, r *http.Request) {
	tok := randomHex(20)
	aw.mu.Lock()
	cName := aw.cookieName
	aw.sessions[tok] = time.Now().Add(1 * time.Hour)
	aw.mu.Unlock()

	aw.ArmLoginTimers()
	http.SetCookie(w, &http.Cookie{
		Name:     cName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPSRequest(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
	})
}

func isHTTPSRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if host == "127.0.0.1" || host == "::1" {
		return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	}
	return false
}

func (aw *AuthWatchdog) HandleLogin(w http.ResponseWriter, r *http.Request, baseRoute string) {
	target := strings.TrimRight(baseRoute, "/") + "/"
	if r.Method != http.MethodPost {
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	_ = r.ParseForm()
	ip := strings.Split(r.RemoteAddr, ":")[0]

	aw.mu.Lock()
	if until, locked := aw.lockUntil[ip]; locked && time.Now().Before(until) {
		aw.mu.Unlock()
		aw.ServeLoginPage(w, r, baseRoute, "Too many failed attempts. Locked for 5 minutes.")
		return
	}
	cid := r.FormValue("cid")
	ch, chOk := aw.captchas[cid]
	delete(aw.captchas, cid)
	aw.mu.Unlock()

	ans, err := strconv.Atoi(strings.TrimSpace(r.FormValue("captcha")))
	if !chOk || err != nil || time.Now().After(ch.expires) || ans != ch.answer {
		aw.ServeLoginPage(w, r, baseRoute, "Incorrect math answer or expired challenge.")
		return
	}

	u := strings.TrimSpace(r.FormValue("username"))
	p := strings.TrimSpace(r.FormValue("password"))
	uOk := subtle.ConstantTimeCompare([]byte(u), []byte(aw.user)) == 1
	pOk := subtle.ConstantTimeCompare([]byte(p), []byte(aw.pass)) == 1

	if !uOk || !pOk {
		aw.mu.Lock()
		aw.failCount[ip]++
		if aw.failCount[ip] >= 5 {
			aw.lockUntil[ip] = time.Now().Add(5 * time.Minute)
			aw.failCount[ip] = 0
		}
		aw.mu.Unlock()
		aw.ServeLoginPage(w, r, baseRoute, "Invalid username or password.")
		return
	}

	aw.mu.Lock()
	delete(aw.failCount, ip)
	aw.mu.Unlock()

	aw.issueNewSession(w, r)
	http.Redirect(w, r, target, http.StatusFound)
}

func (aw *AuthWatchdog) HandleLogout(w http.ResponseWriter, r *http.Request, baseRoute string) {
	aw.mu.Lock()
	cName := aw.cookieName
	aw.mu.Unlock()

	if c, err := r.Cookie(cName); err == nil {
		aw.mu.Lock()
		delete(aw.sessions, c.Value)
		aw.mu.Unlock()
	}
	if aw.onAutoStop != nil {
		aw.onAutoStop("manual logout")
	}
	if aw.onSessionEnd != nil {
		aw.onSessionEnd()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPSRequest(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	http.Redirect(w, r, strings.TrimRight(baseRoute, "/")+"/", http.StatusFound)
}

func (aw *AuthWatchdog) ServeLoginPage(w http.ResponseWriter, _ *http.Request, baseRoute, errMsg string) {
	a, b := randInt(4, 19), randInt(3, 15)
	cid := randomHex(10)
	aw.mu.Lock()
	aw.captchas[cid] = captchaChallenge{answer: a + b, expires: time.Now().Add(3 * time.Minute)}
	aw.mu.Unlock()

	errBox := ""
	if errMsg != "" {
		errBox = `<div style="background:rgba(239,68,68,0.18);border:1px solid #EF4444;color:#FCA5A5;padding:8px 10px;border-radius:6px;margin-bottom:12px;font-size:12px;">⚠ ` + errMsg + `</div>`
	}
	loginPath := strings.TrimRight(baseRoute, "/") + "/login"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, loginPageTemplate, errBox, loginPath, cid, a, b)
}

// RunSelfUpdate executes the synchronous update process (called inside GuardUpdate's single-flight lock).
func RunSelfUpdate() {
	time.Sleep(400 * time.Millisecond)
	script := `export PATH=$PATH:/usr/local/go/bin; TMP=/tmp/sahand-upd-$$; git clone --depth 1 https://github.com/sahand363/Sahand-matrix.git $TMP && cd$TMP && go mod tidy && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /usr/local/bin/sahand-hub ./cmd/sahand-hub && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /usr/local/bin/sahand-agent ./cmd/sahand-agent && cp -f $TMP/scripts/setup.sh /usr/local/bin/sahand-menu && chmod +x /usr/local/bin/sahand-hub /usr/local/bin/sahand-agent /usr/local/bin/sahand-menu && rm -rf$TMP && (systemctl restart sahand-hub sahand-agent 2>/dev/null || true)`
	_ = exec.Command("bash", "-c", script).Run()
}

// TriggerSelfUpdate preserves backward compatibility for callers expecting an async helper.
func TriggerSelfUpdate() {
	go RunSelfUpdate()
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randInt(min, max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	return int(n.Int64()) + min
}

const loginPageTemplate = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>SAHAND MATRIX // Security Gate</title>
<style>
  body { background:#0B0F19; color:#F8FAFC; font-family:'Inter',system-ui,sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; }
  .card { background:#111827; border:1px solid #1E293B; border-top:3px solid #38BDF8; border-radius:12px; padding:26px 28px; width:100%%; max-width:380px; box-shadow:0 20px 40px rgba(0,0,0,0.5); }
  h2 { font-size:16px; color:#38BDF8; margin:0 0 6px 0; display:flex; align-items:center; gap:8px; }
  p { font-size:12px; color:#94A3B8; margin:0 0 18px 0; }
  label { display:block; font-size:12px; color:#CBD5E1; margin-bottom:5px; font-weight:600; }
  input { width:100%%; box-sizing:border-box; background:#070B14; border:1px solid #1E293B; color:#FFF; padding:9px 12px; border-radius:6px; font-size:13px; margin-bottom:14px; }
  input:focus { outline:none; border-color:#38BDF8; }
  .math-box { background:#0D1322; border:1px solid #38BDF8; border-radius:8px; padding:10px 12px; margin-bottom:16px; display:flex; align-items:center; justify-content:space-between; }
  .btn { width:100%%; background:#10B981; color:#04130D; border:none; padding:10px; border-radius:6px; font-size:13px; font-weight:700; cursor:pointer; }
  .btn:hover { filter:brightness(1.1); }
</style></head><body>
<div class="card">
  <h2>❖ SAHAND MATRIX</h2>
  <p>Protected Packet & DPI Diagnostic Lab (1h Session / 10m Auto-Stop)</p>
  %s
  <form method="POST" action="%s">
    <input type="hidden" name="cid" value="%s">
    <label>Username</label>
    <input type="text" name="username" required autofocus placeholder="Enter username">
    <label>Password</label>
    <input type="password" name="password" required placeholder="••••••••">
    <div class="math-box">
      <span style="font-size:13px;font-weight:700;color:#7DD3FC;">Security Check: %d + %d = ?</span>
      <input type="number" name="captcha" required placeholder="?" style="width:85px;margin:0;text-align:center;font-weight:700;">
    </div>
    <button class="btn" type="submit">🔓 Unlock Matrix Lab</button>
  </form>
</div></body></html>`
