package web

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func authFixture(t *testing.T) (*webAuthenticator, http.Handler, *string) {
	t.Helper()
	encoded, err := bcrypt.GenerateFromPassword([]byte("test-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	hash := string(encoded)
	auth := newWebAuthenticator(func() (string, string) { return "admin", hash })
	handler := auth.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("protected or public content"))
	}))
	return auth, handler, &hash
}

func loginRequest(handler http.Handler, next string, cookie *http.Cookie) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "test-password", "next": next})
	r := httptest.NewRequest("POST", "http://console.test/api/auth/login", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://console.test")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestGuestRoutesDoNotOpenBrowserAuthPrompt(t *testing.T) {
	_, handler, _ := authFixture(t)
	for _, test := range []struct {
		path   string
		status int
	}{
		{"/", 303}, {"/index.html", 303}, {"/login.html", 303},
		{"/api/config", 401}, {"/api/auth/session", 401}, {"/rfw/api/rules", 401},
		{"/api/vms/example/tty", 401}, {"/login", 200}, {"/logo.png", 200}, {"/favicon.ico", 200},
		{"/api/vm-status", 200},
	} {
		t.Run(test.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("GET", test.path, nil))
			if w.Code != test.status || w.Header().Get("WWW-Authenticate") != "" {
				t.Fatalf("status=%d, challenge=%q", w.Code, w.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

func TestLoginIssuesOpaqueSessionAndLogoutRevokesIt(t *testing.T) {
	_, handler, _ := authFixture(t)
	login := loginRequest(handler, "/?tab=instances", nil)
	if login.Code != 200 || !strings.Contains(login.Body.String(), "/?tab=instances") {
		t.Fatal(login.Code, login.Body.String())
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing session cookie")
	}
	cookie := cookies[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" ||
		cookie.MaxAge != 0 || !cookie.Expires.IsZero() || strings.Contains(cookie.Value, "password") {
		t.Fatal("session cookie policy", cookie)
	}
	for _, path := range []string{"/", "/api/config", "/api/vms/example/tty", "/rfw/api/rules"} {
		r := httptest.NewRequest("GET", "http://console.test"+path, nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(path, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "http://console.test/api/auth/logout", nil)
	r.AddCookie(cookie)
	r.Header.Set("Origin", "http://console.test")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 200 || w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("logout did not clear cookie")
	}
	r = httptest.NewRequest("GET", "/api/config", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("revoked session still works")
	}
}

func TestSessionsExpireRotateAndFollowCredentialChanges(t *testing.T) {
	for _, action := range []string{"expiry", "password", "rotation", "restart", "tamper"} {
		t.Run(action, func(t *testing.T) {
			a, handler, hash := authFixture(t)
			cookie := loginRequest(handler, "/", nil).Result().Cookies()[0]
			switch action {
			case "expiry":
				future := a.now().Add(sessionLifetime + time.Minute)
				a.now = func() time.Time { return future }
			case "password":
				*hash = "changed-password-hash"
			case "rotation":
				loginRequest(handler, "/", cookie)
			case "restart":
				a.sessions = make(map[[32]byte]webSession)
			case "tamper":
				cookie.Value += "x"
			}
			r := httptest.NewRequest("GET", "/api/auth/session", nil)
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != 401 {
				t.Fatal(action, "old session remained authorized")
			}
		})
	}
}

func TestLoginRejectsBadRequestsAndCrossOrigin(t *testing.T) {
	_, handler, _ := authFixture(t)
	for _, test := range []struct {
		method, contentType, origin, body string
		status                            int
	}{
		{"GET", "", "", "", 405},
		{"POST", "text/plain", "", `{}`, 415},
		{"POST", "application/json", "http://evil.test", `{}`, 403},
		{"POST", "application/json", "", `{broken`, 400},
		{"POST", "application/json", "", `{"username":"admin","password":"wrong"}`, 401},
		{"POST", "application/json", "", `{"username":"wrong","password":"test-password"}`, 401},
		{"POST", "application/json", "", strings.Repeat(" ", 4097) + `{}`, 400},
	} {
		r := httptest.NewRequest(test.method, "http://console.test/api/auth/login", strings.NewReader(test.body))
		r.Header.Set("Content-Type", test.contentType)
		r.Header.Set("Origin", test.origin)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != test.status || len(w.Result().Cookies()) != 0 {
			t.Fatalf("status %d, want %d: %s", w.Code, test.status, w.Body.String())
		}
	}
}

func TestCrossOriginRequestsCannotUseSession(t *testing.T) {
	_, handler, _ := authFixture(t)
	cookie := loginRequest(handler, "/", nil).Result().Cookies()[0]
	for _, path := range []string{"/api/config", "/api/vms/example/tty", "/api/auth/logout"} {
		r := httptest.NewRequest("POST", "http://console.test"+path, nil)
		r.AddCookie(cookie)
		r.Header.Set("Origin", "http://evil.test")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(path, w.Code)
		}
	}
}

func TestScriptBasicAuthAndBrowserSessions(t *testing.T) {
	_, handler, _ := authFixture(t)
	for _, mode := range []string{"", "navigate", "cors", "websocket"} {
		r := httptest.NewRequest("GET", "/api/config", nil)
		r.SetBasicAuth("admin", "test-password")
		r.Header.Set("Sec-Fetch-Mode", mode)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		want := 401
		if mode == "" {
			want = 200
		}
		if w.Code != want {
			t.Fatal(mode, w.Code)
		}
	}
}

func TestSecureCookiesDirectAndBehindProxy(t *testing.T) {
	for _, proxy := range []bool{false, true} {
		_, handler, _ := authFixture(t)
		r := httptest.NewRequest("POST", "https://console.test/api/auth/login", strings.NewReader(`{"username":"admin","password":"test-password"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://console.test")
		if proxy {
			r.TLS = nil
			r.Header.Set("X-Forwarded-Proto", "https")
		} else {
			r.TLS = &tls.ConnectionState{}
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 200 || !w.Result().Cookies()[0].Secure {
			t.Fatal("HTTPS cookie not secure", proxy)
		}
	}
}

func TestSafeLoginNext(t *testing.T) {
	for _, next := range []string{"", "https://evil.test", "//evil.test", "/\\evil.test", "/login", "/\r\nevil.test"} {
		if safeLoginNext(next) != "/" {
			t.Fatal("unsafe redirect accepted", next)
		}
	}
	if safeLoginNext("/?tab=instances#details") != "/?tab=instances#details" {
		t.Fatal("local destination lost")
	}
}

func TestNoCredentialsStillAllowsExistingOpenMode(t *testing.T) {
	a := newWebAuthenticator(func() (string, string) { return "", "" })
	handler := a.wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
}

func TestSessionTokensAreStoredHashedAndBounded(t *testing.T) {
	a, handler, _ := authFixture(t)
	for range 130 {
		if w := loginRequest(handler, "/", nil); w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	if len(a.sessions) != 128 {
		t.Fatal("session map is unbounded", len(a.sessions))
	}
	cookie := loginRequest(handler, "/", nil).Result().Cookies()[0]
	if _, ok := a.sessions[sha256.Sum256([]byte(cookie.Value))]; !ok {
		t.Fatal("session token not hashed")
	}
}

// Optional local browser verification uses the real authentication middleware,
// real static pages and fixture dashboard data; it never contacts a VPS.
func TestBrowserLogin(t *testing.T) {
	if os.Getenv("RUNMAN_TEST_BROWSER") != "1" {
		t.Skip("set RUNMAN_TEST_BROWSER=1 to run browser checks")
	}
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(file))
	hash, err := bcrypt.GenerateFromPassword([]byte("test-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	a := newWebAuthenticator(func() (string, string) { return "admin", string(hash) })
	server := httptest.NewServer(a.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.ServeFile(w, r, filepath.Join(root, "web", "static", "login.html"))
		case "/":
			http.ServeFile(w, r, filepath.Join(root, "web", "static", "index.html"))
		case "/logo.png", "/favicon.ico":
			http.ServeFile(w, r, filepath.Join(root, "web", "static", filepath.Base(r.URL.Path)))
		case "/api/system/info":
			authJSON(w, 200, map[string]any{"nics": []string{"eth0"}, "disks": []string{"/"}})
		case "/api/images", "/api/vms", "/rfw/api/rules":
			authJSON(w, 200, []any{})
		default:
			authJSON(w, 200, map[string]any{})
		}
	})))
	defer server.Close()
	cmd := exec.Command("node", filepath.Join(root, "tests", "test_login_ui.cjs"), server.URL)
	output, err := cmd.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal(err)
	}
}
