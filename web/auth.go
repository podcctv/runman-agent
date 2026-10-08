package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const sessionCookieName = "runman_session"
const sessionLifetime = 12 * time.Hour

type webSession struct {
	expires     time.Time
	credentials [32]byte
}

// Sessions contain opaque tokens, never the submitted password. They expire on
// restart, after twelve hours, or when the configured credentials change.
type webAuthenticator struct {
	credentials func() (string, string)
	mu          sync.Mutex
	sessions    map[[32]byte]webSession
	now         func() time.Time
}

func newWebAuthenticator(credentials func() (string, string)) *webAuthenticator {
	return &webAuthenticator{credentials: credentials, sessions: make(map[[32]byte]webSession), now: time.Now}
}

func credentialVersion(user, hash string) [32]byte {
	return sha256.Sum256([]byte(user + "\x00" + hash))
}

func secureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // Non-browser clients need not send Origin.
	}
	u, err := url.Parse(origin)
	scheme := "http"
	if secureRequest(r) {
		scheme = "https"
	}
	return err == nil && u.Scheme == scheme && strings.EqualFold(u.Host, r.Host) && u.User == nil
}

func safeLoginNext(next string) string {
	u, err := url.Parse(next)
	if err != nil || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") ||
		strings.ContainsAny(next, "\\\r\n") || u.IsAbs() || u.Host != "" || u.Path == "/login" {
		return "/"
	}
	return u.String()
}

func (a *webAuthenticator) authenticated(r *http.Request, user, hash string) bool {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		key := sha256.Sum256([]byte(cookie.Value))
		a.mu.Lock()
		session, ok := a.sessions[key]
		valid := ok && a.now().Before(session.expires) && session.credentials == credentialVersion(user, hash)
		if ok && !valid {
			delete(a.sessions, key)
		}
		a.mu.Unlock()
		if valid {
			return true
		}
	}
	// Keep preemptive Basic Auth for scripts. Browser requests use sessions so
	// cached native-dialog credentials cannot silently undo a sign-out.
	if r.Header.Get("Sec-Fetch-Mode") == "" {
		u, p, ok := r.BasicAuth()
		return ok && u == user && bcrypt.CompareHashAndPassword([]byte(hash), []byte(p)) == nil
	}
	return false
}

func authJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (a *webAuthenticator) login(w http.ResponseWriter, r *http.Request, user, hash string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		authJSON(w, http.StatusForbidden, map[string]string{"error": "origin"})
		return
	}
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		authJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "invalid_request"})
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Next     string `json:"next"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	if err := decoder.Decode(&req); err != nil {
		authJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if user != "" && (req.Username != user || bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil) {
		authJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		return
	}
	if user != "" {
		var random [32]byte
		if _, err := rand.Read(random[:]); err != nil {
			authJSON(w, http.StatusInternalServerError, map[string]string{"error": "unavailable"})
			return
		}
		token := base64.RawURLEncoding.EncodeToString(random[:])
		key := sha256.Sum256([]byte(token))
		a.mu.Lock()
		for k, session := range a.sessions {
			if !a.now().Before(session.expires) || session.credentials != credentialVersion(user, hash) {
				delete(a.sessions, k)
			}
		}
		// Re-login rotates the token, rather than keeping an old session alive.
		if cookie, err := r.Cookie(sessionCookieName); err == nil {
			delete(a.sessions, sha256.Sum256([]byte(cookie.Value)))
		}
		if len(a.sessions) >= 128 {
			var oldestKey [32]byte
			var oldest time.Time
			for k, session := range a.sessions {
				if oldest.IsZero() || session.expires.Before(oldest) {
					oldestKey, oldest = k, session.expires
				}
			}
			delete(a.sessions, oldestKey)
		}
		a.sessions[key] = webSession{expires: a.now().Add(sessionLifetime), credentials: credentialVersion(user, hash)}
		a.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: token, Path: "/", HttpOnly: true,
			Secure: secureRequest(r), SameSite: http.SameSiteStrictMode})
	}
	authJSON(w, http.StatusOK, map[string]string{"redirect": safeLoginNext(req.Next)})
}

func (a *webAuthenticator) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, hash := a.credentials()
		switch r.URL.Path {
		case "/api/auth/login":
			a.login(w, r, user, hash)
			return
		case "/api/auth/logout":
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", "POST")
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if !sameOrigin(r) {
				authJSON(w, http.StatusForbidden, map[string]string{"error": "origin"})
				return
			}
			if cookie, err := r.Cookie(sessionCookieName); err == nil {
				a.mu.Lock()
				delete(a.sessions, sha256.Sum256([]byte(cookie.Value)))
				a.mu.Unlock()
			}
			http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1,
				HttpOnly: true, Secure: secureRequest(r), SameSite: http.SameSiteStrictMode})
			authJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		case "/login", "/logo.png", "/favicon.ico", "/api/vm-status":
			if r.URL.Path == "/login" {
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("X-Frame-Options", "DENY")
				w.Header().Set("Referrer-Policy", "same-origin")
			}
			next.ServeHTTP(w, r)
			return
		}
		if user != "" && !a.authenticated(r, user, hash) {
			if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/rfw/") {
				authJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication_required"})
			} else {
				w.Header().Set("Cache-Control", "no-store")
				http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			}
			return
		}
		if !sameOrigin(r) {
			authJSON(w, http.StatusForbidden, map[string]string{"error": "origin"})
			return
		}
		if r.URL.Path == "/api/auth/session" {
			authJSON(w, http.StatusOK, map[string]any{"username": user, "enabled": user != ""})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
