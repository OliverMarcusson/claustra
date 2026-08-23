package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

func RandomToken(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func RandomBytes(bytes int) ([]byte, error) {
	value := make([]byte, bytes)
	_, err := rand.Read(value)
	return value, err
}

func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func CSRF(sessionToken, purpose string) string {
	sum := sha256.Sum256([]byte("claustra-csrf\x00" + purpose + "\x00" + sessionToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func ValidateCSRF(sessionToken, purpose, value string) bool {
	expected := CSRF(sessionToken, purpose)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(value)) == 1
}

func LoadRSAKey(path string) (*rsa.PrivateKey, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, "", errors.New("signing key is not PEM")
	}
	var key *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, "", errors.New("signing key is not RSA")
		}
	} else {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("parse signing key: %w", err)
		}
	}
	if key.N.BitLen() < 2048 {
		return nil, "", errors.New("signing key must be at least 2048 bits")
	}
	der := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	sum := sha256.Sum256(der)
	kid := base64.RawURLEncoding.EncodeToString(sum[:12])
	return key, kid, nil
}

func GenerateRSAKey(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("refusing to overwrite %s", path)
	} else if !os.IsNotExist(err) {
		return err
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600)
}

func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); net.ParseIP(forwarded) != nil {
			return forwarded
		}
	}
	return host
}

type window struct {
	Start time.Time
	Count int
}
type Limiter struct {
	mu       sync.Mutex
	windows  map[string]window
	limit    int
	duration time.Duration
}

func NewLimiter(limit int, duration time.Duration) *Limiter {
	return &Limiter{windows: map[string]window{}, limit: limit, duration: duration}
}
func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.windows[key]
	if now.Sub(w.Start) >= l.duration {
		w = window{Start: now}
	}
	w.Count++
	l.windows[key] = w
	if len(l.windows) > 10000 {
		for k, v := range l.windows {
			if now.Sub(v.Start) > l.duration {
				delete(l.windows, k)
			}
		}
	}
	return w.Count <= l.limit
}
