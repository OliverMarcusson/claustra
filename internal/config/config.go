package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Issuer                  string
	ListenAddr              string
	DatabaseURL             string
	SigningKeyFile          string
	PreviousSigningKeyFiles []string
	RPID                    string
	RPDisplayName           string
	SecureCookies           bool
	SessionIdleTTL          time.Duration
	SessionAbsoluteTTL      time.Duration
	CodeTTL                 time.Duration
	AccessTokenTTL          time.Duration
	IDTokenTTL              time.Duration
	RecoveryDelay           time.Duration
	DeleteGrace             time.Duration
	SMTP                    SMTP
}

type SMTP struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	StartTLS bool
}

func Load() (Config, error) {
	c := Config{
		Issuer:                  env("CLAUSTRA_ISSUER", "https://claustra.marcusson.dev"),
		ListenAddr:              env("CLAUSTRA_LISTEN_ADDR", "127.0.0.1:13002"),
		DatabaseURL:             os.Getenv("CLAUSTRA_DATABASE_URL"),
		SigningKeyFile:          os.Getenv("CLAUSTRA_SIGNING_KEY_FILE"),
		PreviousSigningKeyFiles: splitCSV(os.Getenv("CLAUSTRA_PREVIOUS_SIGNING_KEY_FILES")),
		RPDisplayName:           env("CLAUSTRA_RP_DISPLAY_NAME", "Claustra"),
		SecureCookies:           envBool("CLAUSTRA_SECURE_COOKIES", true),
		SessionIdleTTL:          30 * 24 * time.Hour,
		SessionAbsoluteTTL:      90 * 24 * time.Hour,
		CodeTTL:                 60 * time.Second,
		AccessTokenTTL:          15 * time.Minute,
		IDTokenTTL:              5 * time.Minute,
		RecoveryDelay:           24 * time.Hour,
		DeleteGrace:             7 * 24 * time.Hour,
		SMTP: SMTP{
			Host: os.Getenv("CLAUSTRA_SMTP_HOST"), Port: envInt("CLAUSTRA_SMTP_PORT", 587),
			Username: os.Getenv("CLAUSTRA_SMTP_USERNAME"), Password: os.Getenv("CLAUSTRA_SMTP_PASSWORD"),
			From: os.Getenv("CLAUSTRA_SMTP_FROM"), StartTLS: envBool("CLAUSTRA_SMTP_STARTTLS", true),
		},
	}

	u, err := url.Parse(c.Issuer)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return Config{}, fmt.Errorf("CLAUSTRA_ISSUER must be an absolute origin without a path")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")) {
		return Config{}, errors.New("CLAUSTRA_ISSUER must use HTTPS except on localhost")
	}
	c.Issuer = strings.TrimSuffix(c.Issuer, "/")
	c.RPID = env("CLAUSTRA_RP_ID", u.Hostname())
	if !strings.EqualFold(c.RPID, u.Hostname()) {
		return Config{}, errors.New("CLAUSTRA_RP_ID must equal the issuer hostname")
	}
	if u.Scheme == "https" && !c.SecureCookies {
		return Config{}, errors.New("CLAUSTRA_SECURE_COOKIES cannot be disabled for an HTTPS issuer")
	}
	if c.DatabaseURL == "" {
		return Config{}, errors.New("CLAUSTRA_DATABASE_URL is required")
	}
	if c.SigningKeyFile == "" {
		return Config{}, errors.New("CLAUSTRA_SIGNING_KEY_FILE is required")
	}
	return c, nil
}

func splitCSV(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
