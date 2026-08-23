package server

import (
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"time"
)

var templateFuncs = template.FuncMap{"fmtTime": fmtTime, "hasScope": hasScope, "asset": asset}

// Cloudflare caches /static for hours and replaces the origin's max-age with
// its own, so a deployed change to the stylesheet or the passkey script keeps
// serving the previous build until that expires - long enough for a fix to
// look like it did not work. The URL carries a hash of the content instead: a
// change is a new cache key, an unchanged asset stays cached, and only the
// HTML has to be fresh for it to take, which it always is since pages are
// sent no-store.
//
// The button kit is deliberately absent. Relying parties embed that URL in
// their own pages and it is not ours to change from under them.
var assetVersions = map[string]string{
	"/static/claustra.css": assetVersion(claustraCSS),
	"/static/passkey.js":   assetVersion(passkeyJS),
	"/static/mark.svg":     assetVersion(markSVG),
}

func assetVersion(content string) string {
	sum := sha256.Sum256([]byte(content))
	return base64.RawURLEncoding.EncodeToString(sum[:])[:10]
}

// asset returns the URL a page should reference for a static file.
func asset(path string) string {
	if version, ok := assetVersions[path]; ok {
		return path + "?v=" + version
	}
	return path
}

// fmtTime renders the timestamps the pages show. Absent optional times, such
// as a passkey that has never been used, read as "never" rather than a zero date.
func fmtTime(value any) string {
	switch v := value.(type) {
	case time.Time:
		return formatTime(v)
	case *time.Time:
		if v == nil {
			return "never"
		}
		return formatTime(*v)
	default:
		return "never"
	}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format("2 Jan 2006, 15:04 UTC")
}
