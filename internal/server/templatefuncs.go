package server

import (
	"html/template"
	"time"
)

var templateFuncs = template.FuncMap{"fmtTime": fmtTime, "hasScope": hasScope}

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
