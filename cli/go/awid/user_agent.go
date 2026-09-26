package awid

import (
	"net/http"
	"strings"
	"sync/atomic"
)

// defaultUserAgent identifies the calling program on requests that set no
// User-Agent of their own. The aw binary sets it at startup so the server can
// tell which CLI versions are in use; library consumers may leave it empty,
// in which case Go's default applies as before.
var defaultUserAgent atomic.Value // string

// SetDefaultUserAgent sets the User-Agent used when a request has no more
// specific one (such as a delegate's SetUserAgent).
func SetDefaultUserAgent(userAgent string) {
	defaultUserAgent.Store(strings.TrimSpace(userAgent))
}

// DefaultUserAgent returns the process-wide default User-Agent, or "".
func DefaultUserAgent() string {
	value, _ := defaultUserAgent.Load().(string)
	return value
}

// setUserAgent sets override when non-empty, else the default when set.
func setUserAgent(req *http.Request, override string) {
	userAgent := strings.TrimSpace(override)
	if userAgent == "" {
		userAgent = DefaultUserAgent()
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
}
