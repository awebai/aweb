package aweb

import (
	"net/http"
	"strings"
)

// Existing request fixtures model a server without request-gzip support.
func serveUnadvertisedHealth(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/health") {
		w.WriteHeader(http.StatusNotFound)
		return true
	}
	return false
}
