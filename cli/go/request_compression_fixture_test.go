package aweb

import "net/http"

// Existing request fixtures model a server without request-gzip support.
func serveUnadvertisedHealth(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet && (r.URL.Path == "/health" || r.URL.Path == "/api/health") {
		w.WriteHeader(http.StatusNotFound)
		return true
	}
	return false
}
