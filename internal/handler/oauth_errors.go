package handler

import (
	"github.com/ledatu/csar-core/httpx"
	"net/http"
)

func oauthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, status, map[string]string{"error": code})
}
