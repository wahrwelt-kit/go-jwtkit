package jwt

import (
	"encoding/json"
	"log"
	"net/http"
)

// ErrorLogger is used by JWTAuthWithLogger when the service is nil. Implementations should not block (e.g. zerolog.Logger.Error().Msg).
type ErrorLogger interface {
	Error(msg string)
}

// JWTAuth returns chi-style middleware: func(http.Handler) http.Handler. It extracts the Bearer token (via ExtractRaw), validates it with svc.ValidateAccessToken, stores claims in the request context, and calls next. Responds with 401 JSON and WWW-Authenticate: Bearer on missing or invalid token; 500 if svc is nil (logs the misconfiguration). Use as r.Use(jwt.JWTAuth(svc)).
func JWTAuth(svc Service) func(http.Handler) http.Handler {
	return JWTAuthWithLogger(svc, nil)
}

// JWTAuthWithLogger is like JWTAuth but uses errLog for the nil-Service case. When errLog is nil, the standard log package is used.
func JWTAuthWithLogger(svc Service, errLog ErrorLogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if svc == nil {
				if errLog != nil {
					errLog.Error("jwt: JWTAuth nil Service (misconfigured), returning 500")
				} else {
					log.Printf("jwt: JWTAuth nil Service (misconfigured), returning 500")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				if err := json.NewEncoder(w).Encode(map[string]string{"error": "misconfigured auth"}); err != nil {
					_, _ = w.Write([]byte(`{"error":"misconfigured auth"}`))
				}
				return
			}
			token := ExtractRaw(r)
			if token == "" {
				writeUnauthorized(w)
				return
			}
			claims, err := svc.ValidateAccessToken(r.Context(), token)
			if err != nil {
				writeUnauthorized(w)
				return
			}
			ctx := ClaimsIntoContext(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": "not authenticated"}); err != nil {
		_, _ = w.Write([]byte(`{"error":"not authenticated"}`))
	}
}
