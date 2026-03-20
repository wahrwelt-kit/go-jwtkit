package jwtkit

import (
	"encoding/json"
	"net/http"

	logger "github.com/takuya-go-kit/go-logkit"
)

// MiddlewareOption configures JWTAuth (e.g. custom error response via WithErrorHandler, logging via WithLogger).
type MiddlewareOption func(*middlewareConfig)

type middlewareConfig struct {
	errorHandler func(w http.ResponseWriter, r *http.Request, err error, status int)
	logger       logger.Logger
}

// WithErrorHandler sets a custom handler for auth errors (missing/invalid token or nil service).
// status is http.StatusUnauthorized (401) for missing or invalid token, or http.StatusInternalServerError (500) for nil service.
// If not set, the middleware uses default JSON error responses and WWW-Authenticate: Bearer for 401.
func WithErrorHandler(fn func(w http.ResponseWriter, r *http.Request, err error, status int)) MiddlewareOption {
	return func(c *middlewareConfig) { c.errorHandler = fn }
}

// WithLogger sets the logger for the middleware. Used to log nil-Service misconfiguration (500 response).
func WithLogger(l logger.Logger) MiddlewareOption {
	return func(c *middlewareConfig) { c.logger = l }
}

// JWTAuth returns chi-style middleware: func(http.Handler) http.Handler.
// It extracts the Bearer token via ExtractRaw, validates it with svc.ValidateAccessToken,
// stores claims in the request context, and calls next.
// On missing or invalid token responds with 401 JSON and WWW-Authenticate: Bearer; on nil svc responds with 500 and logs via WithLogger.
// Use as r.Use(jwtkit.JWTAuth(svc)) or r.With(jwtkit.JWTAuth(svc, jwtkit.WithLogger(log))).Handle(...).
func JWTAuth(svc Service, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	var cfg middlewareConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if svc == nil {
				if cfg.logger != nil {
					cfg.logger.Error("jwt: JWTAuth nil Service (misconfigured), returning 500")
				}
				if cfg.errorHandler != nil {
					cfg.errorHandler(w, r, nil, http.StatusInternalServerError)
				} else {
					writeError(w, http.StatusInternalServerError, "misconfigured auth")
				}
				return
			}
			token := ExtractRaw(r)
			if token == "" {
				if cfg.errorHandler != nil {
					cfg.errorHandler(w, r, nil, http.StatusUnauthorized)
				} else {
					writeUnauthorized(w)
				}
				return
			}
			claims, err := svc.ValidateAccessToken(r.Context(), token)
			if err != nil {
				if cfg.errorHandler != nil {
					cfg.errorHandler(w, r, err, http.StatusUnauthorized)
				} else {
					writeUnauthorized(w)
				}
				return
			}
			ctx := ClaimsIntoContext(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeError(w, http.StatusUnauthorized, "not authenticated")
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, err := json.Marshal(map[string]string{"error": message})
	if err != nil {
		return
	}
	_, _ = w.Write(b)
}
