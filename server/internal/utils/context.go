// context.go
// HTTP request context utilities
// Used to pass client IP, user identity and other metadata through middleware chain

package utils

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// ContextKey defines type-safe string keys for context
type ContextKey string

const (
	// ClientIPKey context key for client real IP address
	ClientIPKey ContextKey = "clientIP"

	// RequestIDKey context key for request unique identifier
	RequestIDKey ContextKey = "requestID"
)

// GetContextValue safely extracts a string value from request context
func GetContextValue(r *http.Request, key ContextKey) string {
	if val, ok := r.Context().Value(key).(string); ok {
		return val
	}
	return ""
}

// ExtractClientIP extracts client real IP from HTTP request
// Priority: X-Forwarded-For, X-Real-IP, then RemoteAddr fallback
func ExtractClientIP(r *http.Request) string {
	// 1. Try X-Forwarded-For (may contain multiple IPs, take first)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// 2. Try X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip := strings.TrimSpace(xri)
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	// 3. Fallback: extract from RemoteAddr (strip port)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}

	// 4. Final fallback: return raw RemoteAddr
	return r.RemoteAddr
}

// WithClientIP injects client IP into request context
func WithClientIP(r *http.Request, ip string) *http.Request {
	ctx := context.WithValue(r.Context(), ClientIPKey, ip)
	return r.WithContext(ctx)
}

// WithRequestID injects request ID into context
func WithRequestID(r *http.Request, id string) *http.Request {
	ctx := context.WithValue(r.Context(), RequestIDKey, id)
	return r.WithContext(ctx)
}
