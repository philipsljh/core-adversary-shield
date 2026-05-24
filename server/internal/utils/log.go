// log.go
// Global log router and sanitization logger
// Provides AdminLog global logger instance with request context binding

package utils

import (
	"log/slog"
	"net/http"
	"os"
)

var (
	// AdminLog global managed logger instance
	// Production should use file-rotating, level-filtering structured logger
	AdminLog *slog.Logger
)

func init() {
	// Initialize structured logger
	opts := &slog.HandlerOptions{
		Level:     slog.LevelInfo,
		AddSource: false,
	}

	handler := slog.NewTextHandler(os.Stdout, opts)
	AdminLog = slog.New(handler)

	AdminLog.Info("[Utils] AdminLog initialized",
		"level", "INFO",
		"handler", "TextHandler")
}

// RequestLogger binds context-aware logger for specific HTTP request
// Auto-injects requestID, clientIP and other fields
func RequestLogger(r *http.Request) *slog.Logger {
	requestID := GetContextValue(r, RequestIDKey)
	clientIP := GetContextValue(r, ClientIPKey)

	if requestID != "" && clientIP != "" {
		return AdminLog.With(
			"request_id", requestID,
			"client_ip", clientIP,
		)
	}

	return AdminLog
}

// LogRequest logs request start
func LogRequest(r *http.Request, method, path string) {
	logger := RequestLogger(r)
	logger.Info("REQUEST_START",
		"method", method,
		"path", path,
		"user_agent", r.UserAgent())
}

// LogResponse logs response completion
func LogResponse(r *http.Request, method, path string, statusCode int, durationMs int64) {
	logger := RequestLogger(r)
	logger.Info("REQUEST_END",
		"method", method,
		"path", path,
		"status", statusCode,
		"duration_ms", durationMs)
}
