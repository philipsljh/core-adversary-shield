// log.go
// CN: 全局日志路由器和净化日志记录器 | EN: Global log router and sanitization logger
// CN: 提供 AdminLog 全局日志器实例，支持请求上下文绑定
// EN: Provides AdminLog global logger instance with request context binding

package utils

import (
	"log/slog"
	"net/http"
	"os"
)

var (
	// CN: AdminLog 全局托管日志器实例 | EN: AdminLog global managed logger instance
	// CN: 生产环境应使用文件轮转、级别过滤的结构化日志器
	// EN: Production should use file-rotating, level-filtering structured logger
	AdminLog *slog.Logger
)

func init() {
	// CN: 初始化结构化日志器 | EN: Initialize structured logger
	opts := &slog.HandlerOptions{
		Level:     slog.LevelInfo,
		AddSource: false,
	}

	handler := slog.NewTextHandler(os.Stdout, opts)
	AdminLog = slog.New(handler)

	AdminLog.Info("[Utils] CN: AdminLog 已初始化 | EN: AdminLog initialized",
		"level", "INFO",
		"handler", "TextHandler")
}

// CN: RequestLogger 为特定 HTTP 请求绑定上下文感知的日志器
// EN: RequestLogger binds context-aware logger for specific HTTP request
// CN: 自动注入 requestID、clientIP 和其他字段
// EN: Auto-injects requestID, clientIP and other fields
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

// CN: LogRequest 记录请求开始 | EN: LogRequest logs request start
func LogRequest(r *http.Request, method, path string) {
	logger := RequestLogger(r)
	logger.Info("REQUEST_START",
		"method", method,
		"path", path,
		"user_agent", r.UserAgent())
}

// CN: LogResponse 记录响应完成 | EN: LogResponse logs response completion
func LogResponse(r *http.Request, method, path string, statusCode int, durationMs int64) {
	logger := RequestLogger(r)
	logger.Info("REQUEST_END",
		"method", method,
		"path", path,
		"status", statusCode,
		"duration_ms", durationMs)
}
