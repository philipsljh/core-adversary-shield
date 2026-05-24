// context.go
// CN: HTTP 请求上下文工具 | EN: HTTP request context utilities
// CN: 用于在中间件链中传递客户端 IP、用户身份和其他元数据
// EN: Used to pass client IP, user identity and other metadata through middleware chain

package utils

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// CN: ContextKey 为上下文定义类型安全的字符串键 | EN: ContextKey defines type-safe string keys for context
type ContextKey string

const (
	// CN: ClientIPKey 客户端真实 IP 地址的上下文键 | EN: ClientIPKey context key for client real IP address
	ClientIPKey ContextKey = "clientIP"

	// CN: RequestIDKey 请求唯一标识符的上下文键 | EN: RequestIDKey context key for request unique identifier
	RequestIDKey ContextKey = "requestID"
)

// CN: GetContextValue 从请求上下文中安全地提取字符串值
// EN: GetContextValue safely extracts a string value from request context
func GetContextValue(r *http.Request, key ContextKey) string {
	if val, ok := r.Context().Value(key).(string); ok {
		return val
	}
	return ""
}

// CN: ExtractClientIP 从 HTTP 请求中提取客户端真实 IP
// EN: ExtractClientIP extracts client real IP from HTTP request
// CN: 优先级：X-Forwarded-For, X-Real-IP, 然后 RemoteAddr 回退
// EN: Priority: X-Forwarded-For, X-Real-IP, then RemoteAddr fallback
func ExtractClientIP(r *http.Request) string {
	// CN: 1. 尝试 X-Forwarded-For（可能包含多个 IP，取第一个）
	// EN: 1. Try X-Forwarded-For (may contain multiple IPs, take first)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// CN: 2. 尝试 X-Real-IP | EN: 2. Try X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip := strings.TrimSpace(xri)
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	// CN: 3. 回退：从 RemoteAddr 提取（去除端口）| EN: 3. Fallback: extract from RemoteAddr (strip port)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}

	// CN: 4. 最终回退：返回原始 RemoteAddr | EN: 4. Final fallback: return raw RemoteAddr
	return r.RemoteAddr
}

// CN: WithClientIP 将客户端 IP 注入到请求上下文中
// EN: WithClientIP injects client IP into request context
func WithClientIP(r *http.Request, ip string) *http.Request {
	ctx := context.WithValue(r.Context(), ClientIPKey, ip)
	return r.WithContext(ctx)
}

// CN: WithRequestID 将请求 ID 注入到上下文中
// EN: WithRequestID injects request ID into context
func WithRequestID(r *http.Request, id string) *http.Request {
	ctx := context.WithValue(r.Context(), RequestIDKey, id)
	return r.WithContext(ctx)
}
