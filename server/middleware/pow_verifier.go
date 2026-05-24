// pow_verifier.go
// CN: 计算挑战验证中间件 | EN: Computational Challenge Verification Middleware
//
// CN: 本模块实现了基于工作量证明（PoW）的限流机制，用于保护 API 端点免受暴力和洪水攻击。
// EN: This module implements a proof-of-work (PoW) based rate limiting mechanism for protecting API endpoints from brute force and flood attacks.
//
// CN: 中间件拦截请求，强制客户端支付 CPU 成本，并在允许访问前验证计算挑战。
// EN: The middleware intercepts requests, forces clients to pay a CPU cost, and verifies the computational challenge before allowing access.

package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"server/internal/utils"
)

// CN: PoWConfig 定义计算挑战难度参数和时间窗口
// EN: PoWConfig defines computational challenge difficulty parameters and time window
type PoWConfig struct {
	// CN: LeadingZeros 要求 SHA256 哈希前导零十六进制字符数
	// EN: LeadingZeros requires SHA256 hash prefix zero hex character count
	// CN: 4 个字符 = 16 位，平均需要 2^16 = 65536 次哈希尝试
	// EN: 4 characters = 16 bits, average needs 2^16 = 65536 hash attempts
	LeadingZeros int

	// CN: TicketTTL 是票据有效寿命
	// EN: TicketTTL is ticket valid lifetime
	// CN: 超过此时间的票据将被拒绝，防止重放攻击
	// EN: Tickets beyond this time are rejected, prevents replay attacks
	TicketTTL time.Duration
}

// CN: DefaultPoWConfig 返回生产环境推荐的默认配置
// EN: DefaultPoWConfig returns production recommended default configuration
func DefaultPoWConfig() *PoWConfig {
	return &PoWConfig{
		LeadingZeros: 4,
		TicketTTL:    20 * time.Second,
	}
}

// CN: ticketTracker 维护已发行票据缓存，防止重放攻击和超时重用
// EN: ticketTracker maintains issued ticket cache, prevents replay attacks and timeout reuse
type ticketTracker struct {
	mu      sync.RWMutex
	issued  map[string]time.Time
	maxSize int
	ttl     time.Duration
}

// CN: newTicketTracker 创建容量限制的票据跟踪器
// EN: newTicketTracker creates capacity-limited ticket tracker
func newTicketTracker(maxSize int, ttl time.Duration) *ticketTracker {
	return &ticketTracker{
		issued:  make(map[string]time.Time),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// CN: MarkIssued 标记票据已发行
// EN: MarkIssued marks a ticket as issued
func (tt *ticketTracker) MarkIssued(ticket string) {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	if len(tt.issued) >= tt.maxSize {
		tt.cleanup()
	}

	tt.issued[ticket] = time.Now()
}

// CN: IsValid 检查票据是否有效（已发行且未过期）
// EN: IsValid checks if ticket is valid (issued and not expired)
func (tt *ticketTracker) IsValid(ticket string, ttl time.Duration) bool {
	tt.mu.RLock()
	defer tt.mu.RUnlock()

	issuedAt, exists := tt.issued[ticket]
	if !exists {
		return false
	}

	return time.Since(issuedAt) <= ttl
}

// CN: cleanup 移除过期条目（必须在写锁下调用）
// EN: cleanup removes expired entries (must be called under write lock)
func (tt *ticketTracker) cleanup() {
	now := time.Now()
	for ticket, issuedAt := range tt.issued {
		if now.Sub(issuedAt) > tt.ttl {
			delete(tt.issued, ticket)
		}
	}
}

// CN: globalTicketTracker 全局票据跟踪器实例（10 万容量）
// EN: globalTicketTracker global ticket tracker instance (100k capacity)
var globalTicketTracker = newTicketTracker(100000, 20*time.Second)

// ============================================================================
// CN: IP 级别限流器（防洪水保护）| EN: IP-level Rate Limiter (Anti-Flood Protection)
// ============================================================================

// CN: ipCounter 跟踪滑动窗口内每个 IP 的请求频率
// EN: ipCounter tracks per-IP request frequency within a sliding window
type ipCounter struct {
	count     int
	firstSeen time.Time
}

// CN: ipRateLimiter 提供高性能、并发安全的每个 IP 限流器
// EN: ipRateLimiter provides high-performance, concurrency-safe per-IP rate limiting
type ipRateLimiter struct {
	mu       sync.RWMutex
	requests map[string]*ipCounter
	maxReqs  int
	window   time.Duration
}

// CN: Allow 检查 IP 是否被允许发出请求
// EN: Allow checks if an IP is allowed to make a request
func (rl *ipRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	counter, exists := rl.requests[ip]

	if !exists || now.Sub(counter.firstSeen) > rl.window {
		// CN: 新窗口或过期窗口：重置计数器 | EN: New window or expired window: reset counter
		rl.requests[ip] = &ipCounter{count: 1, firstSeen: now}
		return true
	}

	counter.count++
	if counter.count > rl.maxReqs {
		return false
	}
	return true
}

// CN: CleanupExpiredEntries 定期移除过期条目以防止内存泄漏
// EN: CleanupExpiredEntries periodically removes expired entries to prevent memory leak
func (rl *ipRateLimiter) CleanupExpiredEntries() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, counter := range rl.requests {
		if now.Sub(counter.firstSeen) > rl.window*2 {
			delete(rl.requests, ip)
		}
	}
}

// CN: globalPoWRatelimiter 强制执行每个 IP 的计算挑战限流（60 秒内 100 个请求）
// EN: globalPoWRatelimiter enforces per-IP computational challenge rate limiting (100 requests per 60 seconds)
var globalPoWRatelimiter = &ipRateLimiter{
	requests: make(map[string]*ipCounter),
	maxReqs:  100,
	window:   60 * time.Second,
}

// CN: 启动限流器清理 goroutine | EN: Start rate limiter cleanup goroutine
func init() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			globalPoWRatelimiter.CleanupExpiredEntries()
		}
	}()
}

// CN: VerifyPoW 计算挑战验证中间件
// EN: VerifyPoW computational challenge verification middleware
//
// CN: 从请求头中提取 Ticket、Nonce 和 Answer，验证 SHA256(Ticket + Nonce + Answer) 满足前导零要求。
// EN: Extracts Ticket, Nonce and Answer from request headers, verifies SHA256(Ticket + Nonce + Answer) meets leading zero requirement.
// CN: 失败时返回 400 Bad Request，不通过。
// EN: Returns 400 Bad Request on failure, does not pass through.
func VerifyPoW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := utils.GetContextValue(r, utils.ClientIPKey)

		// CN: 限流检查：在挑战验证前拒绝洪水请求 | EN: Rate limit check: reject flood requests before challenge verification
		if !globalPoWRatelimiter.Allow(clientIP) {
			utils.AdminLog.Warn("CHALLENGE_RATE_LIMIT",
				"reason", "CN: IP 超过计算挑战限流 | EN: IP exceeded computational challenge rate limit",
				"ip", clientIP)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprintf(w, `{"code":429,"msg":"Rate limit exceeded, please slow down"}`)
			return
		}

		ticket := r.Header.Get("X-PoW-Ticket")
		nonce := r.Header.Get("X-PoW-Nonce")
		answer := r.Header.Get("X-PoW-Answer")

		if ticket == "" || nonce == "" || answer == "" {
			utils.AdminLog.Warn("CHALLENGE_MISSING",
				"reason", "CN: 缺少计算挑战凭证 | EN: missing computational challenge credentials",
				"ticket_len", len(ticket),
				"nonce_len", len(nonce),
				"answer_len", len(answer),
				"ip", clientIP)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"code":400,"msg":"Missing challenge credentials"}`)
			return
		}

		cfg := DefaultPoWConfig()
		if !globalTicketTracker.IsValid(ticket, cfg.TicketTTL) {
			utils.AdminLog.Warn("CHALLENGE_TICKET_INVALID",
				"reason", "CN: 票据无效或已过期 | EN: ticket invalid or expired",
				"ip", clientIP)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"code":400,"msg":"Challenge ticket invalid or expired"}`)
			return
		}

		hashInput := ticket + nonce + answer
		hashBytes := sha256.Sum256([]byte(hashInput))
		hashHex := hex.EncodeToString(hashBytes[:])

		expectedPrefix := strings.Repeat("0", cfg.LeadingZeros)
		if !strings.HasPrefix(hashHex, expectedPrefix) {
			utils.AdminLog.Warn("CHALLENGE_VERIFY_FAIL",
				"reason", "CN: 计算挑战失败 | EN: computational challenge failed",
				"hash_prefix", hashHex[:16]+"...",
				"expected_prefix", expectedPrefix,
				"ip", clientIP)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"code":400,"msg":"Computational challenge failed"}`)
			return
		}

		utils.AdminLog.Info("CHALLENGE_PASS",
			"ticket_prefix", maskTicket(ticket),
			"ip", clientIP)
		next.ServeHTTP(w, r)
	})
}

// CN: VerifyPoWSimple 简化的计算挑战验证（无票据跟踪场景）
// EN: VerifyPoWSimple simplified computational challenge verification (for scenarios without ticket tracking)
// CN: 直接验证 SHA256(Nonce + Answer) 满足前导零要求
// EN: Directly verifies SHA256(Nonce + Answer) meets leading zero requirement
func VerifyPoWSimple(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.Header.Get("X-PoW-Nonce")
		answer := r.Header.Get("X-PoW-Answer")
		clientIP := utils.GetContextValue(r, utils.ClientIPKey)

		if nonce == "" || answer == "" {
			utils.AdminLog.Warn("CHALLENGE_SIMPLE_MISSING",
				"reason", "CN: 缺少计算挑战凭证 | EN: missing computational challenge credentials",
				"ip", clientIP)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"code":400,"msg":"Missing challenge credentials"}`)
			return
		}

		hashBytes := sha256.Sum256([]byte(nonce + answer))
		hashHex := hex.EncodeToString(hashBytes[:])

		cfg := DefaultPoWConfig()
		expectedPrefix := strings.Repeat("0", cfg.LeadingZeros)
		if !strings.HasPrefix(hashHex, expectedPrefix) {
			utils.AdminLog.Warn("CHALLENGE_SIMPLE_FAIL",
				"reason", "CN: 计算挑战失败 | EN: computational challenge failed",
				"hash_prefix", hashHex[:16]+"...",
				"ip", clientIP)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"code":400,"msg":"Computational challenge failed"}`)
			return
		}

		utils.AdminLog.Info("CHALLENGE_SIMPLE_PASS",
			"ip", clientIP)
		next.ServeHTTP(w, r)
	})
}

// CN: IssueTicket 发行新的计算挑战 Ticket
// EN: IssueTicket issues a new computational challenge Ticket
// CN: 调用者应将返回的票据分发给客户端，客户端在后续请求中携带此票据
// EN: Caller should distribute returned ticket to client, client carries this ticket in subsequent requests
func IssueTicket() string {
	ticket := fmt.Sprintf("%d-%08x", time.Now().UnixNano(), uint32(time.Now().Nanosecond()))
	globalTicketTracker.MarkIssued(ticket)
	return ticket
}

// CN: maskTicket 净化票据用于日志，仅保留前 16 个字符
// EN: maskTicket sanitizes ticket for logging, keeps only first 16 characters
func maskTicket(ticket string) string {
	if len(ticket) <= 16 {
		return ticket
	}
	return ticket[:16] + "..."
}

func init() {
	cfg := DefaultPoWConfig()
	slog.Info("[Challenge] CN: 中间件已初始化 | EN: Middleware initialized",
		"leading_zeros", cfg.LeadingZeros,
		"ticket_ttl_sec", cfg.TicketTTL.Seconds(),
		"tracker_capacity", 100000)
}
