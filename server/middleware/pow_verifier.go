// pow_verifier.go
// Proof of Work (PoW) verification middleware
// Intercepts illegal requests, forces clients to pay CPU cost, prevents brute force and flood attacks

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

// PoWConfig defines proof of work difficulty parameters and time window
type PoWConfig struct {
	// LeadingZeros requires SHA256 hash prefix zero hex character count
	// 4 characters = 16 bits, average needs 2^16 = 65536 hash attempts
	LeadingZeros int

	// TicketTTL is ticket valid lifetime
	// Tickets beyond this time are rejected, prevents replay attacks
	TicketTTL time.Duration
}

// DefaultPoWConfig returns production recommended default configuration
func DefaultPoWConfig() *PoWConfig {
	return &PoWConfig{
		LeadingZeros: 4,
		TicketTTL:    20 * time.Second,
	}
}

// ticketTracker maintains issued ticket cache, prevents replay attacks and timeout reuse
type ticketTracker struct {
	mu      sync.RWMutex
	issued  map[string]time.Time
	maxSize int
	ttl     time.Duration
}

// newTicketTracker creates capacity-limited ticket tracker
func newTicketTracker(maxSize int, ttl time.Duration) *ticketTracker {
	return &ticketTracker{
		issued:  make(map[string]time.Time),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// MarkIssued marks a ticket as issued
func (tt *ticketTracker) MarkIssued(ticket string) {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	if len(tt.issued) >= tt.maxSize {
		tt.cleanup()
	}

	tt.issued[ticket] = time.Now()
}

// IsValid checks if ticket is valid (issued and not expired)
func (tt *ticketTracker) IsValid(ticket string, ttl time.Duration) bool {
	tt.mu.RLock()
	defer tt.mu.RUnlock()

	issuedAt, exists := tt.issued[ticket]
	if !exists {
		return false
	}

	return time.Since(issuedAt) <= ttl
}

// cleanup removes expired entries (must be called under write lock)
func (tt *ticketTracker) cleanup() {
	now := time.Now()
	for ticket, issuedAt := range tt.issued {
		if now.Sub(issuedAt) > tt.ttl {
			delete(tt.issued, ticket)
		}
	}
}

// globalTicketTracker global ticket tracker instance (100k capacity)
var globalTicketTracker = newTicketTracker(100000, 20*time.Second)

// ============================================================================
// IP-level Rate Limiter (Anti-Flood Protection)
// ============================================================================

// ipCounter tracks per-IP request frequency within a sliding window
type ipCounter struct {
	count     int
	firstSeen time.Time
}

// ipRateLimiter provides high-performance, concurrency-safe per-IP rate limiting
type ipRateLimiter struct {
	mu       sync.RWMutex
	requests map[string]*ipCounter
	maxReqs  int
	window   time.Duration
}

// Allow checks if an IP is allowed to make a request
func (rl *ipRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	counter, exists := rl.requests[ip]

	if !exists || now.Sub(counter.firstSeen) > rl.window {
		// New window or expired window: reset counter
		rl.requests[ip] = &ipCounter{count: 1, firstSeen: now}
		return true
	}

	counter.count++
	if counter.count > rl.maxReqs {
		return false
	}
	return true
}

// CleanupExpiredEntries periodically removes expired entries to prevent memory leak
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

// globalPoWRatelimiter enforces per-IP PoW rate limiting (100 requests per 60 seconds)
var globalPoWRatelimiter = &ipRateLimiter{
	requests: make(map[string]*ipCounter),
	maxReqs:  100,
	window:   60 * time.Second,
}

// Start rate limiter cleanup goroutine
func init() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			globalPoWRatelimiter.CleanupExpiredEntries()
		}
	}()
}

// VerifyPoW proof of work verification middleware
// Extracts Ticket, Nonce and Answer from request headers, verifies SHA256(Ticket + Nonce + Answer) meets leading zero requirement
// Returns 400 Bad Request on failure, does not pass through
func VerifyPoW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := utils.GetContextValue(r, utils.ClientIPKey)

		// Rate limit check: reject flood requests before PoW verification
		if !globalPoWRatelimiter.Allow(clientIP) {
			utils.AdminLog.Warn("POW_RATE_LIMIT",
				"reason", "IP exceeded PoW rate limit",
				"ip", clientIP)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprintf(w, `{"code":429,"msg":"PoW rate limit exceeded, please slow down"}`)
			return
		}

		ticket := r.Header.Get("X-PoW-Ticket")
		nonce := r.Header.Get("X-PoW-Nonce")
		answer := r.Header.Get("X-PoW-Answer")

		if ticket == "" || nonce == "" || answer == "" {
			utils.AdminLog.Warn("POW_MISSING",
				"reason", "missing PoW credentials",
				"ticket_len", len(ticket),
				"nonce_len", len(nonce),
				"answer_len", len(answer),
				"ip", clientIP)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"code":400,"msg":"Missing PoW credentials"}`)
			return
		}

		cfg := DefaultPoWConfig()
		if !globalTicketTracker.IsValid(ticket, cfg.TicketTTL) {
			utils.AdminLog.Warn("POW_TICKET_INVALID",
				"reason", "ticket invalid or expired",
				"ip", clientIP)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"code":400,"msg":"PoW ticket invalid or expired"}`)
			return
		}

		hashInput := ticket + nonce + answer
		hashBytes := sha256.Sum256([]byte(hashInput))
		hashHex := hex.EncodeToString(hashBytes[:])

		expectedPrefix := strings.Repeat("0", cfg.LeadingZeros)
		if !strings.HasPrefix(hashHex, expectedPrefix) {
			utils.AdminLog.Warn("POW_CHALLENGE_FAIL",
				"reason", "PoW challenge failed",
				"hash_prefix", hashHex[:16]+"...",
				"expected_prefix", expectedPrefix,
				"ip", clientIP)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"code":400,"msg":"PoW challenge failed"}`)
			return
		}

		utils.AdminLog.Info("POW_PASS",
			"ticket_prefix", maskTicket(ticket),
			"ip", clientIP)
		next.ServeHTTP(w, r)
	})
}

// VerifyPoWSimple simplified PoW verification (for scenarios without ticket tracking)
// Directly verifies SHA256(Nonce + Answer) meets leading zero requirement
func VerifyPoWSimple(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.Header.Get("X-PoW-Nonce")
		answer := r.Header.Get("X-PoW-Answer")
		clientIP := utils.GetContextValue(r, utils.ClientIPKey)

		if nonce == "" || answer == "" {
			utils.AdminLog.Warn("POW_SIMPLE_MISSING",
				"reason", "missing PoW credentials",
				"ip", clientIP)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"code":400,"msg":"Missing PoW credentials"}`)
			return
		}

		hashBytes := sha256.Sum256([]byte(nonce + answer))
		hashHex := hex.EncodeToString(hashBytes[:])

		cfg := DefaultPoWConfig()
		expectedPrefix := strings.Repeat("0", cfg.LeadingZeros)
		if !strings.HasPrefix(hashHex, expectedPrefix) {
			utils.AdminLog.Warn("POW_SIMPLE_FAIL",
				"reason", "PoW challenge failed",
				"hash_prefix", hashHex[:16]+"...",
				"ip", clientIP)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"code":400,"msg":"PoW challenge failed"}`)
			return
		}

		utils.AdminLog.Info("POW_SIMPLE_PASS",
			"ip", clientIP)
		next.ServeHTTP(w, r)
	})
}

// IssueTicket issues a new PoW Ticket
// Caller should distribute returned ticket to client, client carries this ticket in subsequent requests
func IssueTicket() string {
	ticket := fmt.Sprintf("%d-%08x", time.Now().UnixNano(), uint32(time.Now().Nanosecond()))
	globalTicketTracker.MarkIssued(ticket)
	return ticket
}

// maskTicket sanitizes ticket for logging, keeps only first 16 characters
func maskTicket(ticket string) string {
	if len(ticket) <= 16 {
		return ticket
	}
	return ticket[:16] + "..."
}

func init() {
	cfg := DefaultPoWConfig()
	slog.Info("[PoW] Middleware initialized",
		"leading_zeros", cfg.LeadingZeros,
		"ticket_ttl_sec", cfg.TicketTTL.Seconds(),
		"tracker_capacity", 100000)
}
