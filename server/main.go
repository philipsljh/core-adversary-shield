// main.go
// Enterprise Policy Orchestration Server - Entry Point
//
// This server implements a zero-trust policy orchestration framework with:
// - Onion-model middleware pipeline (BaseInfo -> VerifyPoW -> Ticket)
// - Ed25519 blind oracle digital signature issuance
// - SQLite WAL industrial-grade deadlock-free write shell with exponential backoff
//
// Start:
//   go run main.go
//
// Production:
//   go build -o server && ./server
//
// Dev mode (for testing only):
//   POLICY_SERVER_DEV_MODE=1 go run main.go

package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"server/internal/utils"
	"server/middleware"
)

// ============================================================================
// Middleware: extract client IP
// ============================================================================

// BaseInfoMiddleware extracts real client IP and injects into context
// This is the first layer of the onion-model middleware pipeline
func BaseInfoMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := utils.ExtractClientIP(r)
		r = utils.WithClientIP(r, clientIP)
		next.ServeHTTP(w, r)
	})
}

// ============================================================================
// Business Handler
// ============================================================================

// Handler defines business processors for policy orchestration
type Handler struct{}

// HandleGetTicket returns PoW Ticket to client
// This endpoint issues a computational challenge for rate limiting
func (h *Handler) HandleGetTicket(w http.ResponseWriter, r *http.Request) {
	clientIP := utils.GetContextValue(r, utils.ClientIPKey)

	ticket := middleware.IssueTicket()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"code":   "0",
		"msg":    "success",
		"ticket": ticket,
		"ip":     clientIP,
	})
}

// HeartbeatRequest heartbeat request structure
type HeartbeatRequest struct {
	Username     string `json:"username"`
	Nonce        string `json:"nonce"`
	SessionToken string `json:"session_token"`
}

// HandleHeartbeat heartbeat endpoint: returns Ed25519 oracle signature
// Dynamically extracts parameters from request body
func (h *Handler) HandleHeartbeat(w http.ResponseWriter, r *http.Request) {
	clientIP := utils.GetContextValue(r, utils.ClientIPKey)

	var req HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"code":400,"msg":"Invalid request body"}`)
		return
	}

	if req.Username == "" || req.Nonce == "" || req.SessionToken == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"code":400,"msg":"Missing required fields: username, nonce, session_token"}`)
		return
	}

	expireTime := time.Now().Add(5 * time.Minute).Unix()

	// Load policy hash from environment variable to avoid static feature exposure
	policyHash := os.Getenv("POLICY_SERVER_RESOURCE_HASH")
	if policyHash == "" {
		slog.Warn("[Heartbeat] POLICY_SERVER_RESOURCE_HASH not set, using noise placeholder. " +
			"Production MUST set this environment variable to the actual resource bytecode hash.")
		policyHash = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	signature, err := middleware.SignOracle(req.Username, req.Nonce, expireTime, policyHash)
	if err != nil {
		utils.AdminLog.Error("ORACLE_SIGN_FAIL",
			"error", err,
			"ip", clientIP)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"code":500,"msg":"Signature generation failed"}`)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"code":             "0",
		"msg":              "success",
		"server_sign":      signature,
		"nonce":            req.Nonce,
		"expire_timestamp": fmt.Sprintf("%d", expireTime),
		"resource_hash":    policyHash,
	})

	utils.AdminLog.Info("ORACLE_SIGN_SUCCESS",
		"username", req.Username,
		"ip", clientIP)
}

// HandleHealth health check endpoint
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"code":0,"msg":"ok","timestamp":%d}`, time.Now().Unix())
}

// ============================================================================
// Main function
// ============================================================================

func main() {
	slog.Info("========================================")
	slog.Info("Enterprise Policy Orchestration Server - Starting")
	slog.Info("========================================")

	pubKey := middleware.GetOraclePublicKey()
	if pubKey == "" {
		slog.Error("[Main] FATAL: Oracle Signer not ready. " +
			"Set POLICY_SERVER_ED25519_PRIVATE_KEY (production) or POLICY_SERVER_DEV_MODE=1 (development)")
		slog.Error("[Main] Server exiting.")
		return
	}
	slog.Info("[Main] Oracle Signer ready", "public_key_prefix", pubKey[:16]+"...")

	handler := &Handler{}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", handler.HandleHealth)

	// Onion-model middleware pipeline: BaseInfo -> Handler
	mux.Handle("/api/v1/pow/ticket",
		BaseInfoMiddleware(http.HandlerFunc(handler.HandleGetTicket)))

	// Onion-model middleware pipeline: BaseInfo -> VerifyPoW -> Handler
	mux.Handle("/api/v1/auth/heartbeat",
		BaseInfoMiddleware(
			middleware.VerifyPoW(
				http.HandlerFunc(handler.HandleHeartbeat),
			),
		))

	addr := ":8080"
	slog.Info("[Main] HTTP server listening", "addr", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("[Main] FATAL: HTTP server failed", "error", err)
	}
}
