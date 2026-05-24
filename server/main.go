// main.go
// Core Security Server - minimal demo entry point
// Demonstrates end-to-end PoW middleware and Ed25519 signature issuance
//
// Start:
//   go run main.go
//
// Production:
//   go build -o server && ./server
//
// Dev mode (not recommended for production):
//   RXXL_DEV_MODE=1 go run main.go

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

// Handler defines business processors
type Handler struct{}

// HandleGetTicket returns PoW Ticket to client
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

// HandleHeartbeat heartbeat endpoint: returns Ed25519 signature
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

	// Load scriptHash from environment variable to avoid static feature exposure
	scriptHash := os.Getenv("RXXL_SCRIPT_HASH")
	if scriptHash == "" {
		slog.Warn("[Heartbeat] RXXL_SCRIPT_HASH not set, using noise placeholder. " +
			"Production MUST set this environment variable to the actual script bytecode hash.")
		scriptHash = "a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1"
	}

	signature, err := middleware.SignOracle(req.Username, req.Nonce, expireTime, scriptHash)
	if err != nil {
		utils.AdminLog.Error("HEARTBEAT_SIGN_FAIL",
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
		"script_hash":      scriptHash,
	})

	utils.AdminLog.Info("HEARTBEAT_SUCCESS",
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
	slog.Info("Core Security Server - Starting")
	slog.Info("========================================")

	pubKey := middleware.GetOraclePublicKey()
	if pubKey == "" {
		slog.Error("[Main] FATAL: Oracle Signer not ready. " +
			"Set RXXL_ED25519_PRIVATE_KEY (production) or RXXL_DEV_MODE=1 (development)")
		slog.Error("[Main] Server exiting.")
		return
	}
	slog.Info("[Main] Oracle Signer ready", "public_key_prefix", pubKey[:16]+"...")

	handler := &Handler{}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", handler.HandleHealth)

	mux.Handle("/api/v1/pow/ticket",
		BaseInfoMiddleware(http.HandlerFunc(handler.HandleGetTicket)))

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
