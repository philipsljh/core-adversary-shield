// main.go
// CN: 企业级策略编排服务器 - 入口文件 | EN: Enterprise Policy Orchestration Server - Entry Point
//
// CN: 本服务器实现了零信任策略编排框架，包含：
// EN: This server implements a zero-trust policy orchestration framework with:
// - CN: 洋葱模型中间件管道（BaseInfo -> VerifyPoW -> Ticket）| EN: Onion-model middleware pipeline (BaseInfo -> VerifyPoW -> Ticket)
// - CN: Ed25519 盲预言机数字签名签发 | EN: Ed25519 blind oracle digital signature issuance
// - CN: SQLite WAL 工业级无死锁写外壳，带指数退避 | EN: SQLite WAL industrial-grade deadlock-free write shell with exponential backoff
//
// CN: 启动方式:
// EN: Start:
//   go run main.go
//
// CN: 生产环境:
// EN: Production:
//   go build -o server && ./server
//
// CN: 开发模式（仅用于测试）:
// EN: Dev mode (for testing only):
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
// CN: 中间件：提取客户端 IP | EN: Middleware: extract client IP
// ============================================================================

// CN: BaseInfoMiddleware 提取真实客户端 IP 并注入到上下文中
// EN: BaseInfoMiddleware extracts real client IP and injects into context
// CN: 这是洋葱模型中间件管道的第一层
// EN: This is the first layer of the onion-model middleware pipeline
func BaseInfoMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := utils.ExtractClientIP(r)
		r = utils.WithClientIP(r, clientIP)
		next.ServeHTTP(w, r)
	})
}

// ============================================================================
// CN: 业务处理器 | EN: Business Handler
// ============================================================================

// CN: Handler 定义了策略编排的业务处理器
// EN: Handler defines business processors for policy orchestration
type Handler struct{}

// CN: HandleGetTicket 向客户端返回 PoW Ticket
// EN: HandleGetTicket returns PoW Ticket to client
// CN: 此端点发放计算挑战用于限流
// EN: This endpoint issues a computational challenge for rate limiting
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

// CN: HeartbeatRequest 心跳请求结构体 | EN: HeartbeatRequest heartbeat request structure
type HeartbeatRequest struct {
	Username     string `json:"username"`
	Nonce        string `json:"nonce"`
	SessionToken string `json:"session_token"`
}

// CN: HandleHeartbeat 心跳端点：返回 Ed25519 预言机签名
// EN: HandleHeartbeat heartbeat endpoint: returns Ed25519 oracle signature
// CN: 从请求体中动态提取参数
// EN: Dynamically extracts parameters from request body
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

	// CN: 从环境变量加载策略哈希，避免静态特征暴露 | EN: Load policy hash from environment variable to avoid static feature exposure
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

// CN: HandleHealth 健康检查端点 | EN: HandleHealth health check endpoint
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"code":0,"msg":"ok","timestamp":%d}`, time.Now().Unix())
}

// ============================================================================
// CN: 主函数 | EN: Main function
// ============================================================================

func main() {
	slog.Info("========================================")
	slog.Info("CN: 企业级策略编排服务器 - 启动中 | EN: Enterprise Policy Orchestration Server - Starting")
	slog.Info("========================================")

	pubKey := middleware.GetOraclePublicKey()
	if pubKey == "" {
		slog.Error("[Main] FATAL: Oracle Signer not ready. " +
			"Set POLICY_SERVER_ED25519_PRIVATE_KEY (production) or POLICY_SERVER_DEV_MODE=1 (development)")
		slog.Error("[Main] CN: 服务器正在退出 | EN: Server exiting.")
		return
	}
	slog.Info("[Main] CN: 预言机签名器已就绪 | EN: Oracle Signer ready", "public_key_prefix", pubKey[:16]+"...")

	handler := &Handler{}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", handler.HandleHealth)

	// CN: 洋葱模型中间件管道：BaseInfo -> Handler | EN: Onion-model middleware pipeline: BaseInfo -> Handler
	mux.Handle("/api/v1/pow/ticket",
		BaseInfoMiddleware(http.HandlerFunc(handler.HandleGetTicket)))

	// CN: 洋葱模型中间件管道：BaseInfo -> VerifyPoW -> Handler | EN: Onion-model middleware pipeline: BaseInfo -> VerifyPoW -> Handler
	mux.Handle("/api/v1/auth/heartbeat",
		BaseInfoMiddleware(
			middleware.VerifyPoW(
				http.HandlerFunc(handler.HandleHeartbeat),
			),
		))

	addr := ":8080"
	slog.Info("[Main] CN: HTTP 服务器监听中 | EN: HTTP server listening", "addr", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("[Main] FATAL: CN: HTTP 服务器失败 | EN: HTTP server failed", "error", err)
	}
}
