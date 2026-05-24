// db_sqlite_wallet.go
// CN: 高并发数据库死锁隔离层 | EN: High-concurrency Database Deadlock Isolation Layer
//
// CN: 纯 Go 实现的 SQLite 安全写入包装器，使用显式 BEGIN IMMEDIATE 事务。
// EN: Pure Go implementation of SQLite safe write wrapper with explicit BEGIN IMMEDIATE transactions.
// CN: 在 SQLITE_BUSY 错误上实现带随机抖动（20-80ms）的指数退避重试。
// EN: Implements exponential backoff retry with random jitter (20-80ms) on SQLITE_BUSY errors.
//
// CN: 本模块为策略状态持久化和审计日志存储提供工业级无死锁写操作。
// EN: This module provides industrial-grade deadlock-free write operations for policy state persistence and audit log storage.

package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// ============================================================================
// CN: 配置常量 | EN: Configuration constants
// ============================================================================

const (
	// CN: DefaultDBPath 默认数据库路径（相对路径，已净化）| EN: DefaultDBPath default database path (relative path, sanitized)
	DefaultDBPath = "./data/store.db"

	// CN: MaxRetryAttempts 放弃前的最大重试次数 | EN: MaxRetryAttempts maximum retry attempts before giving up
	MaxRetryAttempts = 5

	// CN: BaseRetryDelay 基础重试延迟（毫秒）| EN: BaseRetryDelay base retry delay in milliseconds
	BaseRetryDelay = 20 * time.Millisecond

	// CN: MaxRetryDelay 最大重试延迟上限 | EN: MaxRetryDelay maximum retry delay cap
	MaxRetryDelay = 80 * time.Millisecond

	// CN: BusyTimeout SQLite 内置的忙等待超时时间（毫秒）| EN: BusyTimeout SQLite built-in busy wait timeout in milliseconds
	BusyTimeout = 3000

	// CN: WALJournalMode 预写式日志模式，用于更好的并发读写 | EN: WALJournalMode Write-Ahead Logging mode for better concurrent read/write
	WALJournalMode = "WAL"

	// CN: SynchronousNormal 普通同步模式，平衡性能和安全性 | EN: SynchronousNormal normal sync mode, balances performance and safety
	SynchronousNormal = "NORMAL"

	// CN: CacheSize 页面缓存大小（2000 页）| EN: CacheSize page cache size (2000 pages)
	CacheSize = -2000

	// CN: TempStore 内存临时存储，用于更好的排序/临时表性能 | EN: TempStore memory temp store for better sort/temp table performance
	TempStore = "MEMORY"
)

// ============================================================================
// CN: 全局数据库实例 | EN: Global database instance
// ============================================================================

var (
	// CN: DB 全局数据库连接池 | EN: DB global database connection pool
	DB *sql.DB

	// CN: dbInitOnce 确保数据库只初始化一次 | EN: dbInitOnce ensures database is initialized only once
	dbInitOnce sync.Once

	// CN: dbInitErr 初始化错误 | EN: dbInitErr initialization error
	dbInitErr error
)

// ============================================================================
// CN: 安全写入包装器 | EN: Safe write wrapper
// ============================================================================

// CN: SafeWrite 执行数据库写操作，自动事务处理和 SQLITE_BUSY 重试，带指数退避
// EN: SafeWrite executes a database write operation with automatic transaction and SQLITE_BUSY retry with exponential backoff.
func SafeWrite(operation func(tx *sql.Tx) error) error {
	return SafeWriteWithContext(context.Background(), operation)
}

// CN: SafeWriteWithContext 支持上下文的的安全写操作
// EN: SafeWriteWithContext safe write operation with context support
func SafeWriteWithContext(ctx context.Context, operation func(tx *sql.Tx) error) error {
	var lastErr error

	for attempt := 0; attempt <= MaxRetryAttempts; attempt++ {
		if ctx.Err() != nil {
			return fmt.Errorf("write operation cancelled by context: %v", ctx.Err())
		}

		lastErr = tryWriteOnce(ctx, operation)
		if lastErr == nil {
			return nil
		}

		if !isBusyError(lastErr) {
			slog.Error("DB write failed (non-busy error, no retry)",
				"error", lastErr,
				"attempt", attempt+1)
			return lastErr
		}

		if attempt < MaxRetryAttempts {
			delay := calculateRetryDelay(attempt)
			slog.Warn("Database busy (SQLITE_BUSY), retrying",
				"attempt", attempt+1,
				"max_attempts", MaxRetryAttempts+1,
				"delay_ms", delay.Milliseconds(),
				"error", lastErr)

			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return fmt.Errorf("retry cancelled by context: %v", ctx.Err())
			}
		}
	}

	slog.Error("DB write failed (max retries exceeded)",
		"max_attempts", MaxRetryAttempts+1,
		"last_error", lastErr)
	return fmt.Errorf("db write failed, max retries exceeded (%d): %v", MaxRetryAttempts+1, lastErr)
}

// CN: tryWriteOnce 执行单次事务尝试
// EN: tryWriteOnce executes a single transaction attempt
// CN: 使用 _txlock=immediate DSN 参数，BeginTx 自动获取 RESERVED 锁
// EN: With _txlock=immediate DSN parameter, BeginTx automatically acquires RESERVED lock
func tryWriteOnce(ctx context.Context, operation func(tx *sql.Tx) error) error {
	tx, err := DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("transaction creation failed: %v", err)
	}

	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			slog.Warn("Rollback failed (non-critical)", "error", err)
		}
	}()

	if err := operation(tx); err != nil {
		return fmt.Errorf("write operation failed: %v", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit failed: %v", err)
	}

	return nil
}

// ============================================================================
// CN: 指数退避 + 随机抖动 | EN: Exponential backoff + Random Jitter
// ============================================================================

func calculateRetryDelay(attempt int) time.Duration {
	base := BaseRetryDelay * time.Duration(1<<uint(attempt))

	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		b[0] = 50
	}
	jitter := time.Duration(20+int(b[0])%61) * time.Millisecond

	total := base + jitter
	if total > MaxRetryDelay {
		total = MaxRetryDelay
	}

	return total
}

// ============================================================================
// CN: SQLITE_BUSY 错误检测 | EN: SQLITE_BUSY error detection
// ============================================================================

func isBusyError(err error) bool {
	if err == nil {
		return false
	}

	errMsg := err.Error()
	busyPatterns := []string{
		"database is locked",
		"SQLITE_BUSY",
		"busy",
	}

	for _, pattern := range busyPatterns {
		if strings.Contains(errMsg, pattern) {
			return true
		}
	}

	return false
}

// ============================================================================
// CN: 数据库初始化 | EN: Database initialization
// ============================================================================

// CN: InitDB 使用默认路径初始化全局数据库连接
// EN: InitDB initializes the global database connection with default path
func InitDB() error {
	return InitDBWithPath(DefaultDBPath)
}

// CN: InitDBWithPath 使用指定路径初始化全局数据库连接
// EN: InitDBWithPath initializes the global database connection with specified path
func InitDBWithPath(dbPath string) error {
	dbInitOnce.Do(func() {
		dbInitErr = initDBInternal(dbPath)
	})
	return dbInitErr
}

func initDBInternal(dbPath string) error {
	var err error

	DB, err = sql.Open("sqlite3", fmt.Sprintf(
		"%s?_journal=%s&_busy_timeout=%d&_cache_size=%d&_synchronous=%s&_temp_store=%s&_txlock=immediate",
		dbPath, WALJournalMode, BusyTimeout, CacheSize, SynchronousNormal, TempStore))
	if err != nil {
		slog.Error("Database engine failed to load", "error", err, "path", dbPath)
		return fmt.Errorf("database open failed: %v", err)
	}

	DB.SetMaxOpenConns(1)
	DB.SetMaxIdleConns(2)
	DB.SetConnMaxLifetime(30 * time.Minute)

	if err = DB.Ping(); err != nil {
		slog.Error("Database file access denied or corrupted", "error", err, "path", dbPath)
		DB.Close()
		return fmt.Errorf("database ping failed: %v", err)
	}

	slog.Info("Database ready",
		"mode", WALJournalMode,
		"busy_timeout_ms", BusyTimeout,
		"cache_size", CacheSize,
		"path", dbPath)

	return nil
}

// ============================================================================
// CN: 便捷查询函数（只读，无需事务）| EN: Convenience query functions (read-only, no transaction needed)
// ============================================================================

// CN: QueryRowSafe 执行安全的只读查询，返回单行
// EN: QueryRowSafe executes a safe read-only query returning a single row
func QueryRowSafe(query string, args ...interface{}) *sql.Row {
	return DB.QueryRow(query, args...)
}

// CN: ExecSafe 执行包装在 SafeWrite 中的安全写操作
// EN: ExecSafe executes a safe write operation wrapped in SafeWrite
func ExecSafe(query string, args ...interface{}) error {
	return SafeWrite(func(tx *sql.Tx) error {
		_, err := tx.Exec(query, args...)
		return err
	})
}

// ============================================================================
// CN: 优雅关闭 | EN: Graceful shutdown
// ============================================================================

// CN: CloseDB 优雅关闭数据库连接
// EN: CloseDB gracefully closes the database connection
func CloseDB() error {
	if DB == nil {
		return nil
	}

	slog.Info("Closing database connection...")
	if err := DB.Close(); err != nil {
		slog.Error("Database close error", "error", err)
		return err
	}

	slog.Info("Database connection closed safely")
	return nil
}
