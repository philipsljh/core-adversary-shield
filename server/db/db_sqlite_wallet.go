// db_sqlite_wallet.go
// High-concurrency database deadlock isolation layer
// Pure Go implementation of SQLite safe write wrapper with explicit BEGIN IMMEDIATE transactions
// Implements exponential backoff retry with random jitter (20-80ms) on SQLITE_BUSY errors

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
// Configuration constants
// ============================================================================

const (
	// DefaultDBPath default database path (relative path, sanitized)
	DefaultDBPath = "./data/store.db"

	// MaxRetryAttempts maximum retry attempts before giving up
	MaxRetryAttempts = 5

	// BaseRetryDelay base retry delay in milliseconds
	BaseRetryDelay = 20 * time.Millisecond

	// MaxRetryDelay maximum retry delay cap
	MaxRetryDelay = 80 * time.Millisecond

	// BusyTimeout SQLite built-in busy wait timeout in milliseconds
	BusyTimeout = 3000

	// WALJournalMode Write-Ahead Logging mode for better concurrent read/write
	WALJournalMode = "WAL"

	// SynchronousNormal normal sync mode, balances performance and safety
	SynchronousNormal = "NORMAL"

	// CacheSize page cache size (2000 pages)
	CacheSize = -2000

	// TempStore memory temp store for better sort/temp table performance
	TempStore = "MEMORY"
)

// ============================================================================
// Global database instance
// ============================================================================

var (
	// DB global database connection pool
	DB *sql.DB

	// dbInitOnce ensures database is initialized only once
	dbInitOnce sync.Once

	// dbInitErr initialization error
	dbInitErr error
)

// ============================================================================
// Safe write wrapper
// ============================================================================

// SafeWrite executes a database write operation with automatic transaction and SQLITE_BUSY retry
func SafeWrite(operation func(tx *sql.Tx) error) error {
	return SafeWriteWithContext(context.Background(), operation)
}

// SafeWriteWithContext safe write operation with context support
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

// tryWriteOnce executes a single transaction attempt
// With _txlock=immediate DSN parameter, BeginTx automatically acquires RESERVED lock
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
// Exponential backoff + Random Jitter
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
// SQLITE_BUSY error detection
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
// Database initialization
// ============================================================================

func InitDB() error {
	return InitDBWithPath(DefaultDBPath)
}

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
// Convenience query functions (read-only, no transaction needed)
// ============================================================================

func QueryRowSafe(query string, args ...interface{}) *sql.Row {
	return DB.QueryRow(query, args...)
}

func ExecSafe(query string, args ...interface{}) error {
	return SafeWrite(func(tx *sql.Tx) error {
		_, err := tx.Exec(query, args...)
		return err
	})
}

// ============================================================================
// Graceful shutdown
// ============================================================================

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
