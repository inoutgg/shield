package logutil

import (
	"context"
	"log/slog"
)

// Log logs a message with the given level and arguments if the logger is defined.
func Log(ctx context.Context, l *slog.Logger, lvl slog.Level, msg string, args ...any) {
	if l == nil {
		return
	}

	l.Log(ctx, lvl, msg, args...)
}
