// Package configsource provides config source wiring for csar-authn.
// It delegates source construction to csar-core/configsource.BuildSource
// and adds service-specific LoadInitial and NewConfigWatcher helpers.
package configsource

import (
	"context"
	"fmt"
	"log/slog"

	coresrc "github.com/Ledatu/csar-core/configsource"

	"github.com/Ledatu/csar-authn/internal/config"
)

// SourceParams is the shared parameter struct for building config sources.
type SourceParams = coresrc.SourceParams

// Re-export core types used by main.go.
type (
	ConfigSource  = coresrc.ConfigSource
	ConfigWatcher = coresrc.ConfigWatcher
	WatcherOption = coresrc.WatcherOption
)

var (
	WithHashPolicy = coresrc.WithHashPolicy
	WithPinnedHash = coresrc.WithPinnedHash
)

const (
	HashDisabled = coresrc.HashDisabled
	HashTOFU     = coresrc.HashTOFU
	HashPinned   = coresrc.HashPinned
)

// BuildSource delegates to csar-core/configsource.BuildSource.
func BuildSource(p *SourceParams, logger *slog.Logger) (ConfigSource, error) {
	return coresrc.BuildSource(p, logger)
}

// LoadInitial fetches config from the source once and parses it.
func LoadInitial(ctx context.Context, p *SourceParams, logger *slog.Logger) (*config.Config, error) {
	src, err := BuildSource(p, logger)
	if err != nil {
		return nil, err
	}

	fetched, err := src.Fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching config: %w", err)
	}
	if fetched.Data == nil {
		return nil, fmt.Errorf("config source returned empty data")
	}

	return config.LoadFromBytes(fetched.Data)
}

// NewConfigWatcher creates a ConfigWatcher that validates new config bytes
// via config.LoadFromBytes. Full hot-reload is not yet implemented; the
// ApplyFunc only validates and logs. Returns changed=false because no
// runtime state is modified.
func NewConfigWatcher(
	source ConfigSource,
	logger *slog.Logger,
	opts ...WatcherOption,
) *ConfigWatcher {
	applyFn := func(_ context.Context, data []byte) (bool, error) {
		_, err := config.LoadFromBytes(data)
		if err != nil {
			return false, err
		}
		logger.Info("config refresh: new config validated (hot-reload not yet implemented; restart required to apply changes)")
		return false, nil
	}
	return coresrc.NewConfigWatcher(source, applyFn, logger, opts...)
}
