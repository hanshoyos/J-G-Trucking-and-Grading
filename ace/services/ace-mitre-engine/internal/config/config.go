package config

import (
	"strings"

	"github.com/spf13/viper"
)

// Config holds all configuration for the ace-mitre-engine service.
type Config struct {
	Port        int      `mapstructure:"port"`
	DatabaseURL string   `mapstructure:"database_url"`
	SyncOnStart bool     `mapstructure:"sync_on_start"`
	Frameworks  []string `mapstructure:"frameworks"`
	LogLevel    string   `mapstructure:"log_level"`
}

// Load reads configuration from environment variables prefixed with ACE_MITRE_.
func Load() (*Config, error) {
	v := viper.New()

	v.SetEnvPrefix("ACE_MITRE")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Defaults
	v.SetDefault("port", 8090)
	v.SetDefault("database_url", "postgres://ace:ace@localhost:5432/ace_mitre?sslmode=disable")
	v.SetDefault("sync_on_start", false)
	v.SetDefault("frameworks", []string{"enterprise", "ics"})
	v.SetDefault("log_level", "info")

	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
