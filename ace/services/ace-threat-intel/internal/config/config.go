package config

import (
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for ace-threat-intel.
type Config struct {
	Port     int    `mapstructure:"port"`
	LogLevel string `mapstructure:"log_level"`

	Redis RedisConfig `mapstructure:"redis"`

	// IOC cache TTL
	IOCCacheTTL time.Duration `mapstructure:"ioc_cache_ttl"`

	// Feed sync interval
	SyncInterval time.Duration `mapstructure:"sync_interval"`

	// Feed API keys / endpoints
	OTXAPIKey   string `mapstructure:"otx_api_key"`
	TAXIIServer string `mapstructure:"taxii_server"`
	TAXIIUser   string `mapstructure:"taxii_user"`
	TAXIIPass   string `mapstructure:"taxii_pass"`
}

// RedisConfig holds Redis connection settings.
type RedisConfig struct {
	Addr     string `mapstructure:"addr"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

// Load reads configuration from environment variables prefixed with ACE_THREAT_INTEL_.
func Load() (*Config, error) {
	v := viper.New()
	v.SetEnvPrefix("ACE_THREAT_INTEL")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.SetDefault("port", 8091)
	v.SetDefault("log_level", "info")
	v.SetDefault("ioc_cache_ttl", "24h")
	v.SetDefault("sync_interval", "6h")
	v.SetDefault("redis.addr", "localhost:6379")
	v.SetDefault("redis.db", 1)

	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
