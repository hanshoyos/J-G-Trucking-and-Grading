package config

import (
	"strings"

	"github.com/spf13/viper"
)

// Config holds all configuration for ace-asset-inventory.
type Config struct {
	Port        int    `mapstructure:"port"`
	LogLevel    string `mapstructure:"log_level"`
	DatabaseURL string `mapstructure:"database_url"`

	Kafka KafkaConfig   `mapstructure:"kafka"`
	Purdue PurdueConfig `mapstructure:"purdue"`
}

// KafkaConfig holds settings for the passive-discovery consumer.
type KafkaConfig struct {
	Brokers         string `mapstructure:"brokers"`
	NormalizedTopic string `mapstructure:"normalized_topic"`
	ConsumerGroup   string `mapstructure:"consumer_group"`
}

// PurdueConfig holds optional subnet-to-level overrides.
// Maps Purdue level (0–5) to CIDR list for that level.
type PurdueConfig struct {
	Level0Subnets []string `mapstructure:"level0_subnets"`
	Level1Subnets []string `mapstructure:"level1_subnets"`
	Level2Subnets []string `mapstructure:"level2_subnets"`
	Level3Subnets []string `mapstructure:"level3_subnets"`
}

// Load reads config from env with prefix ACE_ASSET_INVENTORY_.
func Load() (*Config, error) {
	v := viper.New()
	v.SetEnvPrefix("ACE_ASSET_INVENTORY")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.SetDefault("port", 8092)
	v.SetDefault("log_level", "info")
	v.SetDefault("database_url",
		"postgres://ace:ace@localhost:5432/ace_assets?sslmode=disable")
	v.SetDefault("kafka.normalized_topic", "ace.events.normalized")
	v.SetDefault("kafka.consumer_group", "ace-asset-inventory")

	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
