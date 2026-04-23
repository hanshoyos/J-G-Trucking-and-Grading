package config

import (
    "github.com/spf13/viper"
)

type Config struct {
    Port              string
    MitreURL          string
    ThreatIntelURL    string
    AssetInventoryURL string
    CorrelateURL      string
    KafkaBrokers      string
    AlertsTopic       string
}

func Load() Config {
    viper.SetEnvPrefix("ACE_GATEWAY")
    viper.AutomaticEnv()
    viper.SetDefault("PORT", "8000")
    viper.SetDefault("MITRE_URL", "http://localhost:8090")
    viper.SetDefault("THREAT_INTEL_URL", "http://localhost:8091")
    viper.SetDefault("ASSET_INVENTORY_URL", "http://localhost:8092")
    viper.SetDefault("CORRELATE_URL", "http://localhost:8082")
    viper.SetDefault("KAFKA_BROKERS", "localhost:9092")
    viper.SetDefault("ALERTS_TOPIC", "ace.alerts")
    return Config{
        Port:              viper.GetString("PORT"),
        MitreURL:          viper.GetString("MITRE_URL"),
        ThreatIntelURL:    viper.GetString("THREAT_INTEL_URL"),
        AssetInventoryURL: viper.GetString("ASSET_INVENTORY_URL"),
        CorrelateURL:      viper.GetString("CORRELATE_URL"),
        KafkaBrokers:      viper.GetString("KAFKA_BROKERS"),
        AlertsTopic:       viper.GetString("ALERTS_TOPIC"),
    }
}
