package config

import "github.com/caarlos0/env/v11"

// LogFormatEnv names the process variable that selects diagnostic log format.
const LogFormatEnv = "PEERIMETER_LOG_FORMAT"

// Environment contains process-level settings read from environment variables.
type Environment struct {
	LogFormat string `env:"PEERIMETER_LOG_FORMAT" envDefault:"console"`
}

// LoadEnvironment reads process-level settings using caarlos0/env.
func LoadEnvironment() (Environment, error) {
	return env.ParseAs[Environment]()
}
