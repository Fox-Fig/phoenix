package config

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/pelletier/go-toml"
)

// LoadServerConfig reads and parses a server configuration file.
func LoadServerConfig(filePath string) (*ServerConfig, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("config file not found: %s", filePath)
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := &ServerConfig{}
	if err := toml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse TOML configuration: %w", err)
	}

	// Apply Server defaults if empty (if applicable)

	return config, nil
}

// LoadClientConfig reads and parses a client configuration file.
func LoadClientConfig(filePath string) (*ClientConfig, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("config file not found: %s", filePath)
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := DefaultClientConfig()
	if err := toml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse TOML configuration: %w", err)
	}

	return config, nil
}
