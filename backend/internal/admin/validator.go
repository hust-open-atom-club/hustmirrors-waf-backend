package admin

import (
	"fmt"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
)

type Validator interface {
	ValidateConfig(yaml string) ([]string, error)
	ValidateRule(ruleYAML string) ([]string, error)
}

type DefaultValidator struct{}

func (DefaultValidator) ValidateConfig(yaml string) ([]string, error) {
	cfg, err := config.LoadRawFromBytes([]byte(yaml))
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	config.ApplyDefaults(cfg)
	if err := config.Validate(cfg); err != nil {
		if ve, ok := err.(config.ValidationError); ok {
			return ve.Problems, nil
		}
		return nil, err
	}
	return nil, nil
}

func (DefaultValidator) ValidateRule(_ string) ([]string, error) {
	return nil, nil
}
