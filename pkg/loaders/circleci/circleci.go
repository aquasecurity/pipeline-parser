package circleci

import (
	"github.com/aquasecurity/pipeline-parser/pkg/loaders/circleci/models"
	"gopkg.in/yaml.v3"
)

type CircleCILoader struct{}

func (c *CircleCILoader) Load(data []byte) (*models.Config, error) {
	config := &models.Config{}
	err := yaml.Unmarshal(data, config)
	return config, err
}

